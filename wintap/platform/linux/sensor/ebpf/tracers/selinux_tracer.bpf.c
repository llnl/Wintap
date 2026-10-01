#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define SELINUX_CONTEXT_LEN 256
#define SELINUX_TCLASS_LEN 32
#define SELINUX_FILENAME_LEN 256
#define SELINUX_RINGBUF_SIZE (4 * 1024 * 1024)
#define SELINUX_FORCE_WAKEUP_BYTES (512 * 1024)
#define SELINUX_INTERACTION_MAX_ENTRIES 16384

enum selinux_record_type {
    SELINUX_RECORD_AVC = 1,
    SELINUX_RECORD_TRANSITION = 2,
    SELINUX_RECORD_INTERACTION = 3,
};

enum selinux_stat_key {
    SELINUX_STAT_AVC_EMITTED = 1,
    SELINUX_STAT_TRANSITION_EMITTED = 2,
    SELINUX_STAT_INTERACTION_NOVEL = 3,
    SELINUX_STAT_INTERACTION_FOLDED = 4,
    SELINUX_STAT_AVC_RING_FAIL = 17,
    SELINUX_STAT_TRANSITION_RING_FAIL = 18,
    SELINUX_STAT_INTERACTION_RING_FAIL = 19,
    SELINUX_STAT_AVC_SELF_DROP = 33,
    SELINUX_STAT_TRANSITION_SELF_DROP = 34,
    SELINUX_STAT_INTERACTION_SELF_DROP = 35,
    SELINUX_STAT_STRING_TRUNCATED = 49,
    SELINUX_STAT_FORCE_WAKEUP = 50,
};

struct selinux_event_header {
    __u32 record_type;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp_ns;
};

struct selinux_avc_event {
    struct selinux_event_header header;
    __u32 requested;
    __u32 denied;
    __u32 audited;
    __s32 result;
    char scontext[SELINUX_CONTEXT_LEN];
    char tcontext[SELINUX_CONTEXT_LEN];
    char tclass[SELINUX_TCLASS_LEN];
    __u32 flags;
};

struct selinux_transition_event {
    struct selinux_event_header header;
    __u32 old_sid;
    __u32 new_sid;
    char filename[SELINUX_FILENAME_LEN];
};

struct selinux_interaction_key {
    __u32 ssid;
    __u32 tsid;
    __u32 tclass;
    __u32 requested;
};

struct selinux_interaction_value {
    __u64 count;
    __u64 emitted_at_flush;
    __u64 first_ts;
    __u64 last_ts;
    __u32 first_pid;
    char first_comm[TASK_COMM_LEN];
};

struct selinux_interaction_event {
    struct selinux_event_header header;
    __u32 ssid;
    __u32 tsid;
    __u32 tclass;
    __u32 requested;
    __u64 count;
    __u64 first_ts;
    __u64 last_ts;
    char first_comm[TASK_COMM_LEN];
    __u32 first_pid;
    __u32 novel;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SELINUX_RINGBUF_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} selinux_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} selinux_filter_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SELINUX_INTERACTION_MAX_ENTRIES);
    __type(key, struct selinux_interaction_key);
    __type(value, struct selinux_interaction_value);
} selinux_interactions SEC(".maps");

static __always_inline void increment_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&selinux_stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int should_drop_self_pid(__u32 pid, __u32 stat_key)
{
    __u32 key = 0;
    __u32 *self_pid = bpf_map_lookup_elem(&selinux_filter_pids, &key);
    if (self_pid && *self_pid != 0 && pid == *self_pid) {
        increment_stat(stat_key);
        return 1;
    }
    return 0;
}

static __always_inline void fill_header(struct selinux_event_header *header,
                                        __u32 record_type, __u32 pid, __u32 tgid)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    header->record_type = record_type;
    header->pid = pid;
    header->tgid = tgid;
    header->uid = (__u32)uid_gid;
    bpf_get_current_comm(&header->comm, sizeof(header->comm));
    header->timestamp_ns = bpf_ktime_get_ns();
}

static __always_inline void submit_event(void *event)
{
    __u64 flags = 0;
    __u64 available = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
    if (available >= SELINUX_FORCE_WAKEUP_BYTES) {
        flags = BPF_RB_FORCE_WAKEUP;
        increment_stat(SELINUX_STAT_FORCE_WAKEUP);
    }

    bpf_ringbuf_submit(event, flags);
}

static __always_inline int copy_data_loc_string(void *ctx, __u32 data_loc,
                                                char *dst, __u32 dst_len)
{
    __u32 offset = data_loc & 0xffff;
    __u32 length = data_loc >> 16;
    if (!offset || !dst || dst_len == 0) {
        if (dst && dst_len > 0)
            dst[0] = '\0';
        return 0;
    }

    char *src = (char *)ctx + offset;
    long copied = bpf_probe_read_kernel_str(dst, dst_len, src);
    if (length >= dst_len || copied == dst_len)
        return 1;
    return 0;
}

SEC("tracepoint/avc/selinux_audited")
int tp_avc_audit(struct trace_event_raw_selinux_audited *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid;

    if (should_drop_self_pid(pid, SELINUX_STAT_AVC_SELF_DROP))
        return 0;

    struct selinux_avc_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(SELINUX_STAT_AVC_RING_FAIL);
        return 0;
    }

    fill_header(&event->header, SELINUX_RECORD_AVC, pid, tgid);
    event->requested = ctx->requested;
    event->denied = ctx->denied;
    event->audited = ctx->audited;
    event->result = ctx->result;
    event->flags = 0;

    if (copy_data_loc_string(ctx, ctx->__data_loc_scontext, event->scontext, sizeof(event->scontext)))
        event->flags |= 1;
    if (copy_data_loc_string(ctx, ctx->__data_loc_tcontext, event->tcontext, sizeof(event->tcontext)))
        event->flags |= 2;
    if (copy_data_loc_string(ctx, ctx->__data_loc_tclass, event->tclass, sizeof(event->tclass)))
        event->flags |= 4;
    if (event->flags)
        increment_stat(SELINUX_STAT_STRING_TRUNCATED);

    submit_event(event);
    increment_stat(SELINUX_STAT_AVC_EMITTED);
    return 0;
}

SEC("kprobe/selinux_bprm_committed_creds")
int k_bprm_commit(struct pt_regs *ctx)
{
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid;

    if (should_drop_self_pid(pid, SELINUX_STAT_TRANSITION_SELF_DROP))
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred = BPF_CORE_READ(task, cred);
    void *security_ptr = 0;
    BPF_CORE_READ_INTO(&security_ptr, cred, security);
    struct task_security_struct *security = (struct task_security_struct *)security_ptr;
    if (!security)
        return 0;

    __u32 old_sid = BPF_CORE_READ(security, osid);
    __u32 new_sid = BPF_CORE_READ(security, sid);
    if (old_sid == new_sid)
        return 0;

    struct selinux_transition_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(SELINUX_STAT_TRANSITION_RING_FAIL);
        return 0;
    }

    fill_header(&event->header, SELINUX_RECORD_TRANSITION, pid, tgid);
    event->old_sid = old_sid;
    event->new_sid = new_sid;
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (filename)
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);
    else
        event->filename[0] = '\0';

    submit_event(event);
    increment_stat(SELINUX_STAT_TRANSITION_EMITTED);
    return 0;
}

static __always_inline int handle_avc_has_perm(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid;

    if (should_drop_self_pid(pid, SELINUX_STAT_INTERACTION_SELF_DROP))
        return 0;

    struct selinux_interaction_key key = {};
    key.ssid = (__u32)PT_REGS_PARM2(ctx);
    key.tsid = (__u32)PT_REGS_PARM3(ctx);
    key.tclass = (__u32)PT_REGS_PARM4(ctx);
    key.requested = (__u32)PT_REGS_PARM5(ctx);

    if (key.requested == 0)
        return 0;

    struct selinux_interaction_value *existing = bpf_map_lookup_elem(&selinux_interactions, &key);
    if (existing) {
        __sync_fetch_and_add(&existing->count, 1);
        existing->last_ts = bpf_ktime_get_ns();
        increment_stat(SELINUX_STAT_INTERACTION_FOLDED);
        return 0;
    }

    struct selinux_interaction_value value = {};
    value.count = 1;
    value.emitted_at_flush = 1;
    value.first_ts = bpf_ktime_get_ns();
    value.last_ts = value.first_ts;
    value.first_pid = pid;
    bpf_get_current_comm(&value.first_comm, sizeof(value.first_comm));
    bpf_map_update_elem(&selinux_interactions, &key, &value, BPF_ANY);

    struct selinux_interaction_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(SELINUX_STAT_INTERACTION_RING_FAIL);
        return 0;
    }

    fill_header(&event->header, SELINUX_RECORD_INTERACTION, pid, tgid);
    event->ssid = key.ssid;
    event->tsid = key.tsid;
    event->tclass = key.tclass;
    event->requested = key.requested;
    event->count = value.count;
    event->first_ts = value.first_ts;
    event->last_ts = value.last_ts;
    __builtin_memcpy(event->first_comm, value.first_comm, sizeof(event->first_comm));
    event->first_pid = value.first_pid;
    event->novel = 1;

    submit_event(event);
    increment_stat(SELINUX_STAT_INTERACTION_NOVEL);
    return 0;
}

SEC("kprobe/avc_has_perm_noaudit")
int k_avc_noaudit(struct pt_regs *ctx)
{
    return handle_avc_has_perm(ctx);
}

// RHEL 8.10 exposes avc_has_perm_noaudit in kallsyms but rejects attaching a
// kprobe to it on the target. Keep the wrapper as a sel-02 attach fallback;
// the preferred production hook remains avc_has_perm_noaudit.
SEC("kprobe/avc_has_perm")
int k_avc_perm(struct pt_regs *ctx)
{
    return handle_avc_has_perm(ctx);
}

char LICENSE[] SEC("license") = "GPL";
