#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

// Event structure for clone/fork/vfork
struct clone_event {
    // Parent process (the one calling fork/clone)
    __u32 parent_pid;
    __u32 parent_uid;
    __u32 parent_gid;
    char parent_comm[TASK_COMM_LEN];
    
    // Child process (newly created)
    __u32 child_pid;
    
    // Timing
    __u64 timestamp_ns;
    
    // Clone flags (indicates fork vs vfork vs clone)
    __u64 clone_flags;
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint structure for sched_process_fork
struct sched_fork_args {
    unsigned long long unused;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

// Optional extra coverage: syscall tracepoints for clone/vfork to capture clone flags.
// This is a best-effort breadcrumb only; sched_process_fork remains the primary source.
struct sys_enter_clone_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long clone_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 8192);
} clone_flags_map SEC(".maps");

// Hook process fork/clone/vfork
// This tracepoint fires for fork(), vfork(), and clone()
SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(struct sched_fork_args *ctx)
{
    struct clone_event *event;
    
    // Reserve space
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Get parent process info
    event->parent_pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get parent UID/GID
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->parent_uid = uid_gid & 0xFFFFFFFF;
    event->parent_gid = uid_gid >> 32;
    
    // Get parent command name (from tracepoint)
    __builtin_memcpy(event->parent_comm, ctx->parent_comm, TASK_COMM_LEN);
    
    // Get child PID (from tracepoint)
    event->child_pid = ctx->child_pid;
    
    // Get timestamp
    event->timestamp_ns = bpf_ktime_get_ns();
    
    // Best-effort clone flags captured from sys_enter_clone/vfork.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *flags = bpf_map_lookup_elem(&clone_flags_map, &pid_tgid);
    event->clone_flags = flags ? *flags : 0;
    if (flags)
        bpf_map_delete_elem(&clone_flags_map, &pid_tgid);
    
    // Submit
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_sys_enter_clone(struct sys_enter_clone_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 flags = (__u64)ctx->clone_flags;
    bpf_map_update_elem(&clone_flags_map, &pid_tgid, &flags, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int trace_sys_enter_vfork(struct sys_enter_clone_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    // vfork has implicit flags; store a sentinel so the event isn't ambiguous.
    __u64 flags = 0xFFFFFFFFFFFFFFFFULL;
    bpf_map_update_elem(&clone_flags_map, &pid_tgid, &flags, BPF_ANY);
    return 0;
}

// Tracepoint-only fallback: capture clone3 flags just as legacy clone flags.
// If this auxiliary hook is unavailable, missing flags remain ambiguous.
struct sys_enter_clone3_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args;
    unsigned long size;
};
SEC("tracepoint/syscalls/sys_enter_clone3")
int trace_sys_enter_clone3(struct sys_enter_clone3_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 flags = 0;
    if (ctx->size >= sizeof(flags) &&
        bpf_probe_read_user(&flags, sizeof(flags), (void *)ctx->args) == 0)
        bpf_map_update_elem(&clone_flags_map, &pid_tgid, &flags, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
