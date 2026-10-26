#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

#define FILEOPS_RECORD_PATH 1
#define FILEOPS_RECORD_FD 2
#define FILEOPS_RINGBUF_SIZE (16 * 1024 * 1024)
#define FILEOPS_POLICY_MAX_RULES 15
#define FILEOPS_POLICY_STAT_SLOTS 128

#define O_DIRECTORY 00200000
#define AT_FDCWD (-100)

enum file_op_type {
    FILE_OP_OPEN = 1,
    FILE_OP_READ = 2,
    FILE_OP_WRITE = 3,
    FILE_OP_CLOSE = 4,
    FILE_OP_MMAP = 5,
    FILE_OP_UNLINK = 6
};

enum fileops_stat_key {
    FILEOPS_STAT_EMITTED_OPEN = 1,
    FILEOPS_STAT_EMITTED_READ = 2,
    FILEOPS_STAT_EMITTED_WRITE = 3,
    FILEOPS_STAT_EMITTED_CLOSE = 4,
    FILEOPS_STAT_EMITTED_MMAP = 5,
    FILEOPS_STAT_EMITTED_UNLINK = 6,
    FILEOPS_STAT_RING_FAIL_OPEN = 17,
    FILEOPS_STAT_RING_FAIL_READ = 18,
    FILEOPS_STAT_RING_FAIL_WRITE = 19,
    FILEOPS_STAT_RING_FAIL_CLOSE = 20,
    FILEOPS_STAT_RING_FAIL_MMAP = 21,
    FILEOPS_STAT_RING_FAIL_UNLINK = 22,
    FILEOPS_STAT_SELF_DROP_OPEN = 33,
    FILEOPS_STAT_SELF_DROP_READ = 34,
    FILEOPS_STAT_SELF_DROP_WRITE = 35,
    FILEOPS_STAT_SELF_DROP_CLOSE = 36,
    FILEOPS_STAT_SELF_DROP_MMAP = 37,
    FILEOPS_STAT_SELF_DROP_UNLINK = 38,
    FILEOPS_STAT_FORCE_WAKEUP = 48,
    FILEOPS_STAT_PSEUDO_DROP_OPEN = 65,
    FILEOPS_STAT_PSEUDO_DROP_UNLINK = 70,
};

struct file_path_event {
    __u32 record_type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u64 timestamp_ns;
    __u32 fd;
    __u32 bytes;
    __u32 op_type;
    __s32 dirfd;
    // Identity fields exist to keep the wire format identical to the CO-RE
    // tier; this fallback tier cannot read inodes and always emits zeros.
    __u64 file_ino;
    __u64 dir_ino;
    __u32 file_dev;
    __u32 dir_dev;
    __u32 mnt_ns;
    __u32 _pad0;
};

struct file_fd_event {
    __u32 record_type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp_ns;
    __u32 fd;
    __u32 bytes;
    __u32 op_type;
    __u32 _pad0;
    __u64 file_ino;
    __u32 file_dev;
    __u32 _pad1;
};

struct openat_state {
    char filename[MAX_FILENAME_LEN];
    __u32 flags;
    __s32 dirfd;
};

struct fileops_comm_key {
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct openat_state);
} openat_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, FILEOPS_RINGBUF_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 96);
    __type(key, __u32);
    __type(value, __u64);
} fileops_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} fileops_filter_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FILEOPS_POLICY_MAX_RULES);
    __type(key, struct fileops_comm_key);
    __type(value, __u32);
} fileops_deny_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, FILEOPS_POLICY_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} fileops_policy_stats SEC(".maps");

static __always_inline void increment_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&fileops_stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline __u32 emitted_key_for_op(__u32 op_type)
{
    return op_type;
}

static __always_inline __u32 ring_fail_key_for_op(__u32 op_type)
{
    return op_type + 16;
}

static __always_inline __u32 self_drop_key_for_op(__u32 op_type)
{
    return op_type + 32;
}

static __always_inline __u32 pseudo_drop_key_for_op(__u32 op_type)
{
    return op_type + 64;
}

static __always_inline int is_pseudo_path_buf(const char *path)
{
    if (!path)
        return 0;

    if (path[0] != '/')
        return 0;

    if (path[1] == 'p' && path[2] == 'r' && path[3] == 'o' && path[4] == 'c' &&
        (path[5] == '\0' || path[5] == '/'))
        return 1;

    if (path[1] == 's' && path[2] == 'y' && path[3] == 's' &&
        (path[4] == '\0' || path[4] == '/'))
        return 1;

    if (path[1] == 'd' && path[2] == 'e' && path[3] == 'v' &&
        (path[4] == '\0' || path[4] == '/'))
        return 1;

    return 0;
}

static __always_inline int should_drop_user_pseudo_path(const char *user_path, __u32 op_type)
{
    char prefix[8] = {};
    if (!user_path)
        return 0;

    bpf_probe_read_user_str(prefix, sizeof(prefix), user_path);
    if (is_pseudo_path_buf(prefix)) {
        increment_stat(pseudo_drop_key_for_op(op_type));
        return 1;
    }

    return 0;
}

static __always_inline int should_drop_self_pid(__u32 pid, __u32 op_type)
{
    __u32 key = 0;
    __u32 *self_pid = bpf_map_lookup_elem(&fileops_filter_pids, &key);
    if (self_pid && *self_pid != 0 && pid == *self_pid) {
        increment_stat(self_drop_key_for_op(op_type));
        return 1;
    }
    return 0;
}

static __always_inline int should_drop_policy(__u32 op_type)
{
    struct fileops_comm_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    __u32 *rule_id = bpf_map_lookup_elem(&fileops_deny_comms, &key);
    if (!rule_id || *rule_id == 0 || *rule_id > FILEOPS_POLICY_MAX_RULES)
        return 0;

    __u32 stat_key = (*rule_id * 8) + op_type;
    __u64 *value = bpf_map_lookup_elem(&fileops_policy_stats, &stat_key);
    if (value)
        __sync_fetch_and_add(value, 1);
    return 1;
}

static __always_inline void submit_file_event(void *event)
{
    // Use the kernel's adaptive wakeup policy. Suppressing notifications kept
    // low-rate records queued despite the userspace poll timeout.
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_file_fd_event(__u32 pid, __u32 fd, __u32 bytes, __u32 op_type)
{
    struct file_fd_event *event;
    if (should_drop_policy(op_type))
        return;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(ring_fail_key_for_op(op_type));
        return;
    }

    event->record_type = FILEOPS_RECORD_FD;
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->fd = fd;
    event->bytes = bytes;
    event->op_type = op_type;
    event->_pad0 = 0;
    event->file_ino = 0;
    event->file_dev = 0;
    event->_pad1 = 0;
    submit_file_event(event);
    increment_stat(emitted_key_for_op(op_type));
}

static __always_inline void emit_file_event_saved(__u32 pid, const char *filename_buf, __u32 fd, __u32 bytes, __u32 op_type, __s32 dirfd)
{
    struct file_path_event *event;
    if (should_drop_policy(op_type))
        return;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(ring_fail_key_for_op(op_type));
        return;
    }

    event->record_type = FILEOPS_RECORD_PATH;
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (filename_buf)
        __builtin_memcpy(event->filename, filename_buf, sizeof(event->filename));
    else
        event->filename[0] = '\0';
    event->timestamp_ns = bpf_ktime_get_ns();
    event->fd = fd;
    event->bytes = bytes;
    event->op_type = op_type;
    event->dirfd = dirfd;
    event->file_ino = 0;
    event->dir_ino = 0;
    event->file_dev = 0;
    event->dir_dev = 0;
    event->mnt_ns = 0;
    event->_pad0 = 0;
    submit_file_event(event);
    increment_stat(emitted_key_for_op(op_type));
}

static __always_inline void emit_file_event_user(__u32 pid, const char *filename, __u32 fd, __u32 bytes, __u32 op_type, __s32 dirfd)
{
    struct file_path_event *event;
    if (should_drop_policy(op_type))
        return;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(ring_fail_key_for_op(op_type));
        return;
    }

    event->record_type = FILEOPS_RECORD_PATH;
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (filename)
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    else
        event->filename[0] = '\0';
    event->timestamp_ns = bpf_ktime_get_ns();
    event->fd = fd;
    event->bytes = bytes;
    event->op_type = op_type;
    event->dirfd = dirfd;
    event->file_ino = 0;
    event->dir_ino = 0;
    event->file_dev = 0;
    event->dir_dev = 0;
    event->mnt_ns = 0;
    event->_pad0 = 0;
    submit_file_event(event);
    increment_stat(emitted_key_for_op(op_type));
}

struct openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

struct sys_exit_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int t_openat_ent(struct openat_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_drop_self_pid(pid, FILE_OP_OPEN))
        return 0;

    struct openat_state st = {};
    st.flags = (__u32)ctx->flags;
    st.dirfd = (__s32)ctx->dfd;
    if (ctx->filename)
        bpf_probe_read_user_str(st.filename, sizeof(st.filename), ctx->filename);
    else
        st.filename[0] = '\0';

    if (is_pseudo_path_buf(st.filename)) {
        increment_stat(pseudo_drop_key_for_op(FILE_OP_OPEN));
        return 0;
    }

    bpf_map_update_elem(&openat_state_map, &pid_tgid, &st, BPF_ANY);
    return 0;
}

struct open_args {
    unsigned long long unused;
    long syscall_nr;
    const char *filename;
    long flags;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_open")
int t_open_ent(struct open_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_drop_self_pid(pid, FILE_OP_OPEN))
        return 0;

    struct openat_state st = {};
    st.flags = (__u32)ctx->flags;
    st.dirfd = AT_FDCWD;
    if (ctx->filename)
        bpf_probe_read_user_str(st.filename, sizeof(st.filename), ctx->filename);
    else
        st.filename[0] = '\0';

    if (is_pseudo_path_buf(st.filename)) {
        increment_stat(pseudo_drop_key_for_op(FILE_OP_OPEN));
        return 0;
    }

    bpf_map_update_elem(&openat_state_map, &pid_tgid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int t_open_exit(struct sys_exit_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_drop_self_pid(pid, FILE_OP_OPEN))
        return 0;

    struct openat_state *stp = bpf_map_lookup_elem(&openat_state_map, &pid_tgid);
    if (!stp)
        return 0;

    struct openat_state st = {};
    __builtin_memcpy(&st, stp, sizeof(st));

    long fd = ctx->ret;
    bpf_map_delete_elem(&openat_state_map, &pid_tgid);

    if (fd < 0)
        return 0;
    if (st.flags & O_DIRECTORY)
        return 0;

    emit_file_event_saved(pid, st.filename, (__u32)fd, 0, FILE_OP_OPEN, st.dirfd);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat(struct sys_exit_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_drop_self_pid(pid, FILE_OP_OPEN))
        return 0;

    struct openat_state *stp = bpf_map_lookup_elem(&openat_state_map, &pid_tgid);
    if (!stp)
        return 0;

    struct openat_state st = {};
    __builtin_memcpy(&st, stp, sizeof(st));

    long fd = ctx->ret;
    bpf_map_delete_elem(&openat_state_map, &pid_tgid);

    if (fd < 0)
        return 0;
    if (st.flags & O_DIRECTORY)
        return 0;

    emit_file_event_saved(pid, st.filename, (__u32)fd, 0, FILE_OP_OPEN, st.dirfd);
    return 0;
}

struct read_enter_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned int fd;
    char *buf;
    __u64 count;
};

SEC("tracepoint/syscalls/sys_enter_read")
int t_read_ent(struct read_enter_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (should_drop_self_pid(pid, FILE_OP_READ))
        return 0;
    emit_file_fd_event(pid, ctx->fd, (__u32)ctx->count, FILE_OP_READ);
    return 0;
}

struct write_enter_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned int fd;
    const char *buf;
    __u64 count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int t_write_ent(struct write_enter_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (should_drop_self_pid(pid, FILE_OP_WRITE))
        return 0;
    emit_file_fd_event(pid, ctx->fd, (__u32)ctx->count, FILE_OP_WRITE);
    return 0;
}

struct close_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned int fd;
};

SEC("tracepoint/syscalls/sys_enter_close")
int t_close(struct close_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (should_drop_self_pid(pid, FILE_OP_CLOSE))
        return 0;
    emit_file_fd_event(pid, ctx->fd, 0, FILE_OP_CLOSE);
    return 0;
}

struct mmap_args {
    unsigned long long unused;
    long syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int t_mmap(struct mmap_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (should_drop_self_pid(pid, FILE_OP_MMAP))
        return 0;
    if (ctx->fd != -1)
        emit_file_fd_event(pid, ctx->fd, ctx->len, FILE_OP_MMAP);
    return 0;
}

struct unlinkat_args {
    unsigned long long unused;
    long syscall_nr;
    int dfd;
    const char *pathname;
    int flag;
};

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int t_unlinkat(struct unlinkat_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (should_drop_self_pid(pid, FILE_OP_UNLINK))
        return 0;
    if (should_drop_user_pseudo_path(ctx->pathname, FILE_OP_UNLINK))
        return 0;
    emit_file_event_user(pid, ctx->pathname, 0, 0, FILE_OP_UNLINK, ctx->dfd);
    return 0;
}

struct unlink_args {
    unsigned long long unused;
    long syscall_nr;
    const char *pathname;
};

SEC("tracepoint/syscalls/sys_enter_unlink")
int t_unlink(struct unlink_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (should_drop_self_pid(pid, FILE_OP_UNLINK))
        return 0;
    if (should_drop_user_pseudo_path(ctx->pathname, FILE_OP_UNLINK))
        return 0;
    emit_file_event_user(pid, ctx->pathname, 0, 0, FILE_OP_UNLINK, AT_FDCWD);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
