#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

#define FILEOPS_RECORD_PATH 1
#define FILEOPS_RECORD_FD 2
#define FILEOPS_RINGBUF_SIZE (16 * 1024 * 1024)
#define FILEOPS_POLICY_MAX_RULES 15
#define FILEOPS_POLICY_STAT_SLOTS 128

#define S_IFMT 00170000
#define S_IFREG 0100000
#define S_IFDIR 0040000

// Common pseudo filesystems that should not enter the File stream when we can
// inspect the fd target in the CO-RE tier.
#define PROC_SUPER_MAGIC 0x9fa0
#define SYSFS_MAGIC 0x62656572
#define DEVPTS_SUPER_MAGIC 0x1cd1
#define TMPFS_MAGIC 0x01021994
#define DEVTMPFS_MAGIC TMPFS_MAGIC

// open(2) flags we care about.
// Keep this local to avoid pulling in additional headers.
#define O_DIRECTORY 00200000
#define AT_FDCWD (-100)

// File operation types
enum file_op_type {
    FILE_OP_OPEN = 1,
    FILE_OP_READ = 2,
    FILE_OP_WRITE = 3,
    FILE_OP_CLOSE = 4,
    FILE_OP_MMAP = 5,
    FILE_OP_UNLINK = 6,
    // Directory-handle open. Emitted so userspace can learn
    // (s_dev, i_ino) -> absolute dir path for race-free relative-open
    // resolution. Never becomes a WintapMessage.
    FILE_OP_DIR_OPEN = 7
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
    FILEOPS_STAT_NONREG_DROP_READ = 58,
    FILEOPS_STAT_NONREG_DROP_WRITE = 59,
    FILEOPS_STAT_NONREG_DROP_CLOSE = 60,
    FILEOPS_STAT_NONREG_DROP_MMAP = 61,
    FILEOPS_STAT_PSEUDO_DROP_OPEN = 65,
    FILEOPS_STAT_PSEUDO_DROP_UNLINK = 70,
};

// Event structure for file operations
struct file_path_event {
    __u32 record_type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u64 timestamp_ns;
    __u32 fd;              // File descriptor
    __u32 bytes;           // Bytes read/written (for read/write)
    __u32 op_type;         // Which operation (open/read/write/etc)
    __s32 dirfd;           // Operation-time dirfd for relative open/unlink paths
    __u64 file_ino;        // Opened object's inode (0 when unavailable)
    __u64 dir_ino;         // dirfd base inode for relative opens (0 when unavailable)
    __u32 file_dev;        // Opened object's superblock s_dev (0 when unavailable)
    __u32 dir_dev;         // dirfd base s_dev (0 when unavailable)
    __u32 mnt_ns;          // Opener's mount-namespace inum (0 when unavailable)
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
    __u64 file_ino;        // fd target inode (0 when unavailable)
    __u32 file_dev;        // fd target superblock s_dev (0 when unavailable)
    __u32 _pad1;
};

// Track openat pathname across sys_enter/sys_exit so we can emit the returned fd.
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
    __type(key, __u64);               // pid_tgid
    __type(value, struct openat_state);
} openat_state_map SEC(".maps");

// Ring buffer map
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

// Opt-in exact-current-task comm deny policy. Values are stable rule IDs set
// by userspace; policy stats are keyed by rule_id * 8 + operation.
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

static __always_inline __u32 nonregular_drop_key_for_op(__u32 op_type)
{
    return op_type + 56;
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
    // Let the ring buffer's adaptive notification logic wake userspace when
    // the consumer catches up. Suppressing notifications retained low-rate
    // records indefinitely and converted sustained traffic into large bursts.
    bpf_ringbuf_submit(event, 0);
}

// Current task's mount-namespace inum; 0 when unreadable. Keys the
// userspace dir-identity index per namespace (fop-13c) so bind-mount /
// container path aliases cannot resolve through another namespace's view.
static __always_inline __u32 current_mnt_ns(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp)
        return 0;
    struct mnt_namespace *mns = BPF_CORE_READ(nsp, mnt_ns);
    if (!mns)
        return 0;
    return BPF_CORE_READ(mns, ns.inum);
}

// Resolve an fd in the current task to its struct inode (NULL on any miss).
// Same traversal previously proven in is_regular_fd on the RHEL8 verifier.
static __always_inline struct inode *fd_to_inode(__u32 fd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return NULL;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return NULL;

    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd >= max_fds)
        return NULL;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return NULL;

    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file)
        return NULL;

    return BPF_CORE_READ(file, f_inode);
}

// Read (i_mode, s_dev, i_ino) for an fd. Returns 1 when the inode was
// reachable; outputs are zeroed otherwise.
static __always_inline int read_fd_inode_info(__u32 fd, umode_t *mode,
                                              __u32 *dev, __u64 *ino)
{
    *mode = 0;
    *dev = 0;
    *ino = 0;

    struct inode *inode = fd_to_inode(fd);
    if (!inode)
        return 0;

    *mode = BPF_CORE_READ(inode, i_mode);
    *ino = BPF_CORE_READ(inode, i_ino);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (sb)
        *dev = BPF_CORE_READ(sb, s_dev);

    return 1;
}

// Helper to emit event. Fills (dev, ino) identity for regular fds so the
// emit path does not walk the fd table twice.
static __always_inline int is_regular_fd_info(__u32 fd, __u32 *dev, __u64 *ino)
{
    *dev = 0;
    *ino = 0;

    struct inode *inode = fd_to_inode(fd);
    if (!inode)
        return 0;

    umode_t mode = BPF_CORE_READ(inode, i_mode);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (sb) {
        unsigned long magic = BPF_CORE_READ(sb, s_magic);
        if (magic == PROC_SUPER_MAGIC || magic == SYSFS_MAGIC ||
            magic == DEVPTS_SUPER_MAGIC || magic == DEVTMPFS_MAGIC)
            return 0;
        *dev = BPF_CORE_READ(sb, s_dev);
    }

    *ino = BPF_CORE_READ(inode, i_ino);
    return 1;
}

static __always_inline void emit_file_fd_event(__u32 pid, __u32 fd,
                                               __u32 bytes, __u32 op_type,
                                               __u32 file_dev, __u64 file_ino)
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
    event->file_ino = file_ino;
    event->file_dev = file_dev;
    event->_pad1 = 0;

    submit_file_event(event);
    increment_stat(emitted_key_for_op(op_type));
}

static __always_inline void emit_file_event_saved(__u32 pid, const char *filename_buf,
                                                   __u32 fd, __u32 bytes, __u32 op_type,
                                                   __s32 dirfd,
                                                   __u32 file_dev, __u64 file_ino,
                                                   __u32 dir_dev, __u64 dir_ino,
                                                   __u32 mnt_ns)
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
    event->file_ino = file_ino;
    event->dir_ino = dir_ino;
    event->file_dev = file_dev;
    event->dir_dev = dir_dev;
    event->mnt_ns = mnt_ns;
    event->_pad0 = 0;

    submit_file_event(event);
    increment_stat(emitted_key_for_op(op_type));
}

static __always_inline void emit_file_event_user(__u32 pid, const char *filename,
                                                  __u32 fd, __u32 bytes, __u32 op_type,
                                                  __s32 dirfd)
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

    // Unlink has no surviving file fd. Preserve the base at syscall entry,
    // before a worker closes/reuses its dirfd, changes cwd, or exits. Userspace
    // resolves learned directory identities, never a late PID/fd guess.
    // This remains unlink intent, not proof of successful syscall completion.
    if (op_type == FILE_OP_UNLINK && event->filename[0] != '/') {
        event->mnt_ns = current_mnt_ns();
        umode_t mode = 0;
        __u32 dev = 0;
        __u64 ino = 0;
        if (dirfd >= 0) {
            read_fd_inode_info((__u32)dirfd, &mode, &dev, &ino);
        } else if (dirfd == AT_FDCWD) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
            struct inode *inode = BPF_CORE_READ(task, fs, pwd.dentry, d_inode);
            if (inode) {
                mode = BPF_CORE_READ(inode, i_mode);
                ino = BPF_CORE_READ(inode, i_ino);
                dev = BPF_CORE_READ(inode, i_sb, s_dev);
            }
        }
        if ((mode & S_IFMT) == S_IFDIR) {
            event->dir_dev = dev;
            event->dir_ino = ino;
        }
    }

    submit_file_event(event);
    increment_stat(emitted_key_for_op(op_type));
}

// openat - File open (emit on sys_exit to capture returned fd)
struct openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

// Common sys_exit tracepoint layout for syscalls.
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

// open - legacy open syscall (some runtimes still use it)
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

    // Read from the map value directly (no 264-byte stack copy; BPF stack
    // budget) and delete the entry only after emission — this thread is the
    // only writer for its own pid_tgid key.
    long fd = ctx->ret;
    if (fd < 0) {
        bpf_map_delete_elem(&openat_state_map, &pid_tgid);
        return 0;
    }

    __u32 flags = stp->flags;
    __s32 dirfd = stp->dirfd;
    char first_byte = stp->filename[0];

    umode_t mode = 0;
    __u32 file_dev = 0;
    __u64 file_ino = 0;
    int have_info = read_fd_inode_info((__u32)fd, &mode, &file_dev, &file_ino);

    // Base-directory identity for relative opens: resolvable later against
    // the userspace (s_dev, i_ino) -> dir-path index even after this
    // process exits.
    __u32 dir_dev = 0;
    __u64 dir_ino = 0;
    umode_t dir_mode = 0;
    if (dirfd >= 0 && first_byte != '/')
        read_fd_inode_info((__u32)dirfd, &dir_mode, &dir_dev, &dir_ino);

    // Directory handles become internal DIR_OPEN records (previously
    // discarded) so userspace can learn dirfd identities; catch both the
    // O_DIRECTORY flag and un-flagged opens of directories.
    __u32 op = ((flags & O_DIRECTORY) || (have_info && (mode & S_IFMT) == S_IFDIR))
                   ? FILE_OP_DIR_OPEN
                   : FILE_OP_OPEN;

    emit_file_event_saved(pid, stp->filename, (__u32)fd, 0, op,
                          dirfd, file_dev, file_ino, dir_dev, dir_ino,
                          current_mnt_ns());
    bpf_map_delete_elem(&openat_state_map, &pid_tgid);
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

    // Read from the map value directly (no stack copy) and delete only
    // after emission — this thread owns its pid_tgid key.
    long fd = ctx->ret;
    if (fd < 0) {
        bpf_map_delete_elem(&openat_state_map, &pid_tgid);
        return 0;
    }

    __u32 flags = stp->flags;
    __s32 dirfd = stp->dirfd;
    char first_byte = stp->filename[0];

    umode_t mode = 0;
    __u32 file_dev = 0;
    __u64 file_ino = 0;
    int have_info = read_fd_inode_info((__u32)fd, &mode, &file_dev, &file_ino);

    __u32 dir_dev = 0;
    __u64 dir_ino = 0;
    umode_t dir_mode = 0;
    if (dirfd >= 0 && first_byte != '/')
        read_fd_inode_info((__u32)dirfd, &dir_mode, &dir_dev, &dir_ino);

    __u32 op = ((flags & O_DIRECTORY) || (have_info && (mode & S_IFMT) == S_IFDIR))
                   ? FILE_OP_DIR_OPEN
                   : FILE_OP_OPEN;

    emit_file_event_saved(pid, stp->filename, (__u32)fd, 0, op,
                          dirfd, file_dev, file_ino, dir_dev, dir_ino,
                          current_mnt_ns());
    bpf_map_delete_elem(&openat_state_map, &pid_tgid);
    return 0;
}

// read - File read (use enter to get FD)
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
    __u32 file_dev = 0;
    __u64 file_ino = 0;
    if (!is_regular_fd_info(ctx->fd, &file_dev, &file_ino)) {
        increment_stat(nonregular_drop_key_for_op(FILE_OP_READ));
        return 0;
    }

    emit_file_fd_event(pid, ctx->fd, (__u32)ctx->count, FILE_OP_READ, file_dev, file_ino);
    return 0;
}

// write - File write (use enter to get FD)
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
    __u32 file_dev = 0;
    __u64 file_ino = 0;
    if (!is_regular_fd_info(ctx->fd, &file_dev, &file_ino)) {
        increment_stat(nonregular_drop_key_for_op(FILE_OP_WRITE));
        return 0;
    }

    emit_file_fd_event(pid, ctx->fd, (__u32)ctx->count, FILE_OP_WRITE, file_dev, file_ino);
    return 0;
}

// close - File close
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
    __u32 file_dev = 0;
    __u64 file_ino = 0;
    if (!is_regular_fd_info(ctx->fd, &file_dev, &file_ino)) {
        increment_stat(nonregular_drop_key_for_op(FILE_OP_CLOSE));
        return 0;
    }

    emit_file_fd_event(pid, ctx->fd, 0, FILE_OP_CLOSE, file_dev, file_ino);
    return 0;
}

// mmap - Memory mapping
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
    
    // Only track file-backed mmaps (fd != -1)
    if (ctx->fd != -1) {
        __u32 file_dev = 0;
        __u64 file_ino = 0;
        if (!is_regular_fd_info((__u32)ctx->fd, &file_dev, &file_ino)) {
            increment_stat(nonregular_drop_key_for_op(FILE_OP_MMAP));
            return 0;
        }
        emit_file_fd_event(pid, (__u32)ctx->fd, ctx->len, FILE_OP_MMAP, file_dev, file_ino);
    }
    
    return 0;
}

// unlinkat - File deletion
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

// unlink - File deletion (non-*at variant)
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
