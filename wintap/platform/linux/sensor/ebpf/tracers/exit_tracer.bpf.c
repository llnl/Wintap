#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "task_start_boottime.h"

#define TASK_COMM_LEN 16

// Event structure for process exit
struct exit_event {
    // Process identification
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    
    // Process details
    char comm[TASK_COMM_LEN];
    
    // Timing
    __u64 timestamp_ns;
    
    // Exit information
    __s32 exit_code;
    // Extended 64-byte ABI; preserve the legacy 48-byte prefix. Separate clocks:
    // boottime matches /proc start identity; monotonic matches timestamp_ns.
    __u64 start_boot_ns;
    __u64 start_monotonic_ns;
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint structure for sched_process_exit
// This is a minimal safe structure
struct sched_exit_args {
    unsigned long long unused;
    char comm[16];
    __s32 pid;
    int prio;
};

// Hook process exit
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct sched_exit_args *ctx)
{
    struct exit_event *event;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 task_pid = BPF_CORE_READ(task, pid);
    __u32 task_tgid = BPF_CORE_READ(task, tgid);

    // sched_process_exit is task-level. Emit only process/thread-group exits
    // so thread exits do not create unmatched Stop records in userspace.
    if (task_pid != task_tgid)
        return 0;
    
    // Reserve space
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Use TGID as the Wintap process PID.
    event->pid = task_tgid;
    
    // Get UID/GID (still available during exit)
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    
    // Get command name (from tracepoint)
    __builtin_memcpy(event->comm, ctx->comm, TASK_COMM_LEN);
    
    // Get timestamp
    event->timestamp_ns = bpf_ktime_get_ns();
    
    // Best-effort parent pid + exit code from task_struct.
    // This runs in the context of the exiting task.
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    event->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;

    // Kernel stores wait status in task->exit_code.
    event->exit_code = BPF_CORE_READ(task, exit_code);
    event->start_boot_ns = wintap_task_start_boottime_ns(task);
    event->start_monotonic_ns = BPF_CORE_READ(task, start_time);
    
    // Submit
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
