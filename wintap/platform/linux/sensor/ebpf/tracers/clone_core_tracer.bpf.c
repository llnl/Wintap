#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Same event ABI as clone_tracer.bpf.c; classification does not depend on
// optional syscall hooks or the clone/clone3 userspace argument layout.
struct clone_event {
    __u32 parent_pid, parent_uid, parent_gid;
    char parent_comm[16];
    __u32 child_pid;
    __u64 timestamp_ns, clone_flags;
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("raw_tracepoint/sched_process_fork")
int trace_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *parent = (void *)ctx->args[0];
    struct task_struct *child = (void *)ctx->args[1];
    __u32 pid = BPF_CORE_READ(child, pid);
    __u32 tgid = BPF_CORE_READ(child, tgid);
    if (pid != tgid)
        return 0;
    struct clone_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    event->parent_pid = BPF_CORE_READ(parent, tgid);
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->parent_uid = (__u32)uid_gid;
    event->parent_gid = uid_gid >> 32;
    BPF_CORE_READ_INTO(&event->parent_comm, parent, comm);
    event->child_pid = tgid;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->clone_flags = 0; // Not needed: child pid/tgid is authoritative.
    bpf_ringbuf_submit(event, 0);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
