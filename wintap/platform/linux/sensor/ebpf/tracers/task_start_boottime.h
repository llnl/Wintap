#ifndef WINTAP_TASK_START_BOOTTIME_H
#define WINTAP_TASK_START_BOOTTIME_H

#include <bpf/bpf_core_read.h>

/*
 * Kernel BTF has used both names for task start time in the boottime clock
 * domain. Upstream kernels expose start_boottime; RHEL 8's 4.18 kernel
 * exposes real_start_time. CO-RE flavor structs let both fields be probed
 * even though only one is present in the build host's vmlinux.h.
 */
struct task_struct___wintap_start_boottime {
    __u64 start_boottime;
} __attribute__((preserve_access_index));

struct task_struct___wintap_real_start_time {
    __u64 real_start_time;
} __attribute__((preserve_access_index));

static __always_inline __u64 wintap_task_start_boottime_ns(struct task_struct *task)
{
    struct task_struct___wintap_start_boottime *boottime_task = (void *)task;
    if (bpf_core_field_exists(boottime_task->start_boottime))
        return BPF_CORE_READ(boottime_task, start_boottime);

    struct task_struct___wintap_real_start_time *real_start_task = (void *)task;
    if (bpf_core_field_exists(real_start_task->real_start_time))
        return BPF_CORE_READ(real_start_task, real_start_time);

    return 0;
}

#endif /* WINTAP_TASK_START_BOOTTIME_H */
