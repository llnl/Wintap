// Deterministic births manifest; build with cc -O2 -pthread -o workload this_file.c.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

static void record(const char *kind) {
    if (getenv("WINTAP_SMOKE_NAMES")) {
        char name[16];
        const char *label = kind;
        if (!strcmp(kind, "clone3_process")) label = "clone3proc";
        if (!strcmp(kind, "clone3_thread")) label = "clone3thr";
        if (!strcmp(kind, "clone_process")) label = "cloneproc";
        if (!strcmp(kind, "clone_thread")) label = "clonethr";
        snprintf(name, sizeof(name), "wt_%s", label);
        prctl(PR_SET_NAME, name, 0, 0, 0);
    }
    char buf[200];
    int n = snprintf(buf, sizeof(buf), "%s %ld %ld %ld\n", kind,
        (long)getpid(), (long)syscall(SYS_gettid), (long)getppid());
    if (write(STDOUT_FILENO, buf, n) != n) _exit(2);
}
static volatile int thread_done;
__attribute__((used, noinline)) void raw_thread(void) {
    record("clone3_thread");
    __atomic_store_n(&thread_done, 1, __ATOMIC_RELEASE);
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}
// A raw clone3 child with a new stack cannot return into the caller's C frame.
#if defined(__aarch64__)
__asm__(".text\n.global spawn_thread3\nspawn_thread3:\n"
        "mov x8, #435\nsvc #0\ncbnz x0, 1f\nbl raw_thread\n1: ret\n");
#elif defined(__x86_64__)
__asm__(".text\n.global spawn_thread3\nspawn_thread3:\n"
        "mov $435, %rax\nsyscall\ntest %rax, %rax\njnz 1f\ncall raw_thread\n1: ret\n");
#else
#error Unsupported workload architecture
#endif
extern long spawn_thread3(struct clone_args *, size_t);

static void wait_child(pid_t p) {
    int status;
    if (p < 0 || waitpid(p, &status, 0) != p || !WIFEXITED(status) || WEXITSTATUS(status)) {
        perror("child"); exit(1);
    }
}
static void *pthread_body(void *arg) {
    record("pthread");
    pid_t p = fork();
    if (!p) { record("worker_fork"); _exit(0); }
    wait_child(p);
    return NULL;
}
static int legacy_thread(void *arg) {
    record("clone_thread");
    __atomic_store_n(&thread_done, 1, __ATOMIC_RELEASE);
    return 0;
}
static int legacy_process(void *arg) {
    record("clone_process");
    return 0;
}
static void wait_thread(void) {
    while (!__atomic_load_n(&thread_done, __ATOMIC_ACQUIRE)) usleep(1000);
    // Keep the mapping alive until the task has fully returned/exited.
    usleep(20000);
}
int main(int argc, char **argv) {
    int rounds = 20;
    if (argc == 2 && !strncmp(argv[1], "--rounds=", 9)) {
        rounds = atoi(argv[1] + 9);
        if (rounds < 1 || rounds > 1000) return 2;
    } else if (argc > 1) { record(!strcmp(argv[1], "vfork_image") ? "vfork_image" : "exec_image"); return 0; }
    record("root");
    for (int i = 0; i < rounds; i++) {
        pid_t p = fork();
        if (!p) { record("fork_only"); _exit(0); }
        wait_child(p);
        if (getenv("WINTAP_SMOKE_NAMES")) {
            // Explicit legacy clone process and safe vfork+exec probes are smoke
            // extras only; preserve the existing default validation manifest.
            void *process_stack = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
            if (process_stack == MAP_FAILED) return 1;
            p = clone(legacy_process, (char *)process_stack + (1 << 20), SIGCHLD, NULL);
            wait_child(p);
            munmap(process_stack, 1 << 20);
            p = vfork();
            if (!p) {
                // Do not call record/prctl or touch parent state in vfork child.
                execl("/proc/self/exe", "wt_vfork_exec", "vfork_image", NULL);
                _exit(1);
            }
            wait_child(p);
        }
        p = fork();
        if (!p) {
            record("fork_exec");
            execl("/proc/self/exe", "clone-workload", "exec", NULL);
            _exit(1);
        }
        wait_child(p);
        pthread_t t;
        if (pthread_create(&t, NULL, pthread_body, NULL) || pthread_join(t, NULL)) return 1;
        void *stack = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack == MAP_FAILED) return 1;
        thread_done = 0;
        if (clone(legacy_thread, (char *)stack + (1 << 20),
            CLONE_VM | CLONE_THREAD | CLONE_SIGHAND, NULL) < 0) return 1;
        wait_thread();
        // Retain stacks until process exit: no racy unmap while a child exits.
        stack = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack == MAP_FAILED) return 1;
        struct clone_args args = { .flags = CLONE_VM | CLONE_THREAD | CLONE_SIGHAND,
            .stack = (unsigned long)stack, .stack_size = 1 << 20 };
        thread_done = 0;
        long tid = spawn_thread3(&args, sizeof(args));
        if (tid < 0) printf("SKIP clone3_thread errno=%ld\n", -tid);
        else wait_thread();
        args = (struct clone_args){ .exit_signal = SIGCHLD };
        p = syscall(SYS_clone3, &args, sizeof(args));
        if (!p) { record("clone3_process"); _exit(0); }
        if (p < 0) printf("SKIP clone3_process errno=%d\n", errno);
        else wait_child(p);
    }
    return 0;
}
