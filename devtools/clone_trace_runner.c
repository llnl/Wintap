// Attach the actual clone object, optionally excluding auxiliary syscall hooks.
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct clone_event { uint32_t parent_pid, uid, gid; char comm[16];
    uint32_t child_pid; uint64_t timestamp, flags; };
static volatile sig_atomic_t stopped;
static void stop(int sig) { stopped = 1; }
static int event(void *ctx, void *data, size_t size) {
    if (size != sizeof(struct clone_event)) return -1;
    struct clone_event *e = data;
    printf("%u %u %llu\n", e->parent_pid, e->child_pid, (unsigned long long)e->flags);
    fflush(stdout);
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj) || bpf_object__load(obj)) return 3;
    struct bpf_link *links[8]; int n = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (argc > 2 && strcmp(bpf_program__name(prog), "trace_process_fork")) continue;
        links[n] = bpf_program__attach(prog);
        if (!links[n] || libbpf_get_error(links[n])) {
            if (!strcmp(bpf_program__name(prog), "trace_process_fork")) return 4;
            fprintf(stderr, "OPTIONAL_ATTACH_FAILED %s\n", bpf_program__name(prog));
            continue;
        }
        n++;
    }
    struct ring_buffer *rb = ring_buffer__new(
        bpf_object__find_map_fd_by_name(obj, "events"), event, NULL, NULL);
    if (!rb) return 5;
    signal(SIGTERM, stop); signal(SIGINT, stop);
    fprintf(stderr, "READY links=%d\n", n); fflush(stderr);
    while (!stopped) ring_buffer__poll(rb, 100);
    ring_buffer__free(rb);
    while (n) bpf_link__destroy(links[--n]);
    bpf_object__close(obj);
    return 0;
}
