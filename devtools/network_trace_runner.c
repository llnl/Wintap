// Dev-time only: attaches a reviewed network BPF object on a designated idle VM.
// No collector/service/configuration changes. Build: cc -O2 ... -lbpf -lelf -lz
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct network_event {
    uint32_t pid;
    char comm[16];
    uint64_t timestamp_ns;
    uint32_t saddr, daddr;
    uint16_t sport, dport;
    uint8_t protocol, op_type;
    uint32_t bytes;
    uint8_t is_ipv6, saddr_v6[16], daddr_v6[16];
};
static volatile sig_atomic_t stopped;
static FILE *output;
static int baseline;
static void stop(int sig) { (void)sig; stopped = 1; }
static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return now.tv_sec + now.tv_nsec / 1e9;
}
static int event(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (size != sizeof(struct network_event)) return 0;
    const struct network_event *e = data;
    if (e->protocol != 6 && e->protocol != 17) return 0;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));
    fprintf(output, "%u,%llu,%u,%u,%s,%u,%s,%u,%u\n", e->pid,
        (unsigned long long)e->timestamp_ns, e->protocol, e->op_type,
        src, e->sport, dst, e->dport, e->bytes);
    return 0;
}
static int required(const char *name) {
    if (baseline && !strcmp(name, "kretprobe__udp_sendmsg")) return 0;
    const char *names[] = {"trace_inet_sock_set_state", "kretprobe__inet_csk_accept",
        "kprobe__tcp_sendmsg", "kprobe__tcp_recvmsg", "kprobe__tcp_close",
        "kprobe__udp_sendmsg", "kretprobe__udp_sendmsg", "kprobe__udp_recvmsg",
        "kretprobe__udp_recvmsg"};
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++)
        if (!strcmp(name, names[i])) return 1;
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 6 && !(argc == 7 && !strcmp(argv[6], "--baseline"))) {
        fprintf(stderr, "usage: runner OBJECT OUTPUT.csv READY CAPTURE_PID SECONDS [--baseline]\n");
        return 2;
    }
    baseline = argc == 7;
    unsigned pid = (unsigned)strtoul(argv[4], NULL, 10);
    int seconds = atoi(argv[5]);
    if (!pid || seconds < 1 || seconds > 120) return 2;
    signal(SIGINT, stop); signal(SIGTERM, stop);
    double start = monotonic_seconds();
    if (start < 0) return 2;
    double until = start + seconds;
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) return 3;
    int status = 3;
    struct bpf_link *links[64] = {0};
    int count = 0, found = 0;
    struct ring_buffer *ring = NULL;
    if (bpf_object__load(obj)) goto cleanup;
    int fd = bpf_object__find_map_fd_by_name(obj, "capture_pid");
    uint32_t key = 0;
    if (fd < 0 || bpf_map_update_elem(fd, &key, &pid, BPF_ANY)) goto cleanup;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (stopped || monotonic_seconds() >= until) goto cleanup;
        const char *name = bpf_program__name(prog);
        if (count == 64) goto cleanup;
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "attach failed: %s\n", name);
            if (required(name)) goto cleanup;
        } else {
            links[count++] = link;
            found += required(name);
        }
    }
    if (found != (baseline ? 8 : 9)) goto cleanup;
    output = fopen(argv[2], "wx");
    if (!output) goto cleanup;
    fprintf(output, "pid,time_ns,protocol,operation,source,source_port,destination,destination_port,bytes\n");
    fd = bpf_object__find_map_fd_by_name(obj, "events");
    ring = ring_buffer__new(fd, event, NULL, NULL);
    if (!ring) goto cleanup;
    FILE *ready = fopen(argv[3], "wx");
    if (!ready) goto cleanup;
    fputs("attached\n", ready);
    fclose(ready);
    while (!stopped && monotonic_seconds() < until) {
        int rc = ring_buffer__poll(ring, 100);
        if (rc < 0 && rc != -EINTR) goto cleanup;
    }
    status = ferror(output) ? 4 : 0;
    const char *maps[] = {"udp_recvmsg_sock_map", "udp_recvmsg_peer_map", "udp_sendmsg_ctx_map"};
    for (size_t i = 0; i < (baseline ? 2 : sizeof(maps)/sizeof(maps[0])); i++) {
        uint64_t next;
        fd = bpf_object__find_map_fd_by_name(obj, maps[i]);
        int rc = fd < 0 ? -1 : bpf_map_get_next_key(fd, NULL, &next);
        fprintf(stderr, "context-map %s empty=%d\n", maps[i], rc < 0 && errno == ENOENT);
        if (fd < 0 || rc == 0 || errno != ENOENT) status = 5;
    }
cleanup:
    ring_buffer__free(ring);
    if (output) fclose(output);
    for (int i = 0; i < count; i++) bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return status;
}
