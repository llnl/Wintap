#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Network byte order conversion
#define bpf_ntohs(x) __builtin_bswap16(x)

#define TASK_COMM_LEN 16

// TCP state values from include/net/tcp_states.h
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_CLOSE 7
#define TCP_LISTEN 10

#define AF_INET 2

// Network operation types
enum net_op_type {
    NET_OP_TCP_CONNECT = 1,
    NET_OP_TCP_ACCEPT = 2,
    NET_OP_TCP_SEND = 3,
    NET_OP_TCP_RECV = 4,
    NET_OP_TCP_CLOSE = 5,
    NET_OP_UDP_SEND = 6,
    NET_OP_UDP_RECV = 7
};

// Network protocol types
enum net_proto {
    PROTO_TCP = 6,
    PROTO_UDP = 17
};

// Event structure for network operations
struct network_event {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp_ns;
    
    // Connection info
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 op_type;
    
    // Data size
    __u32 bytes;
    
    // IPv6 support (for future)
    __u8 is_ipv6;
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

// Diagnostic counters: per-CPU array with indexes:
// 0 = STORE, 1 = HIT (lookup found), 2 = MISS (lookup absent)
// Use a per-cpu array so increments are cheaper and avoid cross-cpu races.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} diag_counters SEC(".maps");

// Optional PID filter for reducing event volume. When set to a non-zero PID,
// the tracer will only emit events (and attribution diagnostics) for that PID.
// Key is always 0.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} capture_pid SEC(".maps");

static __always_inline int pid_allowed(__u32 pid)
{
    __u32 k0 = 0;
    __u32 *want = bpf_map_lookup_elem(&capture_pid, &k0);
    if (!want || *want == 0)
        return 1;
    return pid == *want;
}

static __always_inline void diag_inc(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&diag_counters, &idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

// Map to store PID (and timestamp) keyed by socket pointer. We populate this
// at syscall/kprobe time (user/process context) and consult it in the
// inet_sock_set_state tracepoint which often runs in softirq where
// bpf_get_current_pid_tgid() is unreliable for process attribution.
struct sock_info {
    __u32 pid;
    __u64 start_ns;
    __u8 source; // 1=connect path, 2=accept path
};

#define SOCK_SRC_CONNECT 1
#define SOCK_SRC_ACCEPT  2

// Use a 64-bit integer key for socket pointer to avoid ABI/typing issues when
// passing pointers between kprobe and tracepoint contexts. Using __u64 is
// more portable than `void *` as a map key across libbpf/clang toolchains.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct sock_info);
    __uint(max_entries, 10240);
} sock_pid_map SEC(".maps");

// pid_tgid -> sock pointer for tcp_*_connect kretprobes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 8192);
} tcp_connect_sk_map SEC(".maps");

// Connection info stored keyed by socket pointer so we can attribute
// send/recv events with addresses without reading kernel struct layout.
struct conn_info {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 start_ns;

    // Rate-limit tcp_sendmsg/tcp_recvmsg emission per socket to avoid flooding
    // userland (and OOMing the host) on high-volume systems.
    __u64 last_send_ns;
    __u64 last_recv_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct conn_info);
    __uint(max_entries, 16384);
} conn_map SEC(".maps");

// Per-socket rate limiting for UDP send/recv probes to avoid event floods.
struct udp_rate {
    __u64 last_send_ns;
    __u64 last_recv_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct udp_rate);
    __uint(max_entries, 16384);
} udp_rate_map SEC(".maps");

// Per-thread kernel socket context, including connected recv without peer buffer.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 8192);
} udp_recvmsg_sock_map SEC(".maps");

// pid_tgid -> KERNEL msghdr pointer. msg_name and its populated length are
// read at udp_recvmsg return, before the socket layer copies to user memory.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 8192);
} udp_recvmsg_peer_map SEC(".maps");

struct udp_send_context {
    __u64 sk;
    __u32 peer_addr;
    __u16 peer_port;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct udp_send_context);
    __uint(max_entries, 8192);
} udp_sendmsg_ctx_map SEC(".maps");

// Helper to emit network event
static __always_inline void emit_network_event(__u32 pid, __u32 saddr, __u32 daddr,
                                                __u16 sport, __u16 dport, __u8 protocol,
                                                __u8 op_type, __u32 bytes)
{
    struct network_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->timestamp_ns = bpf_ktime_get_ns();
    
    event->saddr = saddr;
    event->daddr = daddr;
    event->sport = sport;
    event->dport = dport;
    event->protocol = protocol;
    event->op_type = op_type;
    event->bytes = bytes;
    event->is_ipv6 = 0;
    
    bpf_ringbuf_submit(event, 0);
}

// Emit a small in-band diagnostic event via the same ring buffer. We use
// protocol=0xFF to indicate diagnostics and put a small code in op_type.
// The 'bytes' field holds the low 32 bits of the socket pointer to help
// correlate events; sport holds low 16 bits as well for quick human-read.
static __always_inline void emit_diag_event(__u8 diag_code, __u32 pid, void *sk)
{
    __u32 sk_lo = 0;
    __u16 sk_lo16 = 0;
    if (sk) {
        __u64 sk64 = (__u64)sk;
        sk_lo = (__u32)(sk64 & 0xffffffffULL);
        sk_lo16 = (__u16)(sk64 & 0xffffULL);
    }

    // Use emit_network_event with protocol=0xFF to signal a diagnostic
    emit_network_event(pid, 0, 0, 0, sk_lo16, 0xFF, diag_code, sk_lo);
}

// sock:inet_sock_set_state tracepoint context. This tracepoint fires after
// the kernel has assigned socket addresses, so it includes the local address
// that is not available at sys_enter_connect time.
struct inet_sock_set_state_args {
    unsigned long long unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_args *ctx)
{
    // NOTE: The kernel tracepoint argument layout can vary across distros and
    // backports. To keep address/port extraction robust on RHEL8 kernels, we
    // derive tuple information from the live `struct sock` via CO-RE reads
    // rather than trusting ctx->{family,protocol,saddr,daddr,sport,dport}.
    void *sk = (void *)ctx->skaddr;
    if (!sk)
        return 0;

    struct sock *sock = (struct sock *)sk;
    __u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    // Protocol is provided by the tracepoint; avoid reading sk_protocol here
    // because it is a bitfield on some kernels. If the tracepoint layout is
    // different (backports), default to TCP so we don't silently drop events.
    __u16 proto = ctx->protocol;
    if (proto != PROTO_TCP && proto != PROTO_UDP)
        proto = PROTO_TCP;

    // NOTE: On some RHEL8 kernels, the inet_sock_set_state tracepoint's
    // old/new state fields don't reliably match the TCP_* constants. We keep
    // this tracepoint purely for populating conn_map (tuple cache), and emit
    // TcpIpConnect/TcpIpDisconnect from tcp_v4_connect kretprobes / tcp_close
    // kprobes instead.
    __u8 op_type = 0;

    // Prefer PID captured at syscall/kprobe time (stored keyed by socket ptr).
    // Fall back to bpf_get_current_pid_tgid() if no entry exists.
    __u32 pid = 0;
    // Use a u64 key that holds the pointer value for map operations.
    __u64 sk_key = (__u64)sk;
    struct sock_info *si = bpf_map_lookup_elem(&sock_pid_map, &sk_key);
    if (si) {
        // If the stored entry is too old, consider it stale and delete it.
        __u64 now = bpf_ktime_get_ns();
        const __u64 max_age_ns = 5ULL * 1000000000ULL; // 5 seconds
        if (now - si->start_ns > max_age_ns) {
            // stale entry
            bpf_map_delete_elem(&sock_pid_map, &sk_key);
            emit_diag_event(2, 0, sk); // report as MISS/stale
            diag_inc(2);
            pid = 0;
        } else {
            pid = si->pid;
            if (!pid_allowed(pid)) {
                // still consume/delete the entry, but skip emits
                bpf_map_delete_elem(&sock_pid_map, &sk_key);
                return 0;
            }
            // once consumed, delete to avoid leaks
            bpf_map_delete_elem(&sock_pid_map, &sk_key);
            // Emit in-band diagnostic: HIT (code 1)
            emit_diag_event(1, pid, sk);
            diag_inc(1);
        }
    } else {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        pid = pid_tgid >> 32;
        if (!pid_allowed(pid))
            return 0;
        // Emit in-band diagnostic: MISS (code 2)
        emit_diag_event(2, pid, sk);
        diag_inc(2);
    }

    __u32 saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    __u16 sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));

    // Store a copy of the connection tuple keyed by socket pointer so other
    // kprobe-based handlers can later lookup addresses without reading
    // kernel struct fields. This is used for:
    // - TCP send/recv
    // - UDP send/recv for connected UDP sockets (connect+sendmsg/recvmsg)
    struct conn_info cinfo = {};
    cinfo.saddr = saddr;
    cinfo.daddr = daddr;
    cinfo.sport = sport;
    cinfo.dport = dport;
    cinfo.start_ns = bpf_ktime_get_ns();
    __u64 sk_key_for_store = (__u64)sk;
    bpf_map_update_elem(&conn_map, &sk_key_for_store, &cinfo, BPF_ANY);

    return 0;
}

static __always_inline void emit_tcp_connect_event(__u32 pid, void *sk)
{
    struct sock *sock = (struct sock *)sk;
    __u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (family != AF_INET)
        return;

    __u32 saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    __u16 sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));

    // Seed conn_map for subsequent send/recv lookups.
    struct conn_info cinfo = {};
    cinfo.saddr = saddr;
    cinfo.daddr = daddr;
    cinfo.sport = sport;
    cinfo.dport = dport;
    cinfo.start_ns = bpf_ktime_get_ns();
    __u64 sk_key = (__u64)sk;
    bpf_map_update_elem(&conn_map, &sk_key, &cinfo, BPF_ANY);

    emit_network_event(pid, saddr, daddr, sport, dport, PROTO_TCP, NET_OP_TCP_CONNECT, 0);
}

static __always_inline void emit_tcp_disconnect_event(__u32 pid, void *sk)
{
    __u64 sk_key = (__u64)sk;
    struct conn_info *ci = bpf_map_lookup_elem(&conn_map, &sk_key);
    if (ci) {
        emit_network_event(pid, ci->saddr, ci->daddr, ci->sport, ci->dport,
                           PROTO_TCP, NET_OP_TCP_CLOSE, 0);
        bpf_map_delete_elem(&conn_map, &sk_key);
        return;
    }

    // Fallback to live socket fields.
    struct sock *sock = (struct sock *)sk;
    __u16 family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (family != AF_INET)
        return;
    __u32 saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    __u16 sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
    emit_network_event(pid, saddr, daddr, sport, dport, PROTO_TCP, NET_OP_TCP_CLOSE, 0);
}

// Kprobe on tcp_v4_connect to capture the socket pointer in process context.
// This lets us attribute the subsequent inet_sock_set_state event to the
// originating PID even when inet_sock_set_state runs in softirq.
SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 sk_key_tmp = (__u64)sk;
    bpf_map_update_elem(&tcp_connect_sk_map, &pid_tgid, &sk_key_tmp, BPF_ANY);

    struct sock_info info = {};
    info.pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(info.pid))
        return 0;
    info.start_ns = bpf_ktime_get_ns();
    info.source = SOCK_SRC_CONNECT;
    __u64 sk_key = (__u64)sk;
    bpf_map_update_elem(&sock_pid_map, &sk_key, &info, BPF_ANY);
    // Emit in-band diagnostic: STORE (code 0)
    emit_diag_event(0, info.pid, sk);
    diag_inc(0);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    long rc = (long)PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *skp = bpf_map_lookup_elem(&tcp_connect_sk_map, &pid_tgid);
    if (!skp)
        return 0;
    __u64 sk_key_tmp = *skp;
    // Always cleanup.
    bpf_map_delete_elem(&tcp_connect_sk_map, &pid_tgid);
    if (rc != 0)
        return 0;
    void *sk = (void *)sk_key_tmp;
    if (!sk)
        return 0;
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    emit_tcp_connect_event(pid, sk);
    return 0;
}

// Also attach to tcp_v6_connect in case kernel uses the IPv6 path for
// dual-stack sockets or different internal call paths.
SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 sk_key_tmp = (__u64)sk;
    bpf_map_update_elem(&tcp_connect_sk_map, &pid_tgid, &sk_key_tmp, BPF_ANY);

    struct sock_info info = {};
    info.pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(info.pid))
        return 0;
    info.start_ns = bpf_ktime_get_ns();
    info.source = SOCK_SRC_CONNECT;
    __u64 sk_key = (__u64)sk;
    bpf_map_update_elem(&sock_pid_map, &sk_key, &info, BPF_ANY);
    // Emit in-band diagnostic: STORE (code 0)
    emit_diag_event(0, info.pid, sk);
    diag_inc(0);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
    long rc = (long)PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *skp = bpf_map_lookup_elem(&tcp_connect_sk_map, &pid_tgid);
    if (!skp)
        return 0;
    __u64 sk_key_tmp = *skp;
    bpf_map_delete_elem(&tcp_connect_sk_map, &pid_tgid);
    if (rc != 0)
        return 0;
    void *sk = (void *)sk_key_tmp;
    if (!sk)
        return 0;
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    emit_tcp_connect_event(pid, sk);
    return 0;
}

// Generic tcp_connect symbol as a fallback on kernels that export a common
// connector symbol name.
SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 sk_key_tmp = (__u64)sk;
    bpf_map_update_elem(&tcp_connect_sk_map, &pid_tgid, &sk_key_tmp, BPF_ANY);

    struct sock_info info = {};
    info.pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(info.pid))
        return 0;
    info.start_ns = bpf_ktime_get_ns();
    info.source = SOCK_SRC_CONNECT;
    __u64 sk_key = (__u64)sk;
    bpf_map_update_elem(&sock_pid_map, &sk_key, &info, BPF_ANY);
    // Emit in-band diagnostic: STORE (code 0)
    emit_diag_event(0, info.pid, sk);
    diag_inc(0);
    return 0;
}

SEC("kretprobe/tcp_connect")
int kretprobe__tcp_connect(struct pt_regs *ctx)
{
    long rc = (long)PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *skp = bpf_map_lookup_elem(&tcp_connect_sk_map, &pid_tgid);
    if (!skp)
        return 0;
    __u64 sk_key_tmp = *skp;
    bpf_map_delete_elem(&tcp_connect_sk_map, &pid_tgid);
    if (rc != 0)
        return 0;
    void *sk = (void *)sk_key_tmp;
    if (!sk)
        return 0;
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    emit_tcp_connect_event(pid, sk);
    return 0;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    emit_tcp_disconnect_event(pid, sk);
    return 0;
}

// The accept path returns a newly-allocated socket pointer; capture it in a
// kretprobe so we can see the return value (the accepted struct sock *).
SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_RC(ctx);
    if (!sk || (__u64)sk >= (__u64)-4095)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock_info info = {};
    info.pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(info.pid))
        return 0;
    info.start_ns = bpf_ktime_get_ns();
    info.source = SOCK_SRC_ACCEPT;
    __u64 sk_key = (__u64)sk;
    bpf_map_update_elem(&sock_pid_map, &sk_key, &info, BPF_ANY);
    struct sock *sock = (struct sock *)sk;
    if (BPF_CORE_READ(sock, __sk_common.skc_family) != AF_INET)
        return 0;
    struct conn_info ci = {};
    ci.saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    ci.daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    ci.sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    ci.dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
    ci.start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&conn_map, &sk_key, &ci, BPF_ANY);
    // Cache is host-relative; normalized Accept is inbound remote -> local.
    emit_network_event(info.pid, ci.daddr, ci.saddr, ci.dport, ci.sport,
                       PROTO_TCP, NET_OP_TCP_ACCEPT, 0);
    return 0;
}

// Capture TCP send message to emit send events with addresses when possible.
// tcp_sendmsg signature: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    __u64 len = (__u64)PT_REGS_PARM3(ctx);

    // Prefer connection tuple from conn_map (populated by
    // trace_inet_sock_set_state). However, on some kernels the tracepoint
    // argument layout differs enough that saddr/daddr may stay zero. For data
    // quality, fall back to reading from `struct sock`.
    __u64 sk_key = (__u64)sk;
    __u64 now = bpf_ktime_get_ns();
    struct conn_info *ci = bpf_map_lookup_elem(&conn_map, &sk_key);
    if (!ci) {
        struct conn_info tmp = {};
        struct sock *sock = (struct sock *)sk;
        tmp.daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
        tmp.saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
        tmp.dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
        tmp.sport = BPF_CORE_READ(sock, __sk_common.skc_num);
        tmp.start_ns = now;
        tmp.last_send_ns = now;
        bpf_map_update_elem(&conn_map, &sk_key, &tmp, BPF_ANY);
        emit_network_event(pid, tmp.saddr, tmp.daddr, tmp.sport, tmp.dport, PROTO_TCP, NET_OP_TCP_SEND, (__u32)len);
        return 0;
    }

    // Refresh zero tuples from the live socket.
    if (ci->saddr == 0 && ci->daddr == 0) {
        struct sock *sock = (struct sock *)sk;
        ci->daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
        ci->saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
        ci->dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
        ci->sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    }
    const __u64 min_interval_ns = 1ULL * 1000000000ULL; // 1 second
    if (ci->last_send_ns && (now - ci->last_send_ns) < min_interval_ns)
        return 0;
    ci->last_send_ns = now;

    emit_network_event(pid, ci->saddr, ci->daddr, ci->sport, ci->dport, PROTO_TCP, NET_OP_TCP_SEND, (__u32)len);
    return 0;
}

// Capture TCP receive message to emit recv events with addresses when possible.
// tcp_recvmsg signature: ssize_t tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int noblock);
SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    __u64 len = (__u64)PT_REGS_PARM3(ctx);

    __u64 sk_key = (__u64)sk;
    __u64 now = bpf_ktime_get_ns();
    struct conn_info *ci = bpf_map_lookup_elem(&conn_map, &sk_key);
    if (!ci) {
        // For recv, the remote is the source and local is the destination.
        struct conn_info tmp = {};
        struct sock *sock = (struct sock *)sk;
        __u32 daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
        __u32 saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
        __u16 dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
        __u16 sport = BPF_CORE_READ(sock, __sk_common.skc_num);
        tmp.saddr = saddr;
        tmp.daddr = daddr;
        tmp.sport = sport;
        tmp.dport = dport;
        tmp.start_ns = now;
        tmp.last_recv_ns = now;
        bpf_map_update_elem(&conn_map, &sk_key, &tmp, BPF_ANY);
        emit_network_event(pid, daddr, saddr, dport, sport, PROTO_TCP, NET_OP_TCP_RECV, (__u32)len);
        return 0;
    }

    // Refresh zero tuples from the live socket.
    if (ci->saddr == 0 && ci->daddr == 0) {
        struct sock *sock = (struct sock *)sk;
        ci->daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
        ci->saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
        ci->dport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
        ci->sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    }
    const __u64 min_interval_ns = 1ULL * 1000000000ULL; // 1 second
    if (ci->last_recv_ns && (now - ci->last_recv_ns) < min_interval_ns)
        return 0;
    ci->last_recv_ns = now;

    // For recv, swap tuple: remote is the source and local is the destination.
    emit_network_event(pid, ci->daddr, ci->saddr, ci->dport, ci->sport, PROTO_TCP, NET_OP_TCP_RECV, (__u32)len);
    return 0;
}

// Connected UDP sockets commonly use sendmsg/recvmsg (e.g. dig). Emit UDP
// send/recv with best-effort local tuple extraction.
// udp_sendmsg signature: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&udp_sendmsg_ctx_map, &pid_tgid);
    void *sk = (void *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    struct udp_send_context saved = { .sk = (__u64)sk };
    struct sock *sock = (struct sock *)sk;
    if (BPF_CORE_READ(sock, __sk_common.skc_family) != AF_INET)
        return 0;
    saved.peer_addr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    saved.peer_port = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg) return 0;
    void *name = BPF_CORE_READ(msg, msg_name);
    if (name) {
        int namelen = BPF_CORE_READ(msg, msg_namelen);
        struct sockaddr_in peer = {};
        if (namelen < sizeof(peer) || bpf_probe_read_kernel(&peer, sizeof(peer), name) != 0 || peer.sin_family != AF_INET)
            return 0;
        saved.peer_addr = peer.sin_addr.s_addr;
        saved.peer_port = bpf_ntohs(peer.sin_port);
    }
    bpf_map_update_elem(&udp_sendmsg_ctx_map, &pid_tgid, &saved, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int kretprobe__udp_sendmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct udp_send_context *entry = bpf_map_lookup_elem(&udp_sendmsg_ctx_map, &pid_tgid);
    if (!entry) return 0;
    struct udp_send_context saved = *entry;
    bpf_map_delete_elem(&udp_sendmsg_ctx_map, &pid_tgid);
    // udp_sendmsg returns int. arm64 may zero-extend w0; explicitly sign-extend
    // so -EMSGSIZE/-EAGAIN cannot masquerade as a positive byte count.
    long ret = (int)PT_REGS_RC(ctx);
    if (ret < 0 || !pid_allowed(pid_tgid >> 32)) return 0;
    struct sock *sock = (struct sock *)saved.sk;
    __u32 saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    __u16 sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    if (!sport || !saved.peer_port) return 0;
    // Preserve send sampling; failed calls no longer consume it. The local
    // port is now read after autobind, and unconnected peer comes from msg_name.
    __u64 now = bpf_ktime_get_ns();
    const __u64 min_interval_ns = 1ULL * 1000000000ULL;
    struct udp_rate *ur = bpf_map_lookup_elem(&udp_rate_map, &saved.sk);
    if (ur) {
        if (ur->last_send_ns && now - ur->last_send_ns < min_interval_ns) return 0;
        ur->last_send_ns = now;
    } else {
        struct udp_rate initial = { .last_send_ns = now };
        bpf_map_update_elem(&udp_rate_map, &saved.sk, &initial, BPF_ANY);
    }

    // Many local resolvers bind sockets to INADDR_ANY, leaving skc_rcv_saddr=0.
    // For loopback destinations we can safely treat the local IP as 127.0.0.1.
    if (saddr == 0 && ((saved.peer_addr & 0xff) == 0x7f))
        saddr = 0x0100007f;

    emit_network_event(pid_tgid >> 32, saddr, saved.peer_addr, sport, saved.peer_port, PROTO_UDP, NET_OP_UDP_SEND, (__u32)ret);
    return 0;
}

// udp_recvmsg signature: int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int noblock, int *addr_len);
SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&udp_recvmsg_sock_map, &pid_tgid);
    bpf_map_delete_elem(&udp_recvmsg_peer_map, &pid_tgid);
    void *sk = (void *)PT_REGS_PARM1(ctx);
    __u64 msg_ptr = (__u64)PT_REGS_PARM2(ctx);
    if (!sk || !msg_ptr)
        return 0;
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (!pid_allowed(pid))
        return 0;
    __u64 sk_key = (__u64)sk;
    if (bpf_map_update_elem(&udp_recvmsg_sock_map, &pid_tgid, &sk_key, BPF_ANY) != 0 ||
        bpf_map_update_elem(&udp_recvmsg_peer_map, &pid_tgid, &msg_ptr, BPF_ANY) != 0) {
        bpf_map_delete_elem(&udp_recvmsg_sock_map, &pid_tgid);
        bpf_map_delete_elem(&udp_recvmsg_peer_map, &pid_tgid);
    }
    return 0;
}

// One successful-return owner for connected recv and peer-buffer recvfrom/msg.
SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 *sk_keyp = bpf_map_lookup_elem(&udp_recvmsg_sock_map, &pid_tgid);
    __u64 *peer_ptrp = bpf_map_lookup_elem(&udp_recvmsg_peer_map, &pid_tgid);
    __u64 sk_key = sk_keyp ? *sk_keyp : 0;
    __u64 msg_ptr = peer_ptrp ? *peer_ptrp : 0;
    // Copy context then clean on EVERY outcome, including failed reads/filtering.
    bpf_map_delete_elem(&udp_recvmsg_sock_map, &pid_tgid);
    bpf_map_delete_elem(&udp_recvmsg_peer_map, &pid_tgid);
    // udp_recvmsg returns int, including on arm64 where w0 is zero-extended.
    long ret = (int)PT_REGS_RC(ctx);
    if (ret < 0 || !sk_key || !msg_ptr || !pid_allowed(pid))
        return 0; // ret==0 is a legitimate zero-length datagram.

    struct sock *sock = (struct sock *)sk_key;
    if (BPF_CORE_READ(sock, __sk_common.skc_family) != AF_INET)
        return 0;
    __u32 laddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    __u16 lport = BPF_CORE_READ(sock, __sk_common.skc_num);
    __u32 raddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    __u16 rport = bpf_ntohs(BPF_CORE_READ(sock, __sk_common.skc_dport));
    struct msghdr *msg = (struct msghdr *)msg_ptr;
    void *name = BPF_CORE_READ(msg, msg_name);
    if (name) {
        struct sockaddr_in peer = {};
        // inet_recvmsg updates msg_namelen AFTER udp_recvmsg returns. The
        // socket layer supplies kernel sockaddr_storage regardless of the
        // user's address length, so do not reject its still-zero length here.
        if (bpf_probe_read_kernel(&peer, sizeof(peer), name) != 0 ||
            peer.sin_family != AF_INET)
            return 0;
        raddr = peer.sin_addr.s_addr;
        rport = bpf_ntohs(peer.sin_port);
    } else {
        // Preserve connected-receive one-second sampling, but only successful
        // calls consume it. Peer-buffer receives remain unsampled as before.
        __u64 now = bpf_ktime_get_ns();
        const __u64 min_interval_ns = 1ULL * 1000000000ULL;
        struct udp_rate *ur = bpf_map_lookup_elem(&udp_rate_map, &sk_key);
        if (ur) {
            if (ur->last_recv_ns && now - ur->last_recv_ns < min_interval_ns)
                return 0;
            ur->last_recv_ns = now;
        } else {
            struct udp_rate init = { .last_recv_ns = now };
            bpf_map_update_elem(&udp_rate_map, &sk_key, &init, BPF_ANY);
        }
    }
    if (!rport || !lport)
        return 0; // No recoverable peer/socket tuple, not a fabricated port.
    if (laddr == 0 && ((raddr & 0xff) == 0x7f))
        laddr = 0x0100007f;

    emit_network_event(pid, raddr, laddr, rport, lport, PROTO_UDP, NET_OP_UDP_RECV, (__u32)ret);

    return 0;
}

// TCP connect - Outbound connection
struct connect_args {
    unsigned long long unused;
    long syscall_nr;
    int fd;
    struct sockaddr *addr;
    int addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct connect_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct sockaddr_in addr;
    bpf_probe_read_user(&addr, sizeof(addr), ctx->addr);
    
    // Local address is not available at sys_enter_connect time. TCP
    // connection events are emitted from trace_inet_sock_set_state instead.
    // As an additional store path, attempt to lookup the struct sock * for
    // the supplied file descriptor using the bpf helper (if available).
    // This increases the chance we capture the socket pointer in process
    // context and later correlate it in inet_sock_set_state.
    (void)addr;

    int fd = ctx->fd;
    if (fd >= 0)
    {
        // Try to use the sockfd lookup helper. Helper availability varies by
        // kernel version; if the helper is not available this will compile
        // only if provided by the kernel headers used by clang. We wrap the
        // result handling defensively.
#ifdef __BPF_HAVE_SOCKFD_LOOKUP
        void *sk = bpf_sockfd_lookup(fd, AF_INET, 0);
        if (sk) {
            struct sock_info info = {};
            info.pid = pid;
            info.start_ns = bpf_ktime_get_ns();
            __u64 sk_key = (__u64)sk;
            bpf_map_update_elem(&sock_pid_map, &sk_key, &info, BPF_ANY);
            emit_diag_event(0, info.pid, sk);
            diag_inc(0);
        }
#endif

    }

    return 0;
}

// TCP accept - Inbound connection
struct accept_args {
    unsigned long long unused;
    long syscall_nr;
    int fd;
    struct sockaddr *addr;
    int *addrlen;
};

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept(struct accept_args *ctx)
{
    // Peer/local addresses are not available at sys_enter_accept time. TCP
    // Accept is emitted only from successful inet_csk_accept return.
    (void)ctx;
    return 0;
}

// sendto - Send data (TCP/UDP)
struct sendto_args {
    unsigned long long unused;
    long syscall_nr;
    int fd;
    void *buf;
    __u64 len;
    unsigned int flags;
    struct sockaddr *dest_addr;
    int addrlen;
};

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct sendto_args *ctx)
{
    // Core UDP emits once on successful udp_sendmsg return. Syscall entry
    // cannot establish protocol, success or an autobound local port.
    (void)ctx;
    return 0;
}

// recvfrom - Receive data (TCP/UDP)
struct recvfrom_args {
    unsigned long long unused;
    long syscall_nr;
    int fd;
    void *buf;
    __u64 len;
    unsigned int flags;
    struct sockaddr *src_addr;
    int *addrlen;
};

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom(struct recvfrom_args *ctx)
{
    // No user pointer stash or duplicate emission; udp_recvmsg owns the event.
    (void)ctx;
    return 0;
}

struct sys_exit_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_recvfrom_exit(struct sys_exit_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    // Cleanup only if a return hook did not run. Never emit after copying to user.
    (void)ctx;
    bpf_map_delete_elem(&udp_recvmsg_peer_map, &pid_tgid);
    bpf_map_delete_elem(&udp_recvmsg_sock_map, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
