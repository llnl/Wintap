# eBPF Network Sensor Milestone (PID Attribution + TCP Send/Recv + UDP Recv)

## Summary

This milestone started as a PID attribution hardening pass for the Linux eBPF network sensor and expanded into end-to-end TCP send/recv event coverage plus a correctness fix for UDP receive events.

### What I implemented and why

- Fixed pointer-keying portability in the tracer:
  - Changed `sock_pid_map` key from `void *` to `__u64` so the socket-pointer value is stored as an explicit 64-bit integer. This avoids ABI/typing mismatches when passing pointer keys across kprobe/tracepoint contexts.
  - File modified: `wintap/platform/linux/sensor/ebpf/tracers/network_ops_tracer.bpf.c`

- Improved in-kernel diagnostics to be more robust:
  - Changed `diag_counters` from `BPF_MAP_TYPE_ARRAY` -> `BPF_MAP_TYPE_PERCPU_ARRAY`.
  - Kept ringbuffer-based in-band diagnostic events (protocol = 0xFF) — these are reliable and are consumed by userland.

- Made the userland diagnostic reader more tolerant of map formats:
  - `BaseEbpfSensor.StartDiagMonitor` now parses both single-value and per-CPU multi-value map dumps (sums per-CPU values).

- Added userland aggregation of ringbuffer diagnostic events:
  - `NetworkSensor` keeps local counters for diag events (STORE/HIT/MISS) and logs aggregated values on a 10s interval.

- Attempted to ensure the kprobe/kretprobe programs attach:
  - `NetworkSensor` explicitly tries to attach `kprobe__tcp_v4_connect`, `kprobe__tcp_v6_connect`, `kprobe__tcp_connect`, `kretprobe__inet_csk_accept` in addition to `trace_sendto`/`trace_recvfrom`.

- Added TCP send/recv coverage:
  - Added eBPF kprobes `kprobe/tcp_sendmsg` and `kprobe/tcp_recvmsg` to emit `TcpIpSend` and `TcpIpRecv` activity.
  - Avoided direct reads from `struct sock` fields (incomplete type in this build environment) by storing the 4-tuple in a `conn_map` from `tracepoint/sock/inet_sock_set_state` and looking it up from the send/recv probes.
  - Updated `NetworkSensor` to explicitly attach `kprobe__tcp_sendmsg` and `kprobe__tcp_recvmsg`.

- Prevented event floods (OOM mitigation):
  - Initial tcp_sendmsg/tcp_recvmsg emission volume can be extremely high and caused the `dotnet` process to be OOM-killed.
  - Added a simple per-socket rate limit (1 event/sec/socket) using timestamps stored in `conn_map` (`last_send_ns`, `last_recv_ns`).

- Fixed UDP receive correctness:
  - `sys_enter_recvfrom` cannot reliably read `src_addr` because the kernel writes it on syscall return.
  - Implemented a `sys_enter_recvfrom` stash + `sys_exit_recvfrom` emit path using a small `recvfrom_ctx_map` keyed by `pid_tgid`.
  - Added a new BPF program `trace_recvfrom_exit` and updated `NetworkSensor` to attach it.


## Build/run/test performed

- Rebuilt the eBPF tracer (`network_ops_tracer.bpf.o`) and the .NET Lintap runtime several times while iterating.
- Launched Lintap with direct parquet enabled (and selectively enabling only Network sensor during validation runs).
- Validated network parquet output under `/var/log/lintap/data/raw_sensor/*`.

### Testcases used

- Loopback TCP + UDP generator (Python):
  - TCP: multiple connects + send/recv to a local listener.
  - UDP: datagrams and responses to a local listener.
  - Used to validate `TcpIpConnect/Accept/Disconnect` plus new `TcpIpSend/TcpIpRecv` events.

- DNS UDP testcase:
  - Confirmed that `dig` uses `sendmsg/recvmsg` (not `sendto/recvfrom`) when sockets are connected.
  - Used a small Python UDP DNS query against the local stub resolver (`127.0.0.53:53`) using `sendto/recvfrom` to validate `UdpIpSend` and `UdpIpRecv` events.

- Optional syscall visibility check:
  - Used `strace` to confirm which syscalls a particular DNS tool uses (`sendmsg/recvmsg` vs `sendto/recvfrom`).


## Key runtime outcomes and diagnostics

- The tracer emits in-band diagnostic events to the ringbuffer (protocol 0xFF) with op codes:
  - 0 = STORE (kprobe/store)
  - 1 = HIT (lookup found)
  - 2 = MISS (lookup absent or fallback)

- `NetworkSensor` aggregates these into periodic log lines, for example:
  - `NetworkSensor aggregated BPF diag (STORE/HIT/MISS) = 18/9/9`

- After adding an additional store path (sys_enter_connect lookup when helper available) and making kprobe attachments explicit, STORE/HIT counts increased. The last runs observed aggregated counts such as 18 stores, 9 hits, 9 misses under smoke-test traffic.

- Parquet capture validated: outbound TCP connection rows were written and matched test endpoints (smoke test passed).

- End-to-end TCP send/recv validated:
  - `tcpconnection` parquet now shows `ActivityType` values including `TcpIpSend` and `TcpIpRecv` (in addition to `TcpIpConnect`, `TcpIpAccept`, `TcpIpDisconnect`).

- UDP receive validated:
  - `udppacket` parquet now shows `UdpIpRecv` in addition to `UdpIpSend` when using a `sendto/recvfrom` style UDP client (DNS UDP query).


## Remaining issues and observations

- Some MISS events and pid==0 MISSes remain (expected when `inet_sock_set_state` runs in softirq / non-process context with no prior store).
- `bpftool` map dumps sometimes show zeros for the `diag_counters` map even when ringbuffer diag events exist. Ringbuffer-based diagnostics are therefore the most reliable signal.
- `CloneProcess` attach sometimes fails in this environment; existing error logging remains.

- UDP local tuple fields are still incomplete:
  - Current eBPF UDP events emitted from `trace_sendto`/`trace_recvfrom_exit` do not populate the local address/port (source for send, destination for recv). This shows up as `0.0.0.0:0` in parquet.
  - The DNS testcase confirms send/recv events exist, but the local tuple capture needs improvement.

  - Detailed note: `diagnostics/udp_local_tuple_0_0_0_0_notes.md`

- DNS tooling differences matter:
  - Many DNS tools use connected UDP sockets and `sendmsg/recvmsg`, which are not yet traced for UDP in this sensor.
  - The `sendto/recvfrom` path now works reliably (post-fix).


## Next recommended actions

1. Fix UDP local tuple capture:
   - For `UdpIpSend`: capture and emit the local bound port/address for the sending socket.
   - For `UdpIpRecv`: capture the local destination port/address (the socket’s local tuple).
   - Likely requires correlating `fd -> socket` (or `sock -> local tuple`) for UDP, similar in spirit to the TCP `conn_map` approach.

2. Add UDP `sendmsg/recvmsg` coverage:
   - DNS tools often use connected UDP sockets; add hooks for UDP message send/recv paths so DNS lookups via `dig` are captured without requiring a bespoke `sendto/recvfrom` client.

3. Keep TCP send/recv rate limiting configurable:
   - Current 1Hz/socket is sufficient to validate behavior and avoid OOM.
   - Consider a tunable interval or byte aggregation strategy if higher fidelity is needed.

4. Keep diagnostics:
   - Continue emitting in-band ringbuffer diagnostics (0xFF protocol) and userland aggregation.
   - Prefer ringbuffer diagnostics as the source of truth when `bpftool` map dumps are ambiguous.


## Files changed

- wintap/platform/linux/sensor/ebpf/tracers/network_ops_tracer.bpf.c
- wintap/platform/linux/sensor/shared/BaseEbpfSensor.cs
- wintap/platform/linux/sensor/ebpf/NetworkSensor.cs


## Status

- Lintap is running with updated tracer and diagnostics.
- Parquet captures occur and smoke tests pass.
- In-band diagnostics and userland aggregation provide actionable telemetry to iterate further.

- TCP send/recv is now captured end-to-end (with rate limiting).
- UDP recv is now captured correctly for `sendto/recvfrom` callers (via `sys_exit_recvfrom`).
- Remaining gap: UDP local tuple fields are still `0.0.0.0:0` and UDP `sendmsg/recvmsg` is not yet covered.
