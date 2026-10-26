#!/usr/bin/env python3
"""Lintap network sensor validation using tcpdump as ground truth.

This tool runs tcpdump in parallel with a traffic generation phase, then
compares tcpdump-observed 5-tuples and byte metrics against what Lintap wrote
to parquet.

Notes/limitations:
- tcpdump counts packets on the wire; Lintap currently records per-syscall
  send/recv sizes (payload lengths), so packet counts will not match exactly.
- Comparison is done using an undirected 5-tuple (endpoints sorted) to reduce
  sensitivity to direction/modeling differences.

Typical usage (Lintap already running and writing parquet):
  sudo python3 devtools/network_tcpdump_validation.py --data-root /var/log/lintap/data
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


DEFAULT_ENDPOINTS = [
    "http://example.com/",
    "https://example.com/",
]

DEFAULT_UDP_TARGETS = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
]


def default_data_root() -> Path:
    env_root = os.environ.get("WINTAP_DATA_ROOT")
    if env_root:
        return Path(env_root)
    return Path("/var/log/lintap/data")


def check_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("This tool needs root (tcpdump + eBPF environments): run with sudo.")


def start_lintap(dll: Path, data_root: Path, capture_pid: int, log_path: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "WINTAP_DATA_ROOT": str(data_root),
            "WINTAP_DISABLE_MCP": "true",
            "WINTAP_DISABLE_DUCKDB_UI": "true",
            "WINTAP_DISABLE_ETL": "false",
            "WINTAP_DISABLE_SENSORS": "false",
            "WINTAP_ENABLE_DIRECT_PARQUET": "true",
            "WINTAP_DIRECT_PARQUET_FLUSH_SECONDS": "2",
            # Only Network sensor
            "WINTAP_ENABLE_EXECVE_SENSOR": "false",
            "WINTAP_ENABLE_CLONE_SENSOR": "false",
            "WINTAP_ENABLE_EXIT_SENSOR": "false",
            "WINTAP_ENABLE_FILEOPS_SENSOR": "false",
            "WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR": "false",
            "WINTAP_ENABLE_NETWORK_SENSOR": "true",
            # Reduce event volume to the validation process only
            "WINTAP_NETWORK_CAPTURE_PID": str(capture_pid),
        }
    )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(log_path, "w", encoding="utf-8")
    return subprocess.Popen(["dotnet", str(dll)], env=env, stdout=f, stderr=subprocess.STDOUT, text=True)


def stop_lintap(proc: subprocess.Popen) -> None:
    try:
        import signal

        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
        return
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def resolve_ipv4(host: str, port: int) -> set[str]:
    ips: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    return ips


def parse_endpoint(url: str) -> tuple[str, int]:
    # minimal parse to avoid pulling in urllib.parse
    if "://" not in url:
        raise ValueError(f"endpoint must include scheme: {url}")
    scheme, rest = url.split("://", 1)
    host_port = rest.split("/", 1)[0]
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        return host, int(port_s)
    return host_port, (443 if scheme.lower() == "https" else 80)


def generate_http_traffic(endpoints: list[str], rounds: int, request_timeout: int) -> None:
    ctx = ssl.create_default_context()
    for r in range(rounds):
        print(f"http traffic round {r + 1}/{rounds}")
        for url in endpoints:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "lintap-tcpdump-validation/1.0", "Cache-Control": "no-cache"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=request_timeout, context=ctx) as resp:
                    resp.read(512)
                print(f"  OK  {url}")
            except urllib.error.HTTPError as exc:
                # still indicates a valid TCP/TLS connection
                print(f"  OK  {url} (HTTP {exc.code})")
            except Exception as exc:  # noqa: BLE001
                print(f"  ERR {url}: {exc}")


def generate_udp_traffic(targets: list[tuple[str, int]], rounds: int, timeout: int) -> None:
    for r in range(rounds):
        print(f"udp traffic round {r + 1}/{rounds}")
        for ip, port in targets:
            ok = False
            err: str | None = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(b"lintap-tcpdump-validation", (ip, port))
                ok = True
            except Exception as ex:  # noqa: BLE001
                err = str(ex)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            print(f"  UDP -> {ip}:{port} ok={ok} err={err or ''}")


@dataclass(frozen=True)
class FlowKey:
    proto: str  # "TCP" or "UDP"
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int

    @staticmethod
    def from_endpoints(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> "FlowKey":
        left = (src_ip, src_port)
        right = (dst_ip, dst_port)
        if left <= right:
            a_ip, a_port = left
            b_ip, b_port = right
        else:
            a_ip, a_port = right
            b_ip, b_port = left
        return FlowKey(proto=proto, a_ip=a_ip, a_port=a_port, b_ip=b_ip, b_port=b_port)


@dataclass
class Metrics:
    packets: int = 0
    bytes: int = 0

    def add(self, packets: int, bytes_: int) -> None:
        self.packets += packets
        self.bytes += bytes_


# tcpdump text output differs by linktype/interface; for `-i any` it often
# includes an interface name and direction before the `IP` token.
TCPDUMP_LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+"
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+"
    r"(?P<rest>.*)$"
)


def parse_tcpdump_text(path: Path, start_epoch: float, end_epoch: float) -> dict[FlowKey, Metrics]:
    out: dict[FlowKey, Metrics] = {}
    for line in path.read_text(errors="replace").splitlines():
        if not line or line.startswith("tcpdump:"):
            continue

        m = TCPDUMP_LINE_RE.match(line)
        if not m:
            continue

        try:
            ts = float(m.group("ts"))
        except Exception:
            continue

        if ts < start_epoch - 1 or ts > end_epoch + 1:
            continue

        src_ip = m.group("src_ip")
        dst_ip = m.group("dst_ip")
        src_port = int(m.group("src_port"))
        dst_port = int(m.group("dst_port"))
        rest = m.group("rest")

        proto = "UDP" if "UDP" in rest.upper() else "TCP"
        # payload length (best effort). For UDP tcpdump prints `UDP, length N`.
        # For TCP with -q we often get `tcp N` where N is payload bytes.
        bytes_ = 0
        lm = re.search(r"\blength\s+(\d+)\b", rest, flags=re.IGNORECASE)
        if lm:
            bytes_ = int(lm.group(1))
        else:
            tm = re.search(r"\btcp\s+(\d+)\b", rest, flags=re.IGNORECASE)
            if tm:
                bytes_ = int(tm.group(1))

        key = FlowKey.from_endpoints(proto, src_ip, src_port, dst_ip, dst_port)
        out.setdefault(key, Metrics()).add(1, bytes_)

    return out


def run_tcpdump(output_path: Path, iface: str, bpf_filter: str) -> subprocess.Popen:
    cmd = [
        "tcpdump",
        "-i",
        iface,
        "-nn",
        "-tt",
        "-q",
        "-l",
        "-s",
        "0",
        bpf_filter,
    ]
    # tcpdump writes to stdout, we capture in a file.
    f = open(output_path, "w", encoding="utf-8")
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)


def stop_process(proc: subprocess.Popen, timeout_s: int = 5) -> None:
    try:
        import signal

        proc.send_signal(signal.SIGINT)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            return
    try:
        proc.wait(timeout=timeout_s)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def duckdb_json(sql: str) -> list[dict]:
    proc = subprocess.run(["duckdb", "-json", "-c", sql], check=True, text=True, capture_output=True)
    out = proc.stdout.strip()
    if not out:
        return []
    import json

    return json.loads(out)


def collect_lintap_metrics(data_root: Path, start_epoch: float, end_epoch: float) -> dict[FlowKey, Metrics]:
    parquet_root = data_root / "raw_sensor"
    tcp_glob = str((parquet_root / "tcpconnection" / "*.parquet").as_posix())
    udp_glob = str((parquet_root / "udppacket" / "*.parquet").as_posix())
    start_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(start_epoch - 2))
    end_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(end_epoch + 2))

    # Only compare send/recv-like rows where PacketSize is meaningful.
    tcp_sql = f"""
    SELECT
      'TCP' AS proto,
      TcpConnection_SourceAddress AS src_ip,
      CAST(TcpConnection_SourcePort AS INTEGER) AS src_port,
      TcpConnection_DestinationAddress AS dst_ip,
      CAST(TcpConnection_DestinationPort AS INTEGER) AS dst_port,
      CAST(TcpConnection_PacketSize AS BIGINT) AS bytes
    FROM read_parquet('{tcp_glob}', union_by_name=true)
    WHERE CapturedUtc BETWEEN TIMESTAMP '{start_iso}' AND TIMESTAMP '{end_iso}'
      AND ActivityType IN ('TcpIpSend', 'TcpIpRecv')
    """

    udp_sql = f"""
    SELECT
      'UDP' AS proto,
      UdpPacket_SourceAddress AS src_ip,
      CAST(UdpPacket_SourcePort AS INTEGER) AS src_port,
      UdpPacket_DestinationAddress AS dst_ip,
      CAST(UdpPacket_DestinationPort AS INTEGER) AS dst_port,
      CAST(UdpPacket_PacketSize AS BIGINT) AS bytes
    FROM read_parquet('{udp_glob}', union_by_name=true)
    WHERE CapturedUtc BETWEEN TIMESTAMP '{start_iso}' AND TIMESTAMP '{end_iso}'
      AND ActivityType IN ('UdpIpSend', 'UdpIpRecv')
    """

    out: dict[FlowKey, Metrics] = {}
    for sql in (tcp_sql, udp_sql):
        try:
            rows = duckdb_json(sql)
        except Exception:
            continue
        for r in rows:
            proto = r.get("proto")
            src_ip = r.get("src_ip")
            dst_ip = r.get("dst_ip")
            if not proto or not src_ip or not dst_ip:
                continue
            try:
                src_port = int(r.get("src_port") or 0)
                dst_port = int(r.get("dst_port") or 0)
                bytes_ = int(r.get("bytes") or 0)
            except Exception:
                continue
            key = FlowKey.from_endpoints(str(proto), str(src_ip), src_port, str(dst_ip), dst_port)
            out.setdefault(key, Metrics()).add(1, bytes_)
    return out


def print_top(title: str, items: list[tuple[FlowKey, Metrics, Metrics]], limit: int = 20) -> None:
    print(f"\n{title}:")
    if not items:
        print("  <none>")
        return
    for fk, tdm, ltm in items[:limit]:
        print(
            f"  {fk.proto} {fk.a_ip}:{fk.a_port} <-> {fk.b_ip}:{fk.b_port}"
            f"  tcpdump pkts={tdm.packets} bytes={tdm.bytes}"
            f"  lintap evts={ltm.packets} bytes={ltm.bytes}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Lintap network capture vs tcpdump")
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--iface", default="any", help="tcpdump interface (default: any)")
    parser.add_argument("--tcpdump-filter", default="tcp or udp", help="tcpdump BPF filter")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--endpoint", action="append", dest="endpoints")
    parser.add_argument("--udp-target", action="append", dest="udp_targets", help="UDP target as ip:port")
    parser.add_argument("--parquet-wait", type=int, default=70, help="Seconds to wait for parquet flush")
    parser.add_argument(
        "--no-focus",
        action="store_true",
        help="Do not filter results to expected endpoints/UDP targets",
    )
    parser.add_argument(
        "--start-lintap",
        action="store_true",
        help="Start/stop Lintap automatically (recommended for repeatable runs)",
    )
    parser.add_argument(
        "--lintap-dll",
        type=Path,
        default=Path("/tmp/lintap-build/wintap/bin/Debug/net10.0/Lintap.dll"),
        help="Path to Lintap.dll when using --start-lintap",
    )
    parser.add_argument(
        "--clean-data",
        action="store_true",
        help="Delete existing raw_sensor and runtime Logs/event_store/diag before running",
    )
    args = parser.parse_args()

    check_root()

    lintap_proc: subprocess.Popen | None = None
    if args.clean_data:
        runtime_root = Path(os.environ.get("WINTAP_RUNTIME_ROOT", str(args.data_root.parent / "runtime")))
        for p in (
            args.data_root / "raw_sensor",
            runtime_root / "Logs",
            runtime_root / "event_store",
            runtime_root / "diag",
            runtime_root / "esper_staging",
        ):
            try:
                if p.exists():
                    for child in p.iterdir():
                        if child.is_dir():
                            subprocess.run(["rm", "-rf", str(child)], check=False)
                        else:
                            child.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass

    if args.start_lintap:
        if not args.lintap_dll.exists():
            raise SystemExit(f"Lintap DLL not found: {args.lintap_dll}")
        lintap_log = Path(f"/tmp/lintap_tcpdump_validation_lintap_{int(time.time())}.log")
        lintap_proc = start_lintap(args.lintap_dll, args.data_root, os.getpid(), lintap_log)
        print(f"started Lintap pid={lintap_proc.pid} log={lintap_log}")
        # Lintap performs async startup and then attaches sensors.
        # Give it enough time to get to NetworkSensor.Start.
        time.sleep(20)

    endpoints = args.endpoints or DEFAULT_ENDPOINTS
    udp_targets = list(DEFAULT_UDP_TARGETS)
    if args.udp_targets:
        udp_targets = []
        for t in args.udp_targets:
            ip, port_s = t.rsplit(":", 1)
            udp_targets.append((ip, int(port_s)))

    # Resolve endpoints to show context (and help construct a filter if desired).
    resolved = []
    expected_tcp_endpoints: set[tuple[str, int]] = set()
    for url in endpoints:
        host, port = parse_endpoint(url)
        ips = sorted(resolve_ipv4(host, port))
        resolved.append((url, host, port, ips))
        for ip in ips:
            expected_tcp_endpoints.add((ip, port))

    expected_udp_endpoints: set[tuple[str, int]] = set(udp_targets)

    print(f"data root: {args.data_root}")
    print(f"tcpdump iface: {args.iface}")
    print(f"tcpdump filter: {args.tcpdump_filter}")
    print("resolved endpoints:")
    for url, host, port, ips in resolved:
        print(f"  {url} -> {host}:{port} ipv4={ips or ['<none>']}")
    print(f"udp targets: {udp_targets}")

    capture_path = Path(f"/tmp/lintap_tcpdump_{int(time.time())}.log")
    start_epoch = time.time()
    proc = run_tcpdump(capture_path, args.iface, args.tcpdump_filter)

    try:
        generate_http_traffic(endpoints, args.rounds, args.request_timeout)
        generate_udp_traffic(udp_targets, args.rounds, args.request_timeout)
    finally:
        end_epoch = time.time()
        stop_process(proc)

    print(f"tcpdump log: {capture_path}")
    print(f"waiting {args.parquet_wait}s for parquet flush...")
    time.sleep(args.parquet_wait)

    tcpdump_metrics = parse_tcpdump_text(capture_path, start_epoch, end_epoch)
    lintap_metrics = collect_lintap_metrics(args.data_root, start_epoch, end_epoch)

    if not args.no_focus:
        def keep_key(k: FlowKey) -> bool:
            if k.proto == "TCP":
                return (k.a_ip, k.a_port) in expected_tcp_endpoints or (k.b_ip, k.b_port) in expected_tcp_endpoints
            if k.proto == "UDP":
                return (k.a_ip, k.a_port) in expected_udp_endpoints or (k.b_ip, k.b_port) in expected_udp_endpoints
            return False

        tcpdump_metrics = {k: v for k, v in tcpdump_metrics.items() if keep_key(k)}
        lintap_metrics = {k: v for k, v in lintap_metrics.items() if keep_key(k)}

    all_keys = set(tcpdump_metrics.keys()) | set(lintap_metrics.keys())
    missing = []
    extra = []
    diffs = []
    for k in all_keys:
        tdm = tcpdump_metrics.get(k, Metrics())
        ltm = lintap_metrics.get(k, Metrics())
        if tdm.packets > 0 and ltm.packets == 0:
            missing.append((k, tdm, ltm))
        elif tdm.packets == 0 and ltm.packets > 0:
            extra.append((k, tdm, ltm))
        else:
            # sort by absolute byte delta
            diffs.append((k, tdm, ltm))

    missing.sort(key=lambda x: (x[1].bytes, x[1].packets), reverse=True)
    extra.sort(key=lambda x: (x[2].bytes, x[2].packets), reverse=True)
    diffs.sort(key=lambda x: abs(x[1].bytes - x[2].bytes), reverse=True)

    print_top("tcpdump present, lintap missing (undirected 5-tuple)", missing)
    print_top("lintap present, tcpdump missing (undirected 5-tuple)", extra)
    print_top("largest byte deltas (tuples present in both)", diffs)

    # Totals
    def totals(m: dict[FlowKey, Metrics], proto: str) -> Metrics:
        t = Metrics()
        for k, v in m.items():
            if k.proto == proto:
                t.add(v.packets, v.bytes)
        return t

    for proto in ("TCP", "UDP"):
        tdm = totals(tcpdump_metrics, proto)
        ltm = totals(lintap_metrics, proto)
        print(f"\nTOTAL {proto}: tcpdump pkts={tdm.packets} bytes={tdm.bytes} | lintap evts={ltm.packets} bytes={ltm.bytes}")

    print("\nDone.")

    if lintap_proc is not None:
        stop_lintap(lintap_proc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
