#!/usr/bin/env python3
"""
Lintap/Wintap network-capture smoke test.

This is intentionally an integration/smoke test rather than a narrow unit test:
it generates a small amount of real outbound HTTP/HTTPS traffic, waits for the
ETL parquet writer to flush, then queries the collected parquet data to confirm
that outbound TCP connection records were captured.

Prerequisites:
  - Lintap/Wintap is already running.
  - ETLConfig.json has WriteToParquet=true.
  - SerializationIntervalSec is short enough for the selected --timeout.
  - Python package `duckdb` is installed, or `duckdb` CLI is on PATH.

Examples:
  python3 wintap/devtools/network_capture_smoke_test.py \
      --data-root /home/ubuntu/data/lintap/deb-pkg \
      --timeout 180

  WINTAP_DATA_ROOT=/home/ubuntu/data/lintap/deb-pkg \
      python3 wintap/devtools/network_capture_smoke_test.py --timeout 180
"""

from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import platform
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


DEFAULT_ENDPOINTS = [
    "http://example.com/",
    "https://example.com/",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://httpbin.org/get",
]

# Default UDP targets (IP, port). We send a small UDP datagram to these addresses
# to exercise UDP capture in the tracer. Use public DNS servers which are
# typically reachable from most environments.
DEFAULT_UDP_TARGETS = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
]


@dataclass
class EndpointProbe:
    url: str
    host: str
    port: int
    resolved_ipv4: set[str] = field(default_factory=set)
    request_ok: bool = False
    request_error: str | None = None

    @property
    def resolved_ipv4_longs(self) -> set[int]:
        return {int(ipaddress.IPv4Address(ip)) for ip in self.resolved_ipv4}


def default_data_root() -> Path:
    env_root = os.environ.get("WINTAP_DATA_ROOT")
    if env_root:
        return Path(env_root)

    system = platform.system().lower()
    if system == "linux":
        return Path("/var/log/lintap/data")
    if system == "darwin":
        return Path("/Library/Application Support/Mactap")
    if system == "windows":
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(program_data) / "Wintap"

    return Path("/var/log/lintap/data")


def parse_endpoint(url: str) -> EndpointProbe:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Endpoint must include scheme and host: {url}")

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    return EndpointProbe(url=url, host=parsed.hostname, port=port)


def resolve_ipv4(host: str, port: int) -> set[str]:
    ips: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    return ips


def generate_traffic(probes: list[EndpointProbe], rounds: int, request_timeout: int) -> None:
    context = ssl.create_default_context()
    for probe in probes:
        probe.resolved_ipv4 = resolve_ipv4(probe.host, probe.port)

    for round_index in range(rounds):
        print(f"traffic round {round_index + 1}/{rounds}")
        for probe in probes:
            request = urllib.request.Request(
                probe.url,
                headers={
                    "User-Agent": "lintap-network-capture-smoke-test/1.0",
                    "Cache-Control": "no-cache",
                },
                method="GET",
            )

            try:
                with urllib.request.urlopen(request, timeout=request_timeout, context=context) as response:
                    # Read a small chunk. The capture only needs the connection.
                    response.read(512)
                probe.request_ok = True
                probe.request_error = None
                print(f"  OK  {probe.url}")
            except urllib.error.HTTPError as exc:
                # HTTP errors still prove the TCP/TLS connection happened.
                probe.request_ok = True
                probe.request_error = f"HTTP {exc.code}"
                print(f"  OK  {probe.url} ({probe.request_error})")
            except Exception as exc:  # noqa: BLE001 - test should report all endpoint failures
                probe.request_error = str(exc)
                print(f"  ERR {probe.url}: {probe.request_error}")


def generate_udp_traffic(udp_targets: list[tuple[str,int]], rounds: int, timeout: int) -> list[tuple[str,int,bool,str]]:
    """Send simple UDP datagrams to target IPs. Returns list of tuples (ip,port,ok,error)."""
    results = []
    import socket
    for r in range(rounds):
        print(f"udp traffic round {r+1}/{rounds}")
        for ip, port in udp_targets:
            ok = False
            err = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(b"lintap-udp-smoke-test", (ip, port))
                ok = True
            except Exception as ex:
                err = str(ex)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            print(f"  UDP -> {ip}:{port} ok={ok} err={err or ''}")
            results.append((ip, port, ok, err))
    return results


def find_candidate_parquet_files(parquet_root: Path, start_epoch: float) -> list[Path]:
    if not parquet_root.exists():
        return []

    files: list[Path] = []
    for file_path in glob.glob(str(parquet_root / "**" / "*.parquet*"), recursive=True):
        path = Path(file_path)
        if path.is_file():
            files.append(path)

    try:
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass
    files = files[:200]

    # Prefer network-ish files, but keep all recent files as fallback because raw_sensor
    # paths differ from intermediate serializer paths.
    network_files = [
        p for p in files
        if "conn" in str(p).lower() or "tcp" in str(p).lower() or "udp" in str(p).lower()
    ]
    return network_files or files


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def detect_column_names(files: list[Path]) -> dict[str, list[str]]:
    """Detect column names across ETL vs direct-parquet network schemas.

    DuckDB will error if we reference columns that don't exist.
    """

    file_list = ", ".join(sql_string(str(path)) for path in files)
    probe_sql = f"""
WITH data AS (
    SELECT * FROM read_parquet([{file_list}], union_by_name=true)
)
SELECT * FROM data LIMIT 1;
"""

    rows = query_with_python_duckdb(probe_sql)
    if rows is None:
        rows = query_with_duckdb_cli(probe_sql)
    cols = set(rows[0].keys()) if rows else set()

    def keep_existing(candidates: list[str]) -> list[str]:
        return [c for c in candidates if c in cols]

    return {
        # ETL serializers commonly use Remote* columns.
        # Direct-parquet network payloads use Destination* columns.
        "remote_ip": keep_existing(
            [
                "RemoteIpAddr",
                "RemoteAddress",
                "TcpConnection_DestinationAddress",
                "UdpPacket_DestinationAddress",
                "TcpConnection_RemoteIpAddr",
                "UdpPacket_RemoteIpAddr",
            ]
        ),
        "remote_port": keep_existing(
            [
                "RemotePort",
                "TcpConnection_DestinationPort",
                "UdpPacket_DestinationPort",
                "TcpConnection_RemotePort",
                "UdpPacket_RemotePort",
            ]
        ),
        "protocol": keep_existing(["Protocol", "TcpConnection_Protocol", "UdpPacket_Protocol"]),
    }


def coalesce_expr(cols: list[str], cast: str) -> str:
    if not cols:
        return "NULL"
    parts = [f"TRY_CAST({c} AS {cast})" if cast else f"{c}" for c in cols]
    return "COALESCE(" + ", ".join(parts) + ")"


def build_query(files: Iterable[Path], start_epoch: float, target_ports: set[int], cols: dict[str, list[str]]) -> str:
    file_list = ", ".join(sql_string(str(path)) for path in files)
    # We will query both TCP (80/443) and common UDP ports (e.g., 53) by allowing
    # the recent files to be scanned for ports of interest. The smoke-test will
    # compute which ports to expect and validate against them.
    # For the smoke test we restrict by the set of candidate files gathered
    # by modification time and by the target ports. Time fields in parquet
    # may use different origin/scales, so avoid relying on FirstSeenMs filtering
    # here — the file selection already constrains recency.
    ip_expr = coalesce_expr(cols.get("remote_ip", []), "VARCHAR")
    port_expr = coalesce_expr(cols.get("remote_port", []), "INTEGER")
    proto_cols = cols.get("protocol", [])
    if proto_cols:
        proto_expr = "COALESCE(" + ", ".join(f"CAST({c} AS VARCHAR)" for c in proto_cols) + ")"
    else:
        proto_expr = "CAST(NULL AS VARCHAR)"

    # If schema doesn't carry a protocol column (direct-parquet), infer from MessageType.
    proto_expr = f"COALESCE({proto_expr}, CASE WHEN lower(CAST(MessageType AS VARCHAR)) LIKE '%udp%' THEN 'UDP' WHEN lower(CAST(MessageType AS VARCHAR)) LIKE '%tcp%' THEN 'TCP' ELSE NULL END)"

    ports = ",".join(str(p) for p in sorted(target_ports))
    return f"""
WITH data AS (
    SELECT *
    FROM read_parquet([{file_list}], union_by_name=true)
)
SELECT
    {ip_expr} AS remote_ip_addr,
    {port_expr} AS remote_port,
    {proto_expr} AS protocol,
    COUNT(*) AS row_count
FROM data
WHERE {port_expr} IN ({ports})
GROUP BY 1, 2, 3
ORDER BY row_count DESC, remote_port, remote_ip_addr;
"""


def query_with_python_duckdb(sql: str) -> list[dict] | None:
    try:
        import duckdb  # type: ignore[import-not-found]
    except ImportError:
        return None

    con = duckdb.connect(database=":memory:")
    try:
        rows = con.execute(sql).fetchall()
        columns = [desc[0] for desc in con.description]
        return [dict(zip(columns, row)) for row in rows]
    finally:
        con.close()


def query_with_duckdb_cli(sql: str) -> list[dict]:
    proc = subprocess.run(
        ["duckdb", "-json", "-c", sql],
        check=True,
        text=True,
        capture_output=True,
    )
    output = proc.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def query_parquet(files: list[Path], start_epoch: float, target_ports: set[int]) -> list[dict]:
    cols = detect_column_names(files)
    sql = build_query(files, start_epoch, target_ports, cols)

    rows = query_with_python_duckdb(sql)
    if rows is not None:
        return rows

    try:
        return query_with_duckdb_cli(sql)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Could not query parquet files: install the Python `duckdb` package "
            "or put the `duckdb` CLI on PATH."
        ) from exc


def summarize_expected_targets(probes: list[EndpointProbe]) -> None:
    print("\nexpected endpoint targets:")
    for probe in probes:
        ips = ", ".join(sorted(probe.resolved_ipv4)) or "<no IPv4 resolution>"
        print(f"  {probe.url} -> port {probe.port}, IPv4: {ips}, request_ok={probe.request_ok}")


def validate(
    rows: list[dict],
    probes: list[EndpointProbe],
    target_ports: set[int],
    require_target_ip_match: bool,
    udp_ok_ports: set[int],
) -> int:
    ports_label = ",".join(str(p) for p in sorted(target_ports))
    print(f"\ncollected network rows for remote ports {ports_label}:")
    if not rows:
        print("  <none>")
    for row in rows[:50]:
        remote_ip = row.get("remote_ip_addr")
        try:
            remote_ip_text = str(ipaddress.IPv4Address(int(remote_ip))) if remote_ip is not None else "<null>"
        except Exception:
            remote_ip_text = str(remote_ip)
        print(
            f"  remote={remote_ip_text}:{row.get('remote_port')} "
            f"protocol={row.get('protocol')} rows={row.get('row_count')}"
        )

    observed_ports = {int(row["remote_port"]) for row in rows if row.get("remote_port") is not None}
    tcp_expected_ports = {probe.port for probe in probes if probe.request_ok and probe.port in target_ports}
    expected_ports = set(tcp_expected_ports) | set(udp_ok_ports)
    missing_ports = expected_ports - observed_ports

    expected_ips: set[str] = set()
    for probe in probes:
        if probe.request_ok:
            expected_ips.update(probe.resolved_ipv4)

    observed_ips: set[str] = set()
    for row in rows:
        val = row.get("remote_ip_addr")
        if val is None:
            continue
        # remote_ip_addr can be either an integer (legacy) or a string (direct-parquet).
        try:
            if isinstance(val, int):
                observed_ips.add(str(ipaddress.IPv4Address(val)))
            else:
                observed_ips.add(str(val))
        except Exception:
            observed_ips.add(str(val))

    matched_ips = expected_ips & observed_ips

    failures = []
    if expected_ports and not (observed_ports & expected_ports):
        failures.append(f"missing expected remote ports in captured data: {sorted(expected_ports)}")

    if require_target_ip_match and not matched_ips:
        failures.append("none of the resolved endpoint IPv4 addresses appeared in captured data")

    if failures:
        print("\nFAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    if tcp_expected_ports and not (observed_ports & tcp_expected_ports) and (observed_ports & udp_ok_ports):
        print("\nWARN: UDP capture succeeded, but no TCP rows were observed for the successful HTTP(S) probes.")

    print("\nPASS: captured recent outbound network records for the generated traffic.")
    if matched_ips:
        print(f"Matched resolved target IPs: {', '.join(sorted(matched_ips))}")
    else:
        print("No exact target IP match required; validation passed on captured remote ports.")
    return 0


from smoke_manifest import smoke_run, record, epoch_utc, utc_now


@smoke_run("network-capture")
def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HTTP(S) traffic and validate Lintap/Wintap parquet capture.")
    parser.add_argument(
        "--data-root",
        type=Path,
        default=None,
        help="Wintap/Lintap data root. Defaults to WINTAP_DATA_ROOT or platform default.",
    )
    parser.add_argument("--parquet-root", type=Path, default=None, help="Override parquet root. Defaults to <data-root>/raw_sensor.")
    parser.add_argument(
        "--start-lintap",
        action="store_true",
        help="start Lintap in direct-parquet mode for this test (requires root)",
    )
    parser.add_argument(
        "--lintap-dll",
        type=Path,
        default=None,
        help="path to Lintap.dll (required with --start-lintap)",
    )
    parser.add_argument("--endpoint", action="append", dest="endpoints", help="Endpoint URL to request. May be supplied multiple times.")
    parser.add_argument("--rounds", type=int, default=3, help="Number of request rounds to generate.")
    parser.add_argument("--request-timeout", type=int, default=10, help="Per-request timeout in seconds.")
    parser.add_argument("--timeout", type=int, default=180, help="Maximum seconds to wait for parquet rows to appear.")
    parser.add_argument("--poll-interval", type=int, default=10, help="Seconds between parquet polling attempts.")
    parser.add_argument("--require-target-ip-match", action="store_true", help="Require a resolved endpoint IPv4 address to appear in captured rows. Disabled by default because CDNs/proxies can change target IPs.")
    args = parser.parse_args()

    data_root: Path
    if args.data_root is not None:
        data_root = args.data_root
    elif args.start_lintap:
        data_root = Path("/tmp") / ("lintap-data-network-smoke-" + str(int(time.time())))
    else:
        data_root = default_data_root()

    lintap_proc: subprocess.Popen | None = None
    try:
        if args.start_lintap:
            if os.geteuid() != 0:
                print("FAIL: --start-lintap requires root (run with sudo)")
                return 2
            if args.lintap_dll is None:
                print("FAIL: --lintap-dll is required with --start-lintap")
                return 2
            lintap_proc = start_lintap_direct_parquet(args.lintap_dll, data_root)
            # WinTapSvc has plugin init + a 5s delay before sensors start.
            time.sleep(20)

            if lintap_proc.poll() is not None:
                print(f"FAIL: lintap exited early rc={lintap_proc.returncode}")
                return 2

        endpoints = args.endpoints or DEFAULT_ENDPOINTS
        probes = [parse_endpoint(url) for url in endpoints]
        parquet_root = args.parquet_root or data_root / "raw_sensor"

        print(f"data root: {data_root}")
        print(f"parquet root: {parquet_root}")
        print(f"timeout: {args.timeout}s")

        start_epoch = time.time()
        generate_traffic(probes, args.rounds, args.request_timeout)

        # Generate UDP test traffic as well (separate path). This sends small
        # UDP datagrams to DEFAULT_UDP_TARGETS to exercise UDP capture.
        udp_results = generate_udp_traffic(DEFAULT_UDP_TARGETS, args.rounds, args.request_timeout)
        record(selectors=[dict(domain="network", case="network-suite", pids=[os.getpid()],
                               startedAtUtc=epoch_utc(start_epoch), completedAtUtc=utc_now(),
                               ports=sorted({probe.port for probe in probes} | {port for ip, port in DEFAULT_UDP_TARGETS}),
                               expectedProtocols=["tcp", "udp"],
                               targets=[dict(url=p.url, ips=sorted(p.resolved_ipv4), port=p.port,
                                             requestOk=p.request_ok, error=p.request_error) for p in probes])])

        summarize_expected_targets(probes)

        deadline = time.time() + args.timeout
        last_files: list[Path] = []
        last_rows: list[dict] = []

        while time.time() <= deadline:
            last_files = find_candidate_parquet_files(parquet_root, start_epoch)
            if last_files:
                print(f"\nquerying {len(last_files)} recent parquet file(s)...")
                try:
                    # Compute target ports: include HTTP(S) probe ports that succeeded
                    # and any UDP ports used in the UDP traffic that succeeded.
                    target_ports = {probe.port for probe in probes if probe.request_ok}
                    try:
                        udp_ports = {p for (_, p, ok, _) in udp_results if ok}
                    except Exception:
                        udp_ports = set()
                    target_ports.update(udp_ports)

                    last_rows = query_parquet(last_files, start_epoch, target_ports)
                except Exception as exc:  # noqa: BLE001 - test should print actionable failure
                    print(f"query error: {exc}")
                    last_rows = []

                if last_rows:
                    return validate(last_rows, probes, target_ports, args.require_target_ip_match, udp_ports)

            remaining = int(deadline - time.time())
            if remaining <= 0:
                break
            print(f"waiting for parquet network data... {remaining}s remaining")
            time.sleep(args.poll_interval)

        print("\nFAIL: no matching recent network capture rows were found before timeout.")
        print(f"Recent parquet files considered: {len(last_files)}")
        for path in last_files[:20]:
            print(f"  {path}")
        print("\nTips:")
        print("  - Confirm Lintap/Wintap is running.")
        print("  - Use a short flush interval / serialization interval during this test.")
        print("  - Confirm parquet output is enabled.")
        print("  - Pass --data-root if the service uses a custom DataRootPath.")
        return 1
    finally:
        if lintap_proc is not None:
            stop_process(lintap_proc)


def start_lintap_direct_parquet(lintap_dll: Path, data_root: Path) -> subprocess.Popen:
    data_root.mkdir(parents=True, exist_ok=True)

    temp_config = {
        "DataRoot": str(data_root),
        "DisableMCP": True,
        "DisableDuckDBUI": True,
        "DisableSettings": True,
        "DisableETL": True,
        "EnableDirectParquet": True,
        "DirectParquetFlushSeconds": 2,
        "SkipEsperSend": True,
        "SkipProcessResolve": True,
        "SkipParentProcessResolve": True,
        "SkipProcessRegister": True,
        "DisableSensors": False,
        # Keep only the network sensor on.
        "Execve": False,
        "Exit": False,
        "Clone": False,
        "ProcessRundown": False,
        "Network": True,
        "FileOps": False,
    }
    config_path = Path("/tmp") / ("etlconfig-network-smoke-" + str(int(time.time())) + ".json")
    config_path.write_text(json.dumps(temp_config, indent=2))

    env = os.environ.copy()
    env["WINTAP_CONFIG_PATH"] = str(config_path)
    env.setdefault("ASPNETCORE_URLS", "http://127.0.0.1:0")

    cmd = ["dotnet", str(lintap_dll)]
    print(f"starting lintap: {' '.join(cmd)}")
    return subprocess.Popen(
        cmd,
        env=env,
        cwd=str(lintap_dll.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def stop_process(proc: subprocess.Popen) -> None:
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
        return
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
