#!/usr/bin/env python3
"""Verify host-relative TCP endpoints, including same-host and same-PID sockets.

Requires normal ETL parquet, including directed SourcePort/DestinationPort
provenance; direct-parquet socket fields are NOT normalized Local/Remote data.
Uses an assigned, non-loopback IPv4 address, not an Internet/NAT public address.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from smoke_manifest import smoke_run, record, epoch_utc, utc_now


def host_address(explicit=None):
    if explicit:
        address = explicit
    else:
        # Route lookup only: UDP connect sends no packet to this documentation IP.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(("192.0.2.1", 9))
            address = route.getsockname()[0]
    parsed = ipaddress.IPv4Address(address)
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError("Use an assigned non-loopback IPv4 interface address")
    return address


def listener(ip):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(20)
    server.bind((ip, 0))
    server.listen(1)
    return server


def receive_exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("Peer closed before completing the exchange")
        data += part
    return data


def serve(server, result):
    with server.accept()[0] as peer:
        peer.settimeout(20)
        result.update(pid=os.getpid(), localPort=peer.getsockname()[1], remotePort=peer.getpeername()[1])
        for _ in range(3):
            assert receive_exact(peer, 17) == b"endpoint-request!"
            peer.sendall(b"endpoint-reply!")


def client(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
        peer.settimeout(20)
        peer.bind((ip, 0))
        peer.connect((ip, port))
        result = dict(pid=os.getpid(), localPort=peer.getsockname()[1], remotePort=port)
        for _ in range(3):
            peer.sendall(b"endpoint-request!")
            assert receive_exact(peer, 15) == b"endpoint-reply!"
            time.sleep(1.1)  # Exercise successive per-socket rate-limit intervals.
        return result


def worker(mode, ip, port=None):
    if mode == "client":
        print(json.dumps(client(ip, port)), flush=True)
        return
    with listener(ip) as server:
        if mode == "server":
            print(json.dumps(dict(pid=os.getpid(), port=server.getsockname()[1])), flush=True)
            result = {}
            serve(server, result)
            print(json.dumps(result), flush=True)
        else:
            result, errors = {}, []
            def run_server():
                try:
                    serve(server, result)
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=run_server)
            thread.start()
            client_result = client(ip, server.getsockname()[1])
            thread.join(25)
            if thread.is_alive() or errors:
                raise RuntimeError(f"Same-process server failed: {errors}")
            print(json.dumps(dict(server=result, client=client_result)), flush=True)


def generate_cases(ip):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker"]
    selectors = []
    started = utc_now()
    with subprocess.Popen(command + ["server", "--host-ip", ip], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as server:
        try:
            ready = json.loads(server.stdout.readline())
            result = subprocess.run(command + ["client", "--host-ip", ip, "--port", str(ready["port"])],
                                    capture_output=True, text=True, check=True, timeout=30)
            client_result = json.loads(result.stdout)
            output, errors = server.communicate(timeout=30)
            if server.returncode:
                raise RuntimeError(errors)
            server_result = json.loads(output)
        finally:
            if server.poll() is None:
                server.kill()
                server.wait()
    selectors.append(case_selector("same-host-separate-processes", ip, server_result, client_result, started))
    started = utc_now()
    result = subprocess.run(command + ["both", "--host-ip", ip], capture_output=True,
                            text=True, check=True, timeout=35)
    ends = json.loads(result.stdout)
    selectors.append(case_selector("same-host-same-process", ip, ends["server"], ends["client"], started))
    return selectors


def case_selector(case, ip, server, client_result, started):
    return dict(domain="network", case=case, pids=sorted({server["pid"], client_result["pid"]}),
                ports=sorted({server["localPort"], client_result["localPort"]}),
                startedAtUtc=started, completedAtUtc=utc_now(), expectedProtocols=["tcp"],
                expectedActivities=["TcpIpSend", "TcpIpRecv"], endpointExpectations=[
                    dict(role=role, localIp=ip, remoteIp=ip, **end)
                    for role, end in [("server", server), ("client", client_result)]])


def validate_rows(rows, selector):
    """Independent oracle: directed ports identify the socket role before normalization."""
    missing, violations, hashes = [], [], {}
    for end in selector["endpointExpectations"]:
        for activity in ("tcpipsend", "tcpiprecv"):
            inbound = activity == "tcpiprecv"
            source = end["remotePort"] if inbound else end["localPort"]
            destination = end["localPort"] if inbound else end["remotePort"]
            matches = [r for r in rows if r["pid"] == end["pid"] and r["activity"] == activity
                       and r["source_port"] == source and r["destination_port"] == destination]
            label = f"{selector['case']}/{end['role']}/{activity}"
            if not matches:
                missing.append(label)
            for row in matches:
                if (row["local_ip"], row["local_port"], row["remote_ip"], row["remote_port"]) != (
                    end["localIp"], end["localPort"], end["remoteIp"], end["remotePort"]):
                    violations.append(label + ": reversed/incorrect host-relative endpoint")
                if not row["pid_hash"] or row["pid_hash"].lower() in ("fixmepid", "unknown", "0"):
                    violations.append(label + ": missing process identity")
                else:
                    hashes.setdefault(end["pid"], set()).add(row["pid_hash"])
    if any(len(values) != 1 for values in hashes.values()):
        violations.append(selector["case"] + ": inconsistent pid_hash within one process")
    if len(selector["pids"]) == 2 and len(hashes) == 2 and len(set.union(*hashes.values())) != 2:
        violations.append(selector["case"] + ": separate processes share pid_hash")
    return dict(case=selector["case"], missing=missing, violations=sorted(set(violations)),
                pidHashes={str(pid): sorted(values) for pid, values in hashes.items()},
                status="failed" if violations else "pending" if missing else "passed")


def read_rows(parquet_root, selectors):
    import duckdb
    files = sorted(str(p) for p in (parquet_root / "raw_process_conn_incr").rglob("*.parquet"))
    if not files:
        return [], "No normal ETL network parquet yet"
    pids = sorted({pid for s in selectors for pid in s["pids"]})
    ports = sorted({port for s in selectors for port in s["ports"]})
    started = min(dt.datetime.fromisoformat(s["startedAtUtc"]).timestamp() for s in selectors)
    first_seen_min = int((started - 2 + 11644473600) * 10000000)
    completed = max(dt.datetime.fromisoformat(s["completedAtUtc"]).timestamp() for s in selectors)
    first_seen_max = int((completed + 2 + 11644473600) * 10000000)
    with duckdb.connect(":memory:") as conn:
        conn.read_parquet(files, union_by_name=True).create_view("network")
        required = {"sourceport", "destinationport", "localipaddr", "remoteipaddr", "pidhash"}
        columns = {col[0].lower() for col in conn.execute("describe network").fetchall()}
        if not required <= columns:
            return [], "Missing normalized/provenance columns: " + ", ".join(sorted(required - columns))
        result = conn.execute(f"""
          select PID as pid, PidHash as pid_hash,
                 lower(replace(IpEvent, '/', '')) as activity,
                 cast(LocalIpAddr as ubigint) as local_ip, LocalPort as local_port,
                 cast(RemoteIpAddr as ubigint) as remote_ip, RemotePort as remote_port,
                 SourcePort as source_port, DestinationPort as destination_port
          from network
          where PID in ({','.join(map(str,pids))})
            and FirstSeenMs between {first_seen_min} and {first_seen_max}
            and (SourcePort in ({','.join(map(str,ports))}) or DestinationPort in ({','.join(map(str,ports))}))
        """)
        names = [col[0] for col in result.description]
        rows = [dict(zip(names, row)) for row in result.fetchall()]
        for row in rows:
            row["local_ip"] = str(ipaddress.IPv4Address(row["local_ip"]))
            row["remote_ip"] = str(ipaddress.IPv4Address(row["remote_ip"]))
        return rows, None


def run_checks(parquet_root, timeout, poll_interval, host_ip=None, prior_selectors=None):
    ip = host_address(host_ip)
    selectors = generate_cases(ip)
    record(selectors=(prior_selectors or []) + selectors)
    deadline = time.monotonic() + timeout
    while True:
        error = None
        try:
            rows, error = read_rows(parquet_root, selectors)
            cases = [validate_rows(rows, selector) for selector in selectors]
        except Exception as exc:
            error = str(exc)
            cases = []
        record(results=dict(endpointCases=cases, endpointQueryError=error, endpointHostIp=ip))
        if cases and any(case["violations"] for case in cases):
            print("FAIL: endpoint normalization violation: " + json.dumps(cases))
            return 1
        if cases and all(case["status"] == "passed" for case in cases):
            print("PASS: both directions normalized correctly for separate-process and same-process TCP ends")
            return 0
        if time.monotonic() >= deadline:
            print("FAIL: endpoint confirmation incomplete: " + json.dumps(dict(cases=cases, queryError=error)))
            return 1
        time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))


@smoke_run("network-endpoints")
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path(os.environ.get("WINTAP_DATA_ROOT", "/var/log/lintap/data")))
    parser.add_argument("--host-ip", help="Assigned non-loopback host IPv4 address; auto-selected by default")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--poll-interval", type=float, default=5)
    args = parser.parse_args()
    return run_checks(args.data_root / "raw_sensor", args.timeout, args.poll_interval, args.host_ip)


if __name__ == "__main__":
    if "--worker" in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("--worker", choices=("server", "client", "both"))
        parser.add_argument("--host-ip", required=True)
        parser.add_argument("--port", type=int)
        args = parser.parse_args()
        worker(args.worker, args.host_ip, args.port)
    else:
        raise SystemExit(main())
