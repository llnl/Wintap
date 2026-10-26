#!/usr/bin/env python3
"""Small Linux telemetry stimulus, stdlib only. Does NOT validate sensor output.

Run with an already-running collector. Names are <=15 bytes for Linux comm;
manifest PID/TID, paths, ports, times and command lines are authoritative selectors.
Only writes inside a fresh --output directory and connects to loopback addresses.
"""
import argparse
import ctypes
import datetime
import json
import mmap
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import uuid
from smoke_manifest import smoke_run, record


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def name_process(name):
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(15, name.encode(), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


def emit(root, case, operation, **details):
    row = dict(timeUtc=now(), case=case, operation=operation, pid=os.getpid(),
               tid=threading.get_native_id(), parentPid=os.getppid(), **details)
    with (root / "evidence" / f"{os.getpid()}-{threading.get_native_id()}.jsonl").open("a") as stream:
        stream.write(json.dumps(row) + "\n")


def executable(root, case):
    path = root / "bin" / case
    if not path.exists():
        path.symlink_to(sys.executable)
    return path


def worker_command(root, case, *extra):
    return [str(executable(root, case)), str(Path(__file__).resolve()),
            "--output", str(root), "--worker", case, *extra]


def child(root, case, *extra):
    result = subprocess.run(worker_command(root, case, *extra), capture_output=True,
                            text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{case} exit {result.returncode}: {result.stderr}")


def files(root, case):
    directory = root / "files" / case
    directory.mkdir()
    path = directory / "created.bin"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        emit(root, case, "create/open", path=str(path), expectedActivity="Open")
        payload = b"wintap-smoke-file\n" * 64
        assert os.write(fd, payload) == len(payload)
        os.fsync(fd)
        emit(root, case, "write", path=str(path), bytes=len(payload), expectedActivity="Write")
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, len(payload)) == payload
        emit(root, case, "read", path=str(path), bytes=len(payload), expectedActivity="Read")
        with mmap.mmap(fd, len(payload)) as mapping:
            assert mapping[:8] == payload[:8]
            mapping[0:1] = b"W"
            mapping.flush()
        emit(root, case, "file-backed-mmap", path=str(path), expectedActivity="Read",
             note="Linux producer folds mmap into Read, not a distinct MemoryMap row")
    finally:
        os.close(fd)
    emit(root, case, "close", path=str(path), expectedActivity="Close")
    renamed = directory / "renamed.bin"
    path.rename(renamed)
    emit(root, case, "rename", oldPath=str(path), path=str(renamed), expectedActivity=None)
    with renamed.open("r+b", buffering=0) as stream:
        stream.truncate(32)
    emit(root, case, "truncate", path=str(renamed), expectedActivity=None)
    # Reopen after rename supplies the FD/path index with the new name.
    fd = os.open(renamed, os.O_RDONLY)
    os.read(fd, 32)
    os.close(fd)
    renamed.unlink()
    emit(root, case, "unlink", path=str(renamed), expectedActivity="Delete")
    dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open("relative.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600, dir_fd=dirfd)
        os.write(fd, b"relative-path\n")
        os.lseek(fd, 0, os.SEEK_SET)
        os.read(fd, 14)
        os.close(fd)
        os.unlink("relative.bin", dir_fd=dirfd)
        emit(root, case, "dirfd-openat-write-read-close-unlinkat", path=str(directory / "relative.bin"),
             expectedActivities=["Open", "Write", "Read", "Close", "Delete"])
    finally:
        os.close(dirfd)

    # Coexisting case-only names exercise the real serializer/key projection.
    # Each receives independent exact-path assertions in the manifest.
    for name in ('CaseOnly.bin', 'caseonly.bin'):
        exact = directory / name
        fd = os.open(exact, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            assert os.write(fd, b'case-pair') == 9
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, 9) == b'case-pair'
        finally:
            os.close(fd)
        emit(root, case, 'case-only-open-write-read-close', path=str(exact),
             expectedActivities=['Open', 'Write', 'Read', 'Close'])
    for name in ('CaseOnly.bin', 'caseonly.bin'):
        exact = directory / name
        exact.unlink()
        emit(root, case, 'case-only-unlink', path=str(exact), expectedActivity='Delete')

    # Learned cwd identity survives a subsequent cwd change/worker exit. This
    # worker is isolated; no collector or parent process directory is changed.
    old_cwd = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
    base = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fchdir(base)
        fd = os.open('cwd.bin', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
        os.unlink('cwd.bin')
        emit(root, case, 'cwd-unlink', path=str(directory / 'cwd.bin'), expectedActivity='Delete')
    finally:
        os.fchdir(old_cwd)
        os.close(base)
        os.close(old_cwd)


def receive_exact(sock, expected):
    received = b""
    while len(received) < len(expected):
        part = sock.recv(len(expected) - len(received))
        if not part:
            raise RuntimeError("Unexpected TCP EOF")
        received += part
    assert received == expected


def network(root, case, port, ipv6):
    tcp = "tcp" in case
    server = case.endswith("srv")
    address = "::1" if ipv6 else "127.0.0.1"
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,
                       socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(8)
        sock.bind((address, 0))
        if server:
            if tcp:
                sock.listen(1)
            ready = {"port": sock.getsockname()[1]}
            print(json.dumps(ready), flush=True)
            if tcp:
                conn, peer = sock.accept()
                with conn:
                    conn.settimeout(8)
                    emit(root, case, "accept", local=list(conn.getsockname()), peer=list(peer), expectedActivity="TcpIpAccept")
                    receive_exact(conn, b"smoke-request")
                    conn.sendall(b"smoke-response")
                    conn.shutdown(socket.SHUT_WR)
                    assert conn.recv(1) == b""
                emit(root, case, "receive/send/disconnect", peer=list(peer),
                     expectedActivities=["TcpIpRecv", "TcpIpSend", "TcpIpDisconnect"])
            else:
                # Each mode has a distinct worker/socket/selector. Connected
                # Receive must not satisfy the unconnected case (or vice versa).
                data, peer = sock.recvfrom(4096)
                assert data == b"smoke-request"
                sock.sendto(b"smoke-response", peer)
                emit(root, case, "receive/send", local=list(sock.getsockname()), peer=list(peer),
                     expectedActivities=["UdpIpRecv", "UdpIpSend"])
        elif tcp:
            sock.connect((address, port))
            emit(root, case, "connect", local=list(sock.getsockname()), peer=list(sock.getpeername()), expectedActivity="TcpIpConnect")
            sock.sendall(b"smoke-request")
            receive_exact(sock, b"smoke-response")
            sock.shutdown(socket.SHUT_WR)
            assert sock.recv(1) == b""
            emit(root, case, "send/receive/disconnect", expectedActivities=["TcpIpSend", "TcpIpRecv", "TcpIpDisconnect"])
        else:
            connected = "cn" in case
            if connected:
                sock.connect((address, port))
                sock.send(b"smoke-request")
                assert sock.recv(4096) == b"smoke-response"
            else:
                sock.sendto(b"smoke-request", (address, port))
                assert sock.recvfrom(4096)[0] == b"smoke-response"
            emit(root, case, "connected-send/recv" if connected else "unconnected-sendto/recvfrom",
                 local=list(sock.getsockname()), peer=[address, port],
                 expectedActivities=["UdpIpSend", "UdpIpRecv"])


def network_pair(root, protocol, ipv6=False, connected=None):
    if protocol == 'udp' and connected is None:
        network_pair(root, protocol, ipv6, connected=False)
        time.sleep(1.1)  # Respect existing per-socket sampling/pointer reuse.
        network_pair(root, protocol, ipv6, connected=True)
        return
    base = f"wt_{protocol}{'6' if ipv6 else '4'}"
    if connected:
        base += 'cn'
    server = subprocess.Popen(worker_command(root, base + "srv"), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    try:
        # Server has an 8-second socket deadline and exits on setup failure.
        line = server.stdout.readline()
        if not line:
            raise RuntimeError(server.stderr.read())
        port = json.loads(line)["port"]
        child(root, base + "cli", "--port", str(port))
        _, stderr = server.communicate(timeout=15)
        if server.returncode:
            raise RuntimeError(stderr)
    finally:
        if server.poll() is None:
            server.kill()
        server.communicate()


def worker(args):
    root, case = args.output, args.worker
    name_process(case)
    emit(root, case, "worker-start", commandLine=sys.argv, expectedActivity="Start")
    time.sleep(args.hold)
    if case == "wt_file":
        files(root, case)
    elif "tcp" in case or "udp" in case:
        network(root, case, args.port, "6" in case)
    elif case == "wt_fork":
        pid = os.fork()
        if pid == 0:
            name_process("wt_forkchild")
            emit(root, "wt_forkchild", "fork-only", expectedActivity="Start", noExec=True)
            time.sleep(args.hold)
            emit(root, "wt_forkchild", "exit", expectedActivity="Stop")
            os._exit(0)
        assert os.waitpid(pid, 0)[1] == 0
    elif case == "wt_forkexec":
        pid = os.fork()
        if pid == 0:
            os.execv(str(executable(root, "wt_execimage")), worker_command(root, "wt_execimage"))
        assert os.waitpid(pid, 0)[1] == 0
    elif case == "wt_spawn":
        command = worker_command(root, "wt_spawnchild")
        pid = os.posix_spawn(command[0], command, os.environ)
        assert os.waitpid(pid, 0)[1] == 0
        emit(root, case, "posix_spawn", childPid=pid, note="libc chooses clone/vfork implementation")
    elif case == "wt_threads":
        def body():
            name_process("wt_thread")
            emit(root, "wt_thread", "thread-birth", expectedProcessStart=False)
            time.sleep(args.hold)
        thread = threading.Thread(target=body)
        thread.start()
        thread.join()
    time.sleep(args.hold)
    emit(root, case, "worker-exit", expectedActivity="Stop")


@smoke_run("telemetry-workload")
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="fresh stimulus/manifest directory; NOT collector data root")
    parser.add_argument("--clone-helper", type=Path, help="optional compiled clone_lifecycle_workload; one round")
    parser.add_argument("--ipv6", action="store_true", help="extra loopback probes; Linux network capture currently IPv4")
    parser.add_argument("--hold", type=float, default=0.2, help="worker dwell seconds (0–10)")
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This workload targets Linux; use the existing platform capture tests elsewhere")
    if not 0 <= args.hold <= 10:
        parser.error("--hold must be between 0 and 10")
    args.output = (args.output or Path.cwd() / f"telemetry-smoke-{uuid.uuid4().hex[:8]}").resolve()
    if args.worker:
        worker(args)
        return
    root = args.output
    root.mkdir(parents=True, exist_ok=False)
    for directory in ("bin", "files", "evidence"):
        (root / directory).mkdir()
    report = dict(schemaVersion=1, runId=uuid.uuid4().hex, startedAtUtc=now(), output=str(root),
                  stimulusOnly=True, cases=[], limitations=[
                      "Names are runtime comm/exec aliases; fork birth inherits parent name. Match manifest PID/time/path/port too.",
                      "Interpreter resolver may normalize aliases to python. Command line includes case and run directory.",
                      "No one-to-one syscall/row guarantee: normal ETL aggregates; inspect HOST capabilities and collector filters.",
                      "Rename/truncate are extra stimuli, not Linux FileOps event types. IPv6 is not currently certified.",
                      "Refresh needs collector rundown timing; HOST and SELinux are not induced by this workload."])
    def run(label, action):
        try:
            action()
            report["cases"].append(dict(case=label, status="generated"))
        except Exception as error:
            report["cases"].append(dict(case=label, status="failed", reason=str(error)))
    # Precreate exec aliases before forking; worker children never share file setup.
    for case in ("wt_execimage", "wt_spawnchild"):
        executable(root, case)
    for case in ("wt_fork", "wt_forkexec", "wt_spawn", "wt_threads", "wt_file"):
        run(case, lambda case=case: child(root, case, "--hold", str(args.hold)))
    for protocol in ("tcp", "udp"):
        run(f"{protocol}-ipv4", lambda protocol=protocol: network_pair(root, protocol))
    if args.ipv6:
        for protocol in ("tcp", "udp"):
            run(f"{protocol}-ipv6-extra", lambda protocol=protocol: network_pair(root, protocol, True))
    if args.clone_helper:
        def native():
            environment = dict(os.environ, WINTAP_SMOKE_NAMES="1")
            result = subprocess.run([str(args.clone_helper.resolve()), "--rounds=1"],
                                    capture_output=True, text=True, timeout=30, env=environment)
            (root / "native.manifest").write_text(result.stdout)
            (root / "native.stderr").write_text(result.stderr)
            if result.returncode:
                raise RuntimeError(f"native helper exit {result.returncode}: {result.stderr}")
            report["nativeSkips"] = [line for line in result.stdout.splitlines() if line.startswith("SKIP")]
            report["nativeEvents"] = []
            for line in result.stdout.splitlines():
                if line.startswith("SKIP"):
                    continue
                kind, pid, tid, parent = line.split()
                report["nativeEvents"].append(dict(case=kind, pid=int(pid), tid=int(tid), parentPid=int(parent),
                                                  expectedProcessStart=pid == tid))
        run("native-clone-families", native)
    else:
        report["cases"].append(dict(case="native-clone-families", status="skipped",
                                    reason="Pass --clone-helper for legacy clone and clone3 process/thread plus worker-thread fork"))
    report["events"] = [json.loads(line) for path in sorted((root / "evidence").glob("*.jsonl"))
                        for line in path.read_text().splitlines()]
    report["completedAtUtc"] = now()
    selectors = []
    for case in sorted({event["case"] for event in report["events"]}):
        events = [event for event in report["events"] if event["case"] == case]
        domain = "file" if case == "wt_file" else "network" if "tcp" in case or "udp" in case else "process"
        activities = sorted({activity for event in events for activity in
                             event.get("expectedActivities", [event.get("expectedActivity")]) if activity})
        if domain != "process":
            activities = [a for a in activities if a not in ("Start", "Stop")]
        selector = dict(case=case, domain=domain, pids=sorted({e["pid"] for e in events if e.get("expectedProcessStart") is not False}),
                              threadIds=[e["tid"] for e in events if e.get("expectedProcessStart") is False],
                              startedAtUtc=report["startedAtUtc"], completedAtUtc=report["completedAtUtc"],
                              expectedActivities=activities, paths=[e["path"] for e in events if "path" in e])
        if domain == 'file':
            by_path = {}
            for event in events:
                if 'path' not in event:
                    continue
                required = [event['expectedActivity']] if event.get('expectedActivity') else event.get('expectedActivities', [])
                by_path.setdefault(event['path'], set()).update(required)
            selector['pathExpectations'] = [dict(path=path, expectedActivities=sorted(required))
                for path, required in sorted(by_path.items()) if required]
        if domain == "network":
            selector["ports"] = sorted({endpoint[1] for e in events for endpoint in (e.get("local"), e.get("peer")) if endpoint})
            selector["expectedProtocols"] = ["tcp" if "tcp" in case else "udp"]
            # The exact tuple contract is IPv4 here; IPv6 stimulus/skips retain
            # their prior separate scope rather than inheriting IPv4 acceptance.
            unique = {(e['pid'], tuple(e['local']), tuple(e['peer'])) for e in events
                if e.get('local') and e.get('peer') and e['local'][0] == '127.0.0.1' and e['peer'][0] == '127.0.0.1'}
            if unique:
                selector['endpointExpectations'] = [dict(role=case, pid=pid,
                    protocol=selector['expectedProtocols'][0], localIp=local[0], localPort=local[1],
                    remoteIp=peer[0], remotePort=peer[1]) for pid, local, peer in sorted(unique)]
        selectors.append(selector)
    if report.get("nativeEvents"):
        selectors.append(dict(case="native-clone", domain="process",
                              pids=sorted({e["pid"] for e in report["nativeEvents"] if e["expectedProcessStart"]}),
                              threadIds=[e["tid"] for e in report["nativeEvents"] if not e["expectedProcessStart"]],
                              startedAtUtc=report["startedAtUtc"], completedAtUtc=report["completedAtUtc"],
                              expectedActivities=["Start"], skips=report.get("nativeSkips", [])))
    record(selectors=selectors, results={"cases": report["cases"]}, stimulusOnly=True)
    (root / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Manifest: {root / 'manifest.json'}")
    for case in report["cases"]:
        print(f"{case['status']:9} {case['case']} {case.get('reason', '')}")
    if any(case["status"] == "failed" for case in report["cases"]):
        raise SystemExit(1)


if __name__ == "__main__":
    # Internal workers must not create independent top-level smoke manifests.
    if "--worker" in sys.argv:
        main.__wrapped__()
    else:
        main()
