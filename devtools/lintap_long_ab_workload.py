#!/usr/bin/env python3
"""Repeatable long-running FileOps/lifecycle/network workload for Linux capture A/B tests."""

import argparse
import concurrent.futures
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time


CHILD = r"""
import os, socket, sys
base, prefix, count, port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
os.makedirs(base, exist_ok=True)
for i in range(count):
    path = os.path.join(base, f"{prefix}-{i:04d}.dat")
    with open(path, "wb") as output:
        output.write((prefix + "\n").encode() * 8)
    with open(path, "rb") as source:
        source.read()
    os.unlink(path)
try:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
        stream.sendall(prefix.encode())
except OSError:
    pass
try:
    datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    datagram.sendto(prefix.encode(), ("127.0.0.1", port))
    datagram.close()
except OSError:
    pass
"""


def serve(listener: socket.socket, stop: threading.Event) -> None:
    listener.settimeout(0.5)
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.recv(1024)
        except TimeoutError:
            pass
        except OSError:
            break


def run_child(command: list[str]) -> int:
    return subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("duration", type=int, help="duration in seconds")
    parser.add_argument("log", type=Path)
    args = parser.parse_args()

    base = Path("/tmp") / f"lintap-long-ab-{args.tag}"
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    stop = threading.Event()
    server = threading.Thread(target=serve, args=(listener, stop), daemon=True)
    server.start()

    started = time.monotonic()
    deadline = started + args.duration
    round_number = 0
    total_files = 0
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", buffering=1) as log:
        log.write(json.dumps({
            "event": "start",
            "tag": args.tag,
            "epoch": time.time(),
            "duration_s": args.duration,
            "port": port,
        }) + "\n")

        while time.monotonic() < deadline:
            round_number += 1
            round_started = time.monotonic()
            burst = round_number % 10 == 0
            workers = 40 if burst else 20
            files_per_worker = 125 if burst else 30
            round_dir = base / f"r{round_number:04d}"
            round_dir.mkdir()
            commands = []
            for worker in range(workers):
                prefix = f"{args.tag}-r{round_number:04d}-w{worker:03d}"
                commands.append([
                    sys.executable,
                    "-c",
                    CHILD,
                    str(round_dir),
                    prefix,
                    str(files_per_worker),
                    str(port),
                ])

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                return_codes = list(pool.map(run_child, commands))

            files = workers * files_per_worker
            total_files += files
            log.write(json.dumps({
                "event": "round",
                "round": round_number,
                "burst": burst,
                "workers": workers,
                "files": files,
                "failures": sum(code != 0 for code in return_codes),
                "elapsed_s": round(time.monotonic() - round_started, 3),
                "epoch": time.time(),
            }) + "\n")
            shutil.rmtree(round_dir, ignore_errors=True)

            target = started + round_number * 60
            remaining = min(target, deadline) - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

        log.write(json.dumps({
            "event": "finish",
            "rounds": round_number,
            "files": total_files,
            "elapsed_s": round(time.monotonic() - started, 3),
            "epoch": time.time(),
        }) + "\n")

    stop.set()
    listener.close()
    server.join(timeout=1)
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
