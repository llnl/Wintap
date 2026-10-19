#!/usr/bin/env python3
"""
Simple diagnostic CLI that tails the Lintap log and prints BPF diag events live.

This is a pragmatic userland tool that watches `/var/log/lintap/runtime/Logs/Lintap.log`
and prints lines that look like the in-band diag events emitted by the tracer.

Usage: python3 devtools/ebpf_diag_dump.py
"""
import time
import os
import sys


LOG_PATH = os.environ.get("WINTAP_LOG_PATH", "/var/log/lintap/runtime/Logs/Lintap.log")


def follow(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Seek to end
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                yield line.rstrip('\n')
    except FileNotFoundError:
        print(f"Log file not found: {path}", file=sys.stderr)
        sys.exit(2)


def main():
    print(f"Tailing BPF diag events from: {LOG_PATH}")
    for line in follow(LOG_PATH):
        if "BPF diag event code=" in line or "aggregated BPF diag" in line:
            print(line)


if __name__ == '__main__':
    main()
