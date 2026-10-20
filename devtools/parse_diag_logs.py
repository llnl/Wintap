#!/usr/bin/env python3
"""
Parse Lintap log for NetworkSensor aggregated diag lines and emit a CSV for DuckDB.

Writes: /var/log/lintap/runtime/diag/diag_counters_from_logs.csv

Usage: python3 devtools/parse_diag_logs.py --log /var/log/lintap/runtime/Logs/Lintap.log
"""
import argparse
import re
from pathlib import Path
import datetime


LINE_RE = re.compile(r"^(.*) \[Info\]  \[NetworkSensor.Start\]:\s+BPF diag counters .*=(\d+)/(\d+)/(\d+)")
AGG_RE = re.compile(r"aggregated BPF diag \(STORE/HIT/MISS\) = (\d+)/(\d+)/(\d+)")


def parse(log_path: Path):
    out_dir = Path("/var/log/lintap/runtime/diag")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / "diag_counters_from_logs.csv"
    seen_header = out_csv.exists()

    with open(log_path, "r", encoding="utf-8", errors="replace") as f, open(out_csv, "a", encoding="utf-8") as out:
        if not seen_header:
            out.write("TimestampUtc,Store,Hit,Miss\n")

        for line in f:
            m = AGG_RE.search(line)
            if m:
                # try to parse timestamp at start of line
                try:
                    ts_text = line.split(' [', 1)[0].strip()
                    # Example timestamp format: 6/13/2026 12:20:17 PM
                    # Fallback: use current time
                    ts = datetime.datetime.utcnow().isoformat()
                    out.write(f"{ts},{m.group(1)},{m.group(2)},{m.group(3)}\n")
                except Exception:
                    ts = datetime.datetime.utcnow().isoformat()
                    out.write(f"{ts},{m.group(1)},{m.group(2)},{m.group(3)}\n")

    print(f"Wrote diag CSV to: {out_csv}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, default=Path("/var/log/lintap/runtime/Logs/Lintap.log"))
    args = parser.parse_args()
    parse(args.log)


if __name__ == '__main__':
    main()
