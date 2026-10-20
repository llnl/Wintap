#!/usr/bin/env python3
"""
Query persisted BPF diag counters from parquet files using DuckDB.

Searches the Wintap parquet directory for recent parquet files and
queries GenericMessage entries where ProviderId='BPFDiag'.

Usage: python3 devtools/query_bpfdiag_duckdb.py --data-root /var/log/lintap/data --minutes 60
"""
import argparse
import json
import os
import subprocess
from pathlib import Path
import time


def default_data_root():
    return Path(os.environ.get("WINTAP_DATA_ROOT", "/var/log/lintap/data"))


def find_parquet(root: Path, minutes: int):
    cutoff = time.time() - minutes * 60
    files = []
    for p in root.rglob("*.parquet"):
        try:
            if p.stat().st_mtime >= cutoff:
                files.append(p)
        except FileNotFoundError:
            continue
    return files


def build_sql(files):
    file_list = ", ".join("'" + str(p) + "'" for p in files)
    sql = f"""
WITH data AS (
    SELECT * FROM read_parquet([{file_list}], union_by_name=true)
)
SELECT
    data."GenericMessage"['ProviderId'] AS provider,
    data."GenericMessage"['EventName'] AS eventname,
    COUNT(*) AS cnt,
    ANY_VALUE(data."GenericMessage"['Payload']) AS sample_payload
FROM data
WHERE try_cast(MessageType AS VARCHAR) = 'GenericMessage'
  AND data."GenericMessage"['ProviderId'] = 'BPFDiag'
GROUP BY 1,2
ORDER BY cnt DESC;
"""
    return sql


def query_with_duckdb_cli(sql: str):
    proc = subprocess.run(["duckdb", "-json", "-c", sql], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)
    if not proc.stdout.strip():
        return []
    return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--minutes", type=int, default=60)
    args = parser.parse_args()

    # Prefer local CSV written by NetworkSensor for diag counters if present
    csv_path = Path(args.data_root) / "diag" / "diag_counters.csv"
    if csv_path.exists():
        sql = f"SELECT * FROM read_csv_auto('{csv_path}', HEADER=true) ORDER BY TimestampUtc;"
        try:
            rows = query_with_duckdb_cli(sql)
            print(json.dumps(rows, indent=2))
            return 0
        except Exception as e:
            print("duckdb query on CSV failed:", e)
            return 2

    parquet_root = args.data_root / "raw_sensor"
    files = find_parquet(parquet_root, args.minutes)
    if not files:
        print("No recent parquet files found and no diag CSV present")
        return 1

    sql = build_sql(files)
    try:
        rows = query_with_duckdb_cli(sql)
    except Exception as e:
        print("duckdb query failed:", e)
        return 2

    if not rows:
        print("No BPFDiag GenericMessage rows found in recent parquet files")
        return 0

    print(json.dumps(rows, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
