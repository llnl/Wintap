#!/usr/bin/env python3
"""Summarize comparable metrics from lintap_long_ab_workload capture roots."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Optional


DELIVERY = re.compile(
    r"delivery=\[samples=(\d+),avg_us=(\d+),max_us=(\d+),"
    r"le_1ms=(\d+),le_10ms=(\d+),le_100ms=(\d+),le_1s=(\d+),"
    r"le_10s=(\d+),le_60s=(\d+),gt_60s=(\d+)\]"
)
SERIALIZER = re.compile(
    r"fileserializer: serializer_flush .*accepted_total=(\d+),"
    r"dropped_total=(\d+),peak_depth=(\d+)"
)
QUEUE = re.compile(r"queue=\[depth=\d+,high_water=\d+,drops=(\d+),")
RING_FAILURE = re.compile(r"ring_fail_total=(\d+)")
LOG_TIME = "%m/%d/%Y %H:%M:%S"


def workload_window(root: Path) -> tuple[float, float, dict]:
    records = [json.loads(line) for line in (root / "workload.jsonl").read_text().splitlines()]
    start = next(record for record in records if record["event"] == "start")
    finish = next(record for record in records if record["event"] == "finish")
    return start["epoch"], finish["epoch"], finish


def line_epoch(line: str) -> Optional[float]:
    if len(line) < 19:
        return None
    try:
        return datetime.strptime(line[:19], LOG_TIME).timestamp()
    except ValueError:
        return None


def process_metrics(root: Path) -> dict:
    samples = []
    pidstat_path = root / "pidstat.log"
    if pidstat_path.exists():
        for line in pidstat_path.read_text(errors="replace").splitlines():
            fields = line.split()
            if len(fields) < 15 or fields[-1] != "dotnet":
                continue
            try:
                samples.append((float(fields[7]), int(fields[12])))
            except ValueError:
                continue
    return {
        "samples": len(samples),
        "average_cpu_percent": round(sum(row[0] for row in samples) / len(samples), 2) if samples else None,
        "peak_cpu_percent": max((row[0] for row in samples), default=None),
        "average_rss_kib": round(sum(row[1] for row in samples) / len(samples)) if samples else None,
        "peak_rss_kib": max((row[1] for row in samples), default=None),
    }


def summarize(root: Path) -> dict:
    started, finished, workload = workload_window(root)
    delivery_rows = []
    serializer = None
    queue_drops_max = 0
    ring_failures_max = 0
    owner_warnings = 0

    log_path = root / "runtime" / "Logs" / "Lintap.log"
    for line in log_path.read_text(errors="replace").splitlines():
        timestamp = line_epoch(line)
        if timestamp is None or timestamp < started or timestamp > finished + 60:
            continue

        match = DELIVERY.search(line)
        if match:
            delivery_rows.append(tuple(map(int, match.groups())))
        match = SERIALIZER.search(line)
        if match:
            serializer = tuple(map(int, match.groups()))
        match = QUEUE.search(line)
        if match:
            queue_drops_max = max(queue_drops_max, int(match.group(1)))
        ring_failures = [int(value) for value in RING_FAILURE.findall(line)]
        if ring_failures:
            ring_failures_max = max(ring_failures_max, max(ring_failures))
        if "Could not resolve owner process" in line:
            owner_warnings += 1

    samples = sum(row[0] for row in delivery_rows)
    weighted_total_us = sum(row[0] * row[1] for row in delivery_rows)
    buckets = [sum(row[index] for row in delivery_rows) for index in range(3, 10)]
    accepted, dropped, peak = serializer or (0, 0, 0)
    return {
        "root": str(root),
        "workload": {
            "elapsed_s": workload["elapsed_s"],
            "rounds": workload["rounds"],
            "files": workload["files"],
        },
        "delivery": {
            "samples": samples,
            "weighted_interval_average_us": weighted_total_us // max(1, samples),
            "max_us": max((row[2] for row in delivery_rows), default=0),
            "le_1ms": buckets[0],
            "le_10ms": buckets[1],
            "le_100ms": buckets[2],
            "le_1s": buckets[3],
            "le_10s": buckets[4],
            "le_60s": buckets[5],
            "gt_60s": buckets[6],
        },
        "file_serializer": {
            "accepted_total": accepted,
            "dropped_total": dropped,
            "peak_depth": peak,
        },
        "fileops_sender_queue_drops_max": queue_drops_max,
        "bpf_ring_failures_max": ring_failures_max,
        "owner_resolution_warnings": owner_warnings,
        "process_metrics": process_metrics(root),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps([summarize(root) for root in args.roots], indent=2))


if __name__ == "__main__":
    main()
