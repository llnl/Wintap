"""Linux/root dual-sensor direct-parquet characterization; requires duckdb.

Usage: sudo python validate_clone_pipeline.py --dll /native/build/Lintap.dll
       --workload /native/workload --output /fresh/path
This does not replace normal ETL or packaged deployment acceptance.
"""
from smoke_manifest import smoke_run, record, process_selector, utc_now
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import duckdb


@smoke_run("clone-pipeline")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    config = dict(DataRoot=str(args.output / "data"), RuntimeRoot=str(args.output / "runtime"), DisableMCP=True,
                  DisableDuckDBUI=True, DisableSettings=True, DisableETL=True,
                  EnableDirectParquet=True, DirectParquetFlushSeconds=2,
                  SkipEsperSend=True, SkipProcessResolve=True,
                  SkipParentProcessResolve=True, SkipProcessRegister=True,
                  DisableSensors=False, Execve=True, Clone=True, Exit=False,
                  ProcessRundown=False, Network=False, FileOps=False)
    cfg = args.output / "config.json"
    cfg.write_text(json.dumps(config, indent=2))
    env = dict(os.environ, WINTAP_CONFIG_PATH=str(cfg),
               ASPNETCORE_URLS="http://127.0.0.1:0", WINTAP_ENABLE_CLONE_SENSOR="true")
    with (args.output / "lintap.log").open("w") as log:
        proc = subprocess.Popen(["dotnet", str(args.dll)], cwd=args.dll.parent,
                                env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 40
            runtime_log = args.output / "runtime" / "Logs" / "Lintap.log"
            while True:
                text = runtime_log.read_text(errors="replace") if runtime_log.exists() else ""
                if all(f"{sensor} sensor registered" in text
                       for sensor in ("ExecveProcess", "CloneProcess")):
                    break
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Both sensors not registered; inspect runtime/Logs/Lintap.log")
                time.sleep(0.2)
            start = utc_now()
            workload = subprocess.run([str(args.workload)], capture_output=True,
                                      text=True, timeout=30)
            (args.output / "manifest.txt").write_text(workload.stdout)
            record(selectors=[process_selector(workload.stdout, start=start)], mode="direct-parquet")
            workload.check_returncode()
            time.sleep(6)
        finally:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=30)
    # Direct sink with ETL disabled stops at the writer's runtime staging tier.
    files = list(args.output.rglob("*.parquet"))
    if not files:
        raise RuntimeError("No parquet output")
    con = duckdb.connect()
    rows = con.execute("SELECT PID, PidHash, Process_Arguments FROM read_parquet(?, union_by_name=true) "
                       "WHERE MessageType='Process' AND ActivityType='Start'",
                       [[str(f) for f in files]]).fetchall()
    manifest = [line.split() for line in workload.stdout.splitlines() if not line.startswith("SKIP")]
    processes = {int(tid): kind for kind, pid, tid, parent in manifest
                 if pid == tid and kind not in ("root", "exec_image")}
    threads = {int(tid) for kind, pid, tid, parent in manifest if pid != tid}
    births = Counter(pid for pid, identity, source in rows
                     if "PROC_START_SRC=sched_fork" in (source or "").split())
    exec_pids = [pid for pid, kind in processes.items() if kind == "fork_exec"]
    pairs = {pid: [(identity, source) for p, identity, source in rows if p == pid]
             for pid in exec_pids}
    report = dict(process_cases=dict(Counter(processes.values())),
                  missing_births=[pid for pid in processes if not births[pid]],
                  false_thread_starts=sorted(threads & {pid for pid, _, _ in rows}),
                  fork_exec_observations={str(pid): value for pid, value in pairs.items()},
                  fork_exec_identity_mismatches=[pid for pid, observations in pairs.items()
                                                if len({identity for identity, _ in observations}) != 1],
                  fork_exec_observation_counts=dict(Counter(len(value) for value in pairs.values())),
                  fork_exec_missing_pairs=[pid for pid, observations in pairs.items()
                                          if not all(any(marker in (source or "").split()
                                                         for _, source in observations)
                                                     for marker in ("PROC_START_SRC=sched_fork",
                                                                    "PROC_START_SRC=sched_exec"))],
                  skips=[line for line in workload.stdout.splitlines() if line.startswith("SKIP")])
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    record(results=report)
    print(json.dumps({k: v for k, v in report.items() if k != "fork_exec_observations"}, indent=2))
    return int(any(report[key] for key in ("missing_births", "false_thread_starts",
                                          "fork_exec_identity_mismatches", "fork_exec_missing_pairs")))


if __name__ == "__main__":
    raise SystemExit(main())
