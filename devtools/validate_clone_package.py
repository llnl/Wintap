"""Linux/root installed-package normal-ETL acceptance; requires Python duckdb.

Uses lintap.service and its untouched packaged env for the default run. Temporarily
sets ONLY Clone=false for the opt-out run, restoring the env in finally. Intended
for a disposable designated host, never an unrelated active production collector.
"""
from smoke_manifest import smoke_run, record, process_selector, utc_now
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import time

import duckdb


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def receipt(data, previous):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        files = set(data.rglob("*raw_host*.parquet")) - previous
        if files:
            rows = duckdb.connect().execute("SELECT RuntimeCapabilitiesJson FROM read_parquet(?, union_by_name=true)",
                                            [[str(f) for f in files]]).fetchall()
            for (text,) in rows:
                if text:
                    return json.loads(text), text
        time.sleep(0.2)
    raise RuntimeError("No new published HOST receipt")


def workload(workload_path, output, name, rounds=20):
    start = utc_now()
    result = subprocess.run([str(workload_path), f"--rounds={rounds}"], check=True, capture_output=True, text=True, timeout=60)
    (output / f"{name}.manifest").write_text(result.stdout)
    selector = process_selector(result.stdout, case=name, start=start)
    selector["expectedActivities"] = ["Start"]
    if name == "optout":
        selector["pids"] = [r["pid"] for r in selector["records"] if r["case"] == "fork_exec"]
    _selectors.append(selector)
    record(selectors=_selectors)
    return result.stdout


def evaluate(con, files, manifest, enabled):
    entries = [line.split() for line in manifest.splitlines() if not line.startswith("SKIP")]
    processes = {int(tid): (kind, int(parent)) for kind, pid, tid, parent in entries
                 if pid == tid and kind not in ("root", "exec_image")}
    threads = {int(tid) for kind, pid, tid, parent in entries if pid != tid}
    rows = con.execute("SELECT PID, ParentPID, PidHash FROM read_parquet(?, union_by_name=true) WHERE ActivityType='Start'",
                       [[str(f) for f in files]]).fetchall()
    seen = {pid for pid, parent, identity in rows}
    identities = {pid: {identity for p, parent, identity in rows if p == pid} for pid in processes}
    return dict(processCases=dict(Counter(kind for kind, parent in processes.values())),
                missingProcesses=sorted(pid for pid, (kind, parent) in processes.items() if pid not in seen and (enabled or kind == "fork_exec")),
                falseThreadStarts=sorted(threads & seen),
                wrongWorkerParents=[(pid, parent) for pid, parent, identity in rows if pid in processes and processes[pid][0] == "worker_fork" and parent != processes[pid][1]],
                identitySplits=[pid for pid in identities if len(identities[pid]) > 1],
                forkOnlyObserved=sum(pid in seen for pid, (kind, parent) in processes.items() if kind == "fork_only"),
                startCounts=dict(Counter(pid for pid, parent, identity in rows if pid in processes)),
                skips=[line for line in manifest.splitlines() if line.startswith("SKIP")])


_selectors = []


@smoke_run("clone-package")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data", type=Path, default=Path("/var/log/lintap/data"))
    parser.add_argument("--runtime", type=Path, default=Path("/var/log/lintap/runtime"))
    parser.add_argument("--merge-wait", type=int, default=320)
    args = parser.parse_args()
    _selectors.clear()
    args.output.mkdir(parents=True, exist_ok=False)
    env_file = Path("/etc/lintap/lintap.env")
    original = env_file.read_bytes()
    assert all(line.endswith("=true") for line in original.decode().splitlines() if line.startswith("WINTAP_ENABLE_CLONE_SENSOR="))
    assert subprocess.run(["systemctl", "is-active", "lintap"], capture_output=True, text=True).stdout.strip() != "active"  # designated idle host only
    report = {}
    try:
        previous = set(args.data.rglob("*raw_host*.parquet"))
        command("systemctl", "start", "lintap")
        first, text = receipt(args.data, previous)
        assert first["sensors"]["Clone"]["status"] == "running"
        assert first["sensors"]["Clone"]["tier"] == "core"
        assert first["settings"]["etlStarted"]["effectiveValue"] is True
        for key in ("WINTAP_SKIP_PROCESS_RESOLVE", "WINTAP_SKIP_PARENT_PROCESS_RESOLVE", "WINTAP_SKIP_PROCESS_REGISTER", "WINTAP_SKIP_ESPER_SEND", "WINTAP_ENABLE_DIRECT_PARQUET"):
            assert first["settings"][key]["effectiveValue"] is False, key
        assert "RUNTIME_CAPABILITIES " + text in (args.runtime / "Logs/Lintap.log").read_text()
        manifest = workload(args.workload, args.output, "default")
        burst = workload(args.workload, args.output, "burst", 100)
        time.sleep(args.merge_wait)  # one bounded normal merge interval
        command("systemctl", "stop", "lintap")
        files = list(args.data.rglob("*raw_process+*.parquet"))
        assert files, "Normal ETL has no published process output"
        con = duckdb.connect()
        report["default"] = evaluate(con, files, manifest, True)
        report["burst"] = evaluate(con, files, burst, True)
        report["defaultReceipt"] = first
        previous = set(args.data.rglob("*raw_host*.parquet"))
        command("systemctl", "start", "lintap")
        second, _ = receipt(args.data, previous)
        assert second["captureRunId"] != first["captureRunId"]
        assert second["sensors"]["Clone"]["status"] == "running"
        command("systemctl", "stop", "lintap")
        report["restartReceipt"] = second
        previous = set(args.data.rglob("*raw_host*.parquet"))
        env_file.write_text(original.decode().replace("WINTAP_ENABLE_CLONE_SENSOR=true", "WINTAP_ENABLE_CLONE_SENSOR=false"))
        command("systemctl", "start", "lintap")
        off, _ = receipt(args.data, previous)
        assert off["sensors"]["Clone"]["status"] == "disabled"
        manifest_off = workload(args.workload, args.output, "optout")
        time.sleep(args.merge_wait)
        command("systemctl", "stop", "lintap")
        files = list(args.data.rglob("*raw_process+*.parquet"))
        report["optout"] = evaluate(con, files, manifest_off, False)
        report["optoutReceipt"] = off
        assert report["optout"]["forkOnlyObserved"] == 0
        for name in ("default", "burst", "optout"):
            for key in ("missingProcesses", "falseThreadStarts", "wrongWorkerParents"):
                assert not report[name][key], (name, key, report[name][key])
    finally:
        subprocess.run(["systemctl", "stop", "lintap"], check=False)
        env_file.write_bytes(original)
        report["environmentSha256"] = hashlib.sha256(original).hexdigest()
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        record(results=report)
        log = args.runtime / "Logs/Lintap.log"
        if log.exists():
            (args.output / "Lintap.log").write_bytes(log.read_bytes())
    print(json.dumps({k: v for k, v in report.items() if "Receipt" not in k}, indent=2))


if __name__ == "__main__":
    main()
