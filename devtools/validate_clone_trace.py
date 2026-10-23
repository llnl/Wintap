"""Run the actual clone object against a TGID/TID workload manifest (Linux/root).

Usage: sudo python3 validate_clone_trace.py --object /path/clone_tracer.bpf.o
       --runner /path/runner --workload /path/workload --output /fresh/run
Add --primary-only to simulate unavailable auxiliary syscall hooks.
"""
from smoke_manifest import smoke_run, record, process_selector, utc_now
import argparse
from collections import Counter
import json
from pathlib import Path
import platform
import select
import subprocess
import time


def evaluate(manifest, events):
    records = [line.split() for line in manifest.splitlines() if not line.startswith("SKIP")]
    processes = {int(tid): kind for kind, pid, tid, parent in records
                 if pid == tid and kind not in ("root", "exec_image")}
    threads = {int(tid): kind for kind, pid, tid, parent in records if pid != tid}
    raw = [tuple(map(int, line.split())) for line in events.splitlines()]
    # The tracepoint fallback uses CLONE_THREAD; a zero flag is NOT proof of a process.
    accepted = [(parent, child, flags) for parent, child, flags in raw
                if flags == 0xffffffffffffffff or not flags & 0x10000]
    counts = Counter(child for parent, child, flags in accepted)
    root = next(int(pid) for kind, pid, tid, parent in records if kind == "root")
    return {
        "process_cases": dict(Counter(processes.values())),
        "thread_cases": dict(Counter(threads.values())),
        "missing_processes": sorted(pid for pid in processes if not counts[pid]),
        "duplicate_births": sorted(pid for pid in processes if counts[pid] > 1),
        "false_thread_births": sorted(threads.keys() & counts.keys()),
        "wrong_worker_parents": [(parent, child) for parent, child, flags in accepted
                                 if processes.get(child) == "worker_fork" and parent != root],
        "skips": [line for line in manifest.splitlines() if line.startswith("SKIP")],
    }


@smoke_run("clone-trace")
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--object", required=True)
    p.add_argument("--runner", required=True)
    p.add_argument("--workload", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--primary-only", action="store_true")
    args = p.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    cmd = [args.runner, args.object] + (["primary-only"] if args.primary_only else [])
    with (out / "events.txt").open("w") as events, (out / "runner.log").open("w") as log:
        runner = subprocess.Popen(cmd, stdout=events, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 15
            while True:
                if time.monotonic() > deadline:
                    raise RuntimeError("runner did not attach")
                if select.select([runner.stderr], [], [], 0.2)[0]:
                    line = runner.stderr.readline()
                    log.write(line)
                    log.flush()
                    if "READY" in line:
                        break
                if runner.poll() is not None:
                    raise RuntimeError(f"runner attach failed: {runner.returncode}")
            start = utc_now()
            workload = subprocess.run([args.workload], capture_output=True, text=True, timeout=30)
            record(selectors=[process_selector(workload.stdout, start=start)],
                   mode="actual-object-trace", primaryOnly=args.primary_only)
            (out / "manifest.txt").write_text(workload.stdout)
            (out / "workload.log").write_text(workload.stderr)
            workload.check_returncode()
            time.sleep(0.5)  # bounded ring drain, not tool/background polling
        finally:
            runner.terminate()
            _, errors = runner.communicate(timeout=5)
            log.write(errors)
        if runner.returncode:
            raise RuntimeError(f"runner failed: {runner.returncode}")
    result = evaluate((out / "manifest.txt").read_text(), (out / "events.txt").read_text())
    result.update(kernel=platform.release(), arch=platform.machine(), object=args.object,
                  primary_only=args.primary_only)
    (out / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    record(results=result)
    print(json.dumps(result, indent=2))
    return int(any(result[key] for key in (
        "missing_processes", "duplicate_births", "false_thread_births", "wrong_worker_parents")))


if __name__ == "__main__":
    raise SystemExit(main())
