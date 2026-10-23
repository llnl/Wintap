"""Root/Linux HOST receipt validation (requires duckdb).

Runs two startups against one data root, then a globally-disabled startup.
Optionally checks an independently staged fallback-only payload with --fallback-dll.
Does not modify installed objects or substitute for packaged acceptance.
"""
from smoke_manifest import smoke_run, record
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import duckdb


def run(dll, root, disabled=False):
    root.mkdir(parents=True, exist_ok=True)
    cfg = root / "config.json"
    cfg.write_text(json.dumps(dict(DataRoot=str(root / "data"), RuntimeRoot=str(root / "runtime"),
                                  DisableMCP=True, DisableDuckDBUI=True, DisableETL=True,
                                  EnableDirectParquet=True, DisableSettings=True, DisableSensors=disabled,
                                  Execve=True, Clone=True, Exit=True, Network=True, FileOps=True,
                                  SELinux=True, ProcessRundown=False, SkipEsperSend=True,
                                  SkipProcessResolve=True, SkipParentProcessResolve=True, SkipProcessRegister=True)))
    before = set(root.rglob("*raw_host*.parquet"))
    env = {k: v for k, v in os.environ.items() if not k.startswith("WINTAP_")}
    env.update(WINTAP_CONFIG_PATH=str(cfg), WINTAP_ENABLE_CLONE_SENSOR="true",
               ASPNETCORE_URLS="http://127.0.0.1:0")
    with (root / "console.log").open("a") as log:
        proc = subprocess.Popen(["dotnet", str(dll)], cwd=dll.parent, env=env,
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while not (set(root.rglob("*raw_host*.parquet")) - before):
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"No published HOST receipt: {root}")
                time.sleep(0.2)
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=30)
    files = sorted(set(root.rglob("*raw_host*.parquet")) - before)
    rows = duckdb.connect().execute("SELECT RuntimeCapabilitiesJson FROM read_parquet(?, union_by_name=true)",
                                    [[str(f) for f in files]]).fetchall()
    receipts = {value for (value,) in rows if value}
    assert len(receipts) == 1, rows
    text = receipts.pop()
    receipt = json.loads(text)
    assert receipt["schemaVersion"] == 1 and receipt["phase"] == "startup-complete"
    assert receipt["platform"] == "linux" and receipt["kernelRelease"]
    assert receipt["settings"]["etlStarted"]["effectiveValue"] is False
    runtime_log = (root / "runtime" / "Logs" / "Lintap.log").read_text()
    assert "RUNTIME_CAPABILITIES " + text in runtime_log, "Log and parquet receipts differ"
    assert set(receipt["sensors"]) == {"Execve", "Clone", "Exit", "Network", "FileOps", "SELinux", "ProcessRundown"}
    if disabled:
        assert all(s["status"] == "disabled" for s in receipt["sensors"].values())
    else:
        clone = receipt["sensors"]["Clone"]
        assert clone["status"] in ("running", "partial") and clone["objectSha256"]
        assert clone["configurationSource"] == "environment:WINTAP_ENABLE_CLONE_SENSOR"
        assert clone["hooks"]["trace_process_fork"]["outcome"] == "attached"
        assert receipt["sensors"]["ProcessRundown"]["status"] == "disabled"
        for sensor in receipt["sensors"].values():
            assert sensor["status"] != "starting"
            for hook in sensor["hooks"].values():
                assert hook["outcome"] in ("attached", "failed", "not-found", "not-applicable", "exception")
                if hook["outcome"] == "attached":
                    assert hook["errorCode"] is None
    return receipt


@smoke_run("runtime-capabilities")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fallback-dll", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    first = run(args.dll.resolve(), args.output / "restart")
    second = run(args.dll.resolve(), args.output / "restart")
    assert first["captureRunId"] != second["captureRunId"], "Restart reused receipt"
    disabled = run(args.dll.resolve(), args.output / "disabled", True)
    report = dict(first=first, restart=second, globallyDisabled=disabled)
    if args.fallback_dll:
        fallback = run(args.fallback_dll.resolve(), args.output / "fallback")
        clone = fallback["sensors"]["Clone"]
        assert clone["tier"] == "tracepoint"
        assert clone["features"]["threadClassification"] == "best-effort-syscall-flags"
        assert clone["hooks"]["trace_sys_enter_clone3"]["outcome"] == "attached"
        report["fallback"] = fallback
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    record(results=report, selectors=[dict(domain="host", case=k, captureRunId=v["captureRunId"])
                                     for k, v in report.items()])
    print(json.dumps({k: dict(runId=v["captureRunId"], sensors={n: s["status"] for n, s in v["sensors"].items()})
                      for k, v in report.items()}, indent=2))


if __name__ == "__main__":
    main()
