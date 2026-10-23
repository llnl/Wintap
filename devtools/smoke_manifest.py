"""Portable smoke-run evidence. No dependency on collector or analysis filesystem.

Decorated CLIs accept --manifest PATH (default ./smoke-results/<test>-<uuid>.json).
Selectors are written before validation so missing telemetry is still diagnosable.
--smoke-data-root PATH / WINTAP_DATA_ROOT optionally publishes parquet snapshots;
--no-smoke-parquet keeps JSON only. DuckDB is required only for parquet export.
"""
import datetime
import functools
import json
import os
from pathlib import Path
import platform
import socket
import sys
import uuid

_current = None
_durable_root = None
_selectors_published = False


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def epoch_utc(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


def record(**values):
    global _selectors_published
    if _current is not None:
        _current.update(values)
        _save()
        if values.get("selectors") and not _selectors_published:
            _selectors_published = True
            _publish(1, "stimulus-complete")


def _save():
    path = _current_path
    temporary = path.with_suffix(path.suffix + ".active")
    temporary.write_text(json.dumps(_current, indent=2, default=str) + "\n")
    temporary.replace(path)


def _publish(revision, phase):
    if not _durable_root:
        return
    _current.update(smokeEvidenceRevision=revision, smokeEvidencePhase=phase)
    _save()
    try:
        from smoke_parquet import publish
        path = publish(_current, _durable_root, revision, phase)
        print(f"Smoke parquet: {path}")
    except Exception as error:
        # Export failure is not an OS workload failure; keep the JSON evidence
        # and make the problem visible. No delivery/retention guarantees implied.
        _current["durableExportError"] = str(error)
        _save()
        print(f"WARNING: smoke parquet export failed: {error}; JSON retained at {_current_path}", file=sys.stderr)


def smoke_run(test):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            global _current, _current_path, _durable_root, _selectors_published
            if "--help" in sys.argv or "-h" in sys.argv:
                print("Shared smoke option: --manifest PATH (fresh portable run JSON; default ./smoke-results/<test>-<uuid>.json)")
                print("Shared smoke option: --smoke-data-root PATH (contains raw_sensor; default WINTAP_DATA_ROOT); --no-smoke-parquet disables export. Requires Python duckdb.")
                return function(*args, **kwargs)
            run_id = str(uuid.uuid4())
            argv = sys.argv[:]
            path = Path("smoke-results") / f"{test}-{run_id}.json"
            _durable_root = os.environ.get("WINTAP_DATA_ROOT")
            _selectors_published = False
            # Consume shared options before each existing harness's argparse.
            for option in ("--manifest", "--smoke-data-root"):
                matches = [arg for arg in sys.argv if arg == option or arg.startswith(option + "=")]
                if len(matches) > 1:
                    raise SystemExit(f"{option} must be specified only once")
                if not matches:
                    continue
                index = sys.argv.index(matches[0])
                if "=" in matches[0]:
                    value = matches[0].split("=", 1)[1]
                    del sys.argv[index]
                else:
                    if index + 1 >= len(sys.argv) or sys.argv[index + 1].startswith("--"):
                        raise SystemExit(f"{option} requires a path")
                    value = sys.argv[index + 1]
                    del sys.argv[index:index + 2]
                if not value:
                    raise SystemExit(f"{option} requires a path")
                if option == "--manifest":
                    path = Path(value)
                else:
                    _durable_root = value
            if "--no-smoke-parquet" in sys.argv:
                sys.argv.remove("--no-smoke-parquet")
                _durable_root = None
            if path.exists():
                raise SystemExit(f"Refusing to overwrite manifest: {path}")
            path.parent.mkdir(parents=True, exist_ok=True)
            _current_path = path
            _current = dict(smokeManifestVersion=1, runId=run_id, test=test,
                            host=dict(hostname=socket.gethostname(), platform=platform.system(),
                                      architecture=platform.machine()), startedAtUtc=utc_now(),
                             runnerPid=os.getpid(), command=argv, status="running", selectors=[])
            boot_id = Path("/proc/sys/kernel/random/boot_id")
            if boot_id.exists():
                try:
                    _current["host"]["bootId"] = boot_id.read_text().strip()
                except OSError:
                    pass
            _save()
            _publish(0, "started")
            try:
                result = function(*args, **kwargs)
                record(status="passed" if result in (None, 0) else "failed", exitCode=result or 0)
                return result
            except BaseException as error:
                code = error.code if isinstance(error, SystemExit) else 1
                record(status="passed" if code in (None, 0) else "failed", error=str(error),
                       exitCode=code if isinstance(code, int) else 1)
                raise
            finally:
                try:
                    record(completedAtUtc=utc_now())
                    _publish(2, "finished")
                    print(f"Smoke manifest: {path}")
                finally:
                    sys.argv[:] = argv
                    _current = None
                    _durable_root = None
        return wrapped
    return decorate


def process_selector(manifest_text, case="clone", start=None, end=None):
    records = [line.split() for line in manifest_text.splitlines() if line and not line.startswith("SKIP")]
    return dict(case=case, domain="process", startedAtUtc=start, completedAtUtc=end or utc_now(),
                pids=sorted({int(pid) for kind, pid, tid, parent in records if pid == tid}),
                threadIds=sorted({int(tid) for kind, pid, tid, parent in records if pid != tid}),
                records=[dict(case=kind, pid=int(pid), tid=int(tid), parentPid=int(parent))
                         for kind, pid, tid, parent in records], expectedActivities=["Start"],
                skips=[line for line in manifest_text.splitlines() if line.startswith("SKIP")])
