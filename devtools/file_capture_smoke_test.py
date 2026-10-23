#!/usr/bin/env python3
"""Lintap/Wintap file-activity smoke test (parquet-based).

This is an integration test:

generated file activity -> eBPF file sensor -> parquet writer -> DuckDB query -> expected file-path/activity rows

Prereqs:
  - Lintap/Wintap is already running, OR use --start-lintap (requires root).
  - Parquet output is enabled (ETL parquet or direct-parquet).
  - Either the Python `duckdb` package is installed or `duckdb` CLI is on PATH.

Examples:
  python3 devtools/file_capture_smoke_test.py --data-root /var/log/lintap/data --timeout 180

  sudo python3 devtools/file_capture_smoke_test.py \
    --start-lintap \
    --lintap-dll /tmp/lintap-build/wintap/bin/Debug/net8.0/Lintap.dll \
    --timeout 180
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import platform
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class FileStimulus:
    pid: int
    path: Path
    path_prefix: str
    unique_file_count: int
    start_epoch: float


def default_data_root() -> Path:
    env_root = os.environ.get("WINTAP_DATA_ROOT")
    if env_root:
        return Path(env_root)

    tmp = Path("/tmp")
    try:
        candidates = sorted(
            (p for p in tmp.glob("lintap-data-*") if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for cand in candidates:
            parquet_root = cand / "raw_sensor"
            if parquet_root.exists() and any(parquet_root.rglob("*.parquet")):
                return cand
            if parquet_root.exists() and any(parquet_root.rglob("*.parquet")):
                return cand
    except Exception:
        pass

    system = platform.system().lower()
    if system == "linux":
        log_root = Path("/var/log/lintap")
        if (log_root / "data" / "raw_sensor").exists():
            return log_root / "data"
        if (log_root / "runtime" / "Logs" / "Lintap.log").exists():
            return log_root / "data"
        return log_root / "data"
    if system == "darwin":
        return Path("/Library/Application Support/Mactap")
    if system == "windows":
        program_data = os.environ.get("PROGRAMDATA", r"C:\\ProgramData")
        return Path(program_data) / "Wintap"

    return Path("/var/log/lintap/data")


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def query_with_python_duckdb(sql: str) -> list[dict] | None:
    try:
        import duckdb  # type: ignore[import-not-found]
    except ImportError:
        return None

    con = duckdb.connect(database=":memory:")
    try:
        rows = con.execute(sql).fetchall()
        columns = [desc[0] for desc in con.description]
        return [dict(zip(columns, row)) for row in rows]
    finally:
        con.close()


def query_with_duckdb_cli(sql: str) -> list[dict]:
    proc = subprocess.run(
        ["duckdb", "-json", "-c", sql],
        check=True,
        text=True,
        capture_output=True,
    )
    output = proc.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def query_duckdb(sql: str) -> list[dict]:
    rows = query_with_python_duckdb(sql)
    if rows is not None:
        return rows
    return query_with_duckdb_cli(sql)


def find_candidate_parquet_files(parquet_root: Path, start_epoch: float) -> list[Path]:
    if not parquet_root.exists():
        return []

    files: list[Path] = []
    for file_path in glob.glob(str(parquet_root / "**" / "*.parquet*"), recursive=True):
        path = Path(file_path)
        if path.is_file():
            files.append(path)

    try:
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass
    files = files[:200]

    file_files = [p for p in files if "file" in str(p).lower()]
    return file_files or files


def detect_column_names(files: list[Path]) -> dict[str, str]:
    file_list = ", ".join(sql_string(str(path)) for path in files)
    probe_sql = f"""
WITH data AS (
    SELECT * FROM read_parquet([{file_list}], union_by_name=true)
)
SELECT * FROM data LIMIT 1;
"""

    rows = query_duckdb(probe_sql)
    cols = set(rows[0].keys()) if rows else set()

    def pick(*candidates: str, fallback: str) -> str:
        for c in candidates:
            if c in cols:
                return c
        return fallback

    return {
        "pid": pick("PID", fallback="PID"),
        "message_type": pick("MessageType", fallback="MessageType"),
        "activity_type": pick("ActivityType", fallback="ActivityType"),
        # direct-parquet: File_Path; ETL serializer: File_Path; (some paths may be Path)
        "file_path": pick("File_Path", "Path", fallback="File_Path"),
        "captured_ts": pick("CapturedUtc", "EventTime", fallback="EventTime"),
    }


def build_query(files: Iterable[Path], stimulus: FileStimulus, cols: dict[str, str]) -> str:
    file_list = ", ".join(sql_string(str(path)) for path in files)
    want_path = str(stimulus.path).lower()
    want_prefix = stimulus.path_prefix.lower()
    return f"""
WITH data AS (
    SELECT * FROM read_parquet([{file_list}], union_by_name=true)
)
SELECT
    TRY_CAST({cols['pid']} AS INTEGER) AS pid,
    {stimulus.unique_file_count} AS expected_paths,
    lower(CAST({cols['message_type']} AS VARCHAR)) AS message_type,
    lower(CAST({cols['activity_type']} AS VARCHAR)) AS activity_type,
    lower(CAST({cols['file_path']} AS VARCHAR)) AS file_path,
    lower(CAST({cols['file_path']} AS VARCHAR)) = {sql_string(want_path)} AS is_first_path,
    TRY_CAST({cols['captured_ts']} AS TIMESTAMP) AS captured_utc
FROM data
WHERE TRY_CAST({cols['pid']} AS INTEGER) = {stimulus.pid}
  AND lower(CAST({cols['message_type']} AS VARCHAR)) LIKE '%file%'
  AND starts_with(lower(CAST({cols['file_path']} AS VARCHAR)), {sql_string(want_prefix)})
ORDER BY captured_utc DESC NULLS LAST;
"""


def generate_file_activity(base_dir: Path | None = None, unique_file_count: int = 1) -> FileStimulus:
    start_epoch = time.time()
    pid = os.getpid()

    base = base_dir or (Path("/tmp") / "lintap-file-smoke")
    base.mkdir(parents=True, exist_ok=True)
    payload = ("lintap-file-smoke " + str(start_epoch)).encode("utf-8")
    first_path: Path | None = None

    for index in range(max(1, unique_file_count)):
        path = base / (f"wintap-file-smoke-{pid}-{int(start_epoch)}-{index}.txt")
        if first_path is None:
            first_path = path

        # Write
        with open(path, "wb") as f:
            f.write(payload)
            if unique_file_count == 1:
                f.flush()
                os.fsync(f.fileno())

        # Read
        with open(path, "rb") as f:
            _ = f.read(64)

        # Append
        with open(path, "ab") as f:
            f.write(b"\nmore")

        # Delete
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    assert first_path is not None
    return FileStimulus(
        pid=pid,
        path=first_path,
        path_prefix=str(base / f"wintap-file-smoke-{pid}-{int(start_epoch)}-"),
        unique_file_count=max(1, unique_file_count),
        start_epoch=start_epoch,
    )


def validate(rows: list[dict]) -> tuple[bool, str]:
    if not rows:
        return False, "no matching file rows"

    distinct_paths = {str(r.get("file_path") or "").lower() for r in rows}
    distinct_paths.discard("")
    expected_paths = max(1, int(rows[0].get("expected_paths") or 1)) if rows else 1
    minimum_paths = max(1, math.ceil(expected_paths * 0.95))
    if len(distinct_paths) < minimum_paths:
        return False, f"insufficient distinct path coverage ({len(distinct_paths)}/{expected_paths}, minimum={minimum_paths})"

    first_path_rows = [row for row in rows if row.get("is_first_path")]
    activities = {str(r.get("activity_type") or "").lower() for r in first_path_rows}
    activities.discard("")

    # Be tolerant across tracer variants/kernels: some paths may only reliably
    # produce open + delete for short-lived files (fd->path mapping gaps).
    if "open" not in activities:
        return False, f"missing expected activity 'open' (have={sorted(activities)})"
    if len(activities & {"open", "read", "write", "close", "delete"}) < 2:
        return False, f"insufficient activity diversity (have={sorted(activities)})"

    return True, "ok"


def serializer_drop_total(log_path: Path) -> int:
    """Return the most recent FileSerializer ``dropped_total`` counter."""
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
            latest = 0
            for line in log_file:
                if "fileserializer:" not in line.lower():
                    continue
                match = re.search(r"\bdropped_total=(\d+)\b", line.lower())
                if match:
                    latest = int(match.group(1))
            return latest
    except OSError:
        return 0


def serializer_drops_since(log_path: Path, start_offset: int, baseline_drop_total: int) -> list[str]:
    """Return FileSerializer drop evidence written after ``start_offset``.

    Older serializers emitted a prose backlog-limit warning. Current serializers
    report a monotonic ``dropped_total`` counter with each flush, so accept both
    forms. The counter is compared with its value before the stimulus so prior
    test-run loss does not create a false failure.
    """
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
            log_file.seek(start_offset)
            drops: list[str] = []
            for line in log_file:
                normalized = line.lower()
                if "fileserializer:" not in normalized:
                    continue
                if "in-memory backlog limit reached" in normalized:
                    drops.append(line.rstrip())
                    continue
                match = re.search(r"\bdropped_total=(\d+)\b", normalized)
                if match and int(match.group(1)) > baseline_drop_total:
                    drops.append(line.rstrip())
            return drops
    except OSError as exc:
        return [f"could not read {log_path}: {exc}"]


def start_lintap_direct_parquet(lintap_dll: Path, data_root: Path) -> subprocess.Popen:
    data_root.mkdir(parents=True, exist_ok=True)

    temp_config = {
        "DataRoot": str(data_root),
        "DisableMCP": True,
        "DisableDuckDBUI": True,
        "DisableSettings": True,
        "DisableETL": True,
        "EnableDirectParquet": True,
        "DirectParquetFlushSeconds": 2,
        "SkipEsperSend": True,
        "SkipProcessResolve": True,
        "SkipParentProcessResolve": True,
        "SkipProcessRegister": True,
        "DisableSensors": False,
        # Keep only the file sensor on.
        "Execve": False,
        "Exit": False,
        "Clone": False,
        "ProcessRundown": False,
        "Network": False,
        "FileOps": True,
    }
    config_path = Path("/tmp") / ("etlconfig-file-smoke-" + str(int(time.time())) + ".json")
    config_path.write_text(json.dumps(temp_config, indent=2))

    env = os.environ.copy()
    env["WINTAP_CONFIG_PATH"] = str(config_path)
    env.setdefault("ASPNETCORE_URLS", "http://127.0.0.1:0")

    cmd = ["dotnet", str(lintap_dll)]
    print(f"starting lintap: {' '.join(cmd)}")
    # Run from the native build output directory to avoid shared-mount hangs (ASP.NET ContentRootPath).
    return subprocess.Popen(
        cmd,
        env=env,
        cwd=str(lintap_dll.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def stop_process(proc: subprocess.Popen) -> None:
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
        return
    except Exception:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def drain_lines(proc: subprocess.Popen, max_lines: int = 200) -> tuple[list[str], list[str]]:
    out_lines: list[str] = []
    err_lines: list[str] = []
    try:
        if proc.stdout is not None:
            for _ in range(max_lines):
                line = proc.stdout.readline()
                if not line:
                    break
                out_lines.append(line.rstrip())
    except Exception:
        pass
    try:
        if proc.stderr is not None:
            for _ in range(max_lines):
                line = proc.stderr.readline()
                if not line:
                    break
                err_lines.append(line.rstrip())
    except Exception:
        pass
    return out_lines, err_lines


from smoke_manifest import smoke_run, record, epoch_utc, utc_now


@smoke_run("file-capture")
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=None)
    parser.add_argument(
        "--parquet-root",
        type=Path,
        default=None,
        help="Override parquet root. Defaults to <data-root>/raw_sensor.",
    )
    parser.add_argument(
        "--start-lintap",
        action="store_true",
        help="start Lintap in direct-parquet mode for this test (requires root)",
    )
    parser.add_argument(
        "--lintap-dll",
        type=Path,
        default=None,
        help="path to Lintap.dll (required with --start-lintap)",
    )
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--poll-interval", type=int, default=10)
    parser.add_argument("--file-dir", type=Path, default=None, help="Directory to create the test file under")
    parser.add_argument(
        "--unique-file-count",
        type=int,
        default=1,
        help="number of distinct files to create for a high-cardinality FileOps burst",
    )
    parser.add_argument(
        "--require-no-serializer-drops",
        action="store_true",
        help="fail if FileSerializer reports a backlog drop after this smoke starts",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Lintap log path for --require-no-serializer-drops (defaults to <runtime-root>/Logs/Lintap.log)",
    )
    parser.add_argument(
        "--serializer-observation-seconds",
        type=int,
        default=0,
        help="additional time to observe the serializer log after capture validation",
    )
    args = parser.parse_args()

    data_root: Path
    if args.data_root is not None:
        data_root = args.data_root
    elif args.start_lintap:
        data_root = Path("/tmp") / ("lintap-data-file-smoke-" + str(int(time.time())))
    else:
        data_root = default_data_root()

    lintap_proc: subprocess.Popen | None = None
    try:
        if args.start_lintap:
            if os.geteuid() != 0:
                print("FAIL: --start-lintap requires root (run with sudo)")
                return 2
            if args.lintap_dll is None:
                print("FAIL: --lintap-dll is required with --start-lintap")
                return 2
            lintap_proc = start_lintap_direct_parquet(args.lintap_dll, data_root)
            time.sleep(20)

            if lintap_proc.poll() is not None:
                out_lines, err_lines = drain_lines(lintap_proc)
                print(f"FAIL: lintap exited early rc={lintap_proc.returncode}")
                if out_lines:
                    print("lintap stdout (first lines):")
                    for line in out_lines[:50]:
                        print("  " + line)
                if err_lines:
                    print("lintap stderr (first lines):")
                    for line in err_lines[:50]:
                        print("  " + line)
                return 2

        parquet_root = args.parquet_root or (data_root / "raw_sensor")
        runtime_root = Path(os.environ.get("WINTAP_RUNTIME_ROOT", str(data_root.parent / "runtime")))
        log_path = args.log_file or (runtime_root / "Logs" / "Lintap.log")
        log_start_offset = 0
        baseline_drop_total = 0
        if args.require_no_serializer_drops:
            try:
                log_start_offset = log_path.stat().st_size
                baseline_drop_total = serializer_drop_total(log_path)
            except OSError as exc:
                print(f"FAIL: cannot mark serializer log start: {exc}")
                return 2
        print(f"data root: {data_root}")
        print(f"parquet root: {parquet_root}")

        stimulus = generate_file_activity(args.file_dir, args.unique_file_count)
        record(selectors=[dict(domain="file", case="file-suite", pids=[stimulus.pid],
                               pathPrefix=stimulus.path_prefix, expectedPaths=stimulus.unique_file_count,
                               startedAtUtc=epoch_utc(stimulus.start_epoch), completedAtUtc=utc_now(),
                               expectedActivities=["Open", "Read", "Write", "Close", "Delete"])])
        print(f"generated file activity: pid={stimulus.pid} path={stimulus.path} unique_files={max(1, args.unique_file_count)}")

        deadline = time.time() + args.timeout
        last_error = None
        while time.time() < deadline:
            if lintap_proc is not None and lintap_proc.poll() is not None:
                out_lines, err_lines = drain_lines(lintap_proc)
                last_error = f"lintap exited rc={lintap_proc.returncode}"
                if err_lines:
                    last_error += "; stderr: " + (err_lines[-1] if err_lines else "")
                break

            candidates = find_candidate_parquet_files(parquet_root, stimulus.start_epoch)
            if not candidates:
                last_error = f"no parquet files found under {parquet_root}"
                remaining = int(deadline - time.time())
                print(f"waiting for parquet files... {remaining}s remaining")
                time.sleep(args.poll_interval)
                continue

            cols = detect_column_names(candidates)
            sql = build_query(candidates, stimulus, cols)
            try:
                rows = query_duckdb(sql)
            except Exception as exc:  # noqa: BLE001
                last_error = f"duckdb query failed: {exc}"
                time.sleep(args.poll_interval)
                continue

            ok, msg = validate(rows)
            if ok:
                if args.require_no_serializer_drops:
                    if args.serializer_observation_seconds > 0:
                        print(f"observing serializer log for {args.serializer_observation_seconds}s")
                        time.sleep(args.serializer_observation_seconds)
                    drops = serializer_drops_since(log_path, log_start_offset, baseline_drop_total)
                    if drops:
                        print("FAIL: FileSerializer dropped events after smoke start")
                        for line in drops[:10]:
                            print("  " + line)
                        return 2
                activities = sorted({str(r.get("activity_type") or "").lower() for r in rows if r.get("activity_type")})
                distinct_paths = len({str(r.get("file_path") or "").lower() for r in rows if r.get("file_path")})
                print("PASS: captured recent file activity")
                print(f"  rows={len(rows)} distinct_paths={distinct_paths} activities={activities}")
                return 0

            last_error = msg
            remaining = int(deadline - time.time())
            print(f"waiting for expected file rows: {msg} ({remaining}s remaining)")
            time.sleep(args.poll_interval)

        print("FAIL: file parquet validation did not pass")
        if last_error:
            print(f"reason: {last_error}")
        return 2
    finally:
        if lintap_proc is not None:
            stop_process(lintap_proc)


if __name__ == "__main__":
    raise SystemExit(main())
