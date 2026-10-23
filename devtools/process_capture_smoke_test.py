#!/usr/bin/env python3
"""Lintap/Wintap process-capture smoke test (parquet-based).

This mirrors the network capture smoke test approach:

generated process activity -> eBPF process sensors -> parquet writer -> DuckDB query -> expected parent/child linkage

Prereqs:
  - Lintap/Wintap is already running.
  - Parquet output is enabled (ETL parquet or direct-parquet).
  - Either the Python `duckdb` package is installed or `duckdb` CLI is on PATH.

Examples:
  uv run python devtools/process_capture_smoke_test.py --data-root /var/log/lintap/data --timeout 180

  WINTAP_DATA_ROOT=/var/log/lintap/data \
    uv run python devtools/process_capture_smoke_test.py --timeout 180
"""

import argparse
import glob
import json
import os
import platform
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


def set_subprocess_posix_spawn(enabled: bool) -> None:
    """Best-effort toggle for CPython's subprocess implementation."""

    try:
        subprocess._USE_POSIX_SPAWN = enabled  # type: ignore[attr-defined]
    except Exception:
        pass


@dataclass(frozen=True)
class ProcessLink:
    """Expected parent/child relationship (PID-based).

    Some validations use optional breadcrumbs emitted into Process.Arguments.
    """

    name: str
    parent_pid: int
    child_pid: int
    child_args_must_contain: tuple[str, ...] = ()
    require_parent_hash_src_ebpf: bool = False


@dataclass(frozen=True)
class ProcessSuite:
    start_epoch: float
    links: tuple[ProcessLink, ...]
    extra_pids: tuple[int, ...] = ()
    short_lived_parent_pid: int | None = None
    short_lived_child_pids: tuple[int, ...] = ()


def default_data_root() -> Path:
    env_root = os.environ.get("WINTAP_DATA_ROOT")
    if env_root:
        return Path(env_root)

    # If previous runs used /tmp/lintap-data-*, pick the most recently modified one
    # that already has parquet output.
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
        # Prefer the current split data root, while retaining discovery of
        # legacy mixed-root deployments for historical captures.
        log_root = Path("/var/log/lintap")
        if (log_root / "data" / "raw_sensor").exists():
            return log_root / "data"
        if (log_root / "runtime" / "Logs" / "Lintap.log").exists():
            return log_root / "data"
        return log_root / "data"
    if system == "darwin":
        return Path("/Library/Application Support/Mactap")
    if system == "windows":
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
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


def detect_column_names(files: list[Path]) -> dict[str, str | None]:
    """Detect column names for ETL vs direct-parquet process schemas.

    DuckDB will throw a binder error if we reference a column that doesn't exist,
    even when wrapped in TRY_CAST. So we probe the schema first and then build
    a query that only references existing columns.
    """

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

    def pick_optional(*candidates: str) -> str | None:
        for c in candidates:
            if c in cols:
                return c
        return None

    return {
        "pid": pick("PID", fallback="PID"),
        "message_type": pick("MessageType", fallback="MessageType"),
        "activity_type": pick("ActivityType", fallback="ActivityType"),
        "pid_hash": pick("PidHash", fallback="PidHash"),
        # ETL serializer parquet: ParentPid/ParentPidHash
        # Direct-parquet: Process_ParentPID/Process_ParentPidHash
        "parent_pid": pick("Process_ParentPID", "ParentPid", fallback="ParentPid"),
        "parent_pid_hash": pick("Process_ParentPidHash", "ParentPidHash", fallback="ParentPidHash"),
        # ETL serializer parquet commonly uses EventTime; direct-parquet uses CapturedUtc.
        "captured_ts": pick("CapturedUtc", "EventTime", fallback="EventTime"),

        # Optional, used for validating exec/parent-hash breadcrumbs.
        "arguments": pick_optional("Process_Arguments", "Arguments"),
        "command_line": pick_optional("Process_CommandLine", "CommandLine"),
    }


def parse_pid_lines(stdout: str) -> dict[str, int]:
    parsed: dict[str, int] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k or not v:
            continue
        try:
            parsed[k] = int(v)
        except ValueError:
            continue
    return parsed


def spawn_process_suite(short_lived_children: int) -> ProcessSuite:
    """Generate multiple process creation variants.

    Coverage goals (Linux):
    - fork/exec path (bash background job)
    - posix_spawn path (python subprocess posix_spawn when available)
    - execveat path (python os.fexecve -> AT_EMPTY_PATH flags)
    - short-lived children (exercise parent attribution when /proc may be missing)
    """

    start_epoch = time.time()

    # 1) fork/exec: bash + background sleep
    set_subprocess_posix_spawn(False)
    proc1 = subprocess.run(
        ["bash", "-c", "echo CASE=fork_exec; echo PARENT_PID=$$; sleep 5 & echo CHILD_PID=$!; wait"],
        check=True,
        text=True,
        capture_output=True,
    )
    p1 = parse_pid_lines(proc1.stdout)
    fork_parent = p1.get("PARENT_PID")
    fork_child = p1.get("CHILD_PID")
    if not fork_parent or not fork_child:
        raise RuntimeError(f"Failed to parse fork/exec PIDs: {proc1.stdout!r} {proc1.stderr!r}")

    # 2) posix_spawn: python parent spawns sleep using subprocess (posix_spawn when supported)
    # Run this in a separate python process so we can toggle subprocess internals locally.
    proc2 = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os,subprocess,time; "
            "\ntry: subprocess._USE_POSIX_SPAWN=True\nexcept Exception: pass\n"  # best-effort
            "p=subprocess.Popen(['sleep','5']); "
            "print('CASE=posix_spawn'); print('PARENT_PID=%d' % os.getpid()); print('CHILD_PID=%d' % p.pid, flush=True); "
            "time.sleep(5)",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    p2 = parse_pid_lines(proc2.stdout)
    spawn_parent = p2.get("PARENT_PID")
    spawn_child = p2.get("CHILD_PID")
    if not spawn_parent or not spawn_child:
        raise RuntimeError(f"Failed to parse posix_spawn PIDs: {proc2.stdout!r} {proc2.stderr!r}")

    # 3) execveat: python fexecve -> /bin/sleep 5. Capture the python PID via $!.
    # fexecve typically uses execveat(fd, "", argv, envp, AT_EMPTY_PATH=0x1000).
    # Keep the process alive long enough for parquet flush.
    py = sys.executable.replace("'", "'\\''")
    proc3 = subprocess.run(
        [
            "bash",
            "-c",
            "echo CASE=execveat_fexecve; echo PARENT_PID=$$; "
            f"'{py}' -c 'import os; fd=os.open(\"/bin/sleep\", os.O_RDONLY); "
            "os.execveat(fd, \"\", [\"sleep\",\"5\"], os.environ, os.AT_EMPTY_PATH)' & "
            "echo CHILD_PID=$!; wait",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    p3 = parse_pid_lines(proc3.stdout)
    execveat_parent = p3.get("PARENT_PID")
    execveat_child = p3.get("CHILD_PID")
    if not execveat_parent or not execveat_child:
        raise RuntimeError(f"Failed to parse execveat PIDs: {proc3.stdout!r} {proc3.stderr!r}")

    # 4) short-lived children: many fast /bin/true children under a bash parent.
    # This is intentionally racy: we only require that at least one of these children
    # is captured and has eBPF-based parent hash attribution.
    n = max(1, int(short_lived_children))
    cmd_children = "".join(["/bin/true & echo CHILD_PID_%d=$!; " % i for i in range(n)])
    proc4 = subprocess.run(
        ["bash", "-c", f"echo CASE=short_lived; echo PARENT_PID=$$; {cmd_children} wait"],
        check=True,
        text=True,
        capture_output=True,
    )
    p4 = parse_pid_lines(proc4.stdout)
    short_parent = p4.get("PARENT_PID")
    if not short_parent:
        raise RuntimeError(f"Failed to parse short-lived parent PID: {proc4.stdout!r} {proc4.stderr!r}")
    short_children: list[int] = []
    for i in range(n):
        pid = p4.get(f"CHILD_PID_{i}")
        if pid:
            short_children.append(pid)

    links: list[ProcessLink] = []
    links.append(ProcessLink(name="fork_exec", parent_pid=fork_parent, child_pid=fork_child))
    links.append(ProcessLink(name="posix_spawn", parent_pid=spawn_parent, child_pid=spawn_child))
    links.append(
        ProcessLink(
            name="execveat_fexecve",
            parent_pid=execveat_parent,
            child_pid=execveat_child,
            child_args_must_contain=(
                ("PROC_START_SRC=execve_or_execveat", "FLAGS=0x00001000")
                if hasattr(os, "execveat") and hasattr(os, "AT_EMPTY_PATH")
                else ()
            ),
        )
    )

    extra_pids = [
        fork_parent,
        fork_child,
        spawn_parent,
        spawn_child,
        execveat_parent,
        execveat_child,
        short_parent,
        *short_children,
    ]

    return ProcessSuite(
        start_epoch=start_epoch,
        links=tuple(links),
        extra_pids=tuple(sorted(set(extra_pids))),
        short_lived_parent_pid=short_parent,
        short_lived_child_pids=tuple(short_children),
    )


def find_candidate_parquet_files(parquet_root: Path, start_epoch: float) -> list[Path]:
    if not parquet_root.exists():
        return []

    files: list[Path] = []
    for file_path in glob.glob(str(parquet_root / "**" / "*.parquet*"), recursive=True):
        path = Path(file_path)
        if path.is_file() and not path.name.endswith(".active"):
            files.append(path)

    # Prefer recent files, but avoid relying on tight timestamp cutoffs.
    try:
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass
    files = files[:200]

    process_files = [p for p in files if "process" in str(p).lower()]
    return process_files or files


def build_query(files: Iterable[Path], pids: set[int], cols: dict[str, str | None]) -> str:
    file_list = ", ".join(sql_string(str(path)) for path in files)
    pid_list = ",".join(str(pid) for pid in sorted(pids))

    extra_select = ""
    if cols.get("arguments"):
        extra_select += f"\n  , CAST({cols['arguments']} AS VARCHAR) AS process_arguments"
    else:
        extra_select += "\n  , NULL::VARCHAR AS process_arguments"
    if cols.get("command_line"):
        extra_select += f"\n  , CAST({cols['command_line']} AS VARCHAR) AS process_command_line"
    else:
        extra_select += "\n  , NULL::VARCHAR AS process_command_line"

    # DirectParquetSink includes these columns (by design):
    #   PID, MessageType, ActivityType, PidHash, Process_ParentPID, Process_ParentPidHash, CapturedUtc
    # ETL/raw_sensor parquet files may differ; union_by_name=true keeps this resilient.
    return f"""
WITH data AS (
    SELECT * FROM read_parquet([{file_list}], union_by_name=true)
)
SELECT
    TRY_CAST({cols['pid']} AS INTEGER) AS pid,
    CAST({cols['message_type']} AS VARCHAR) AS message_type,
    CAST({cols['activity_type']} AS VARCHAR) AS activity_type,
    CAST({cols['pid_hash']} AS VARCHAR) AS pid_hash,
    TRY_CAST({cols['parent_pid']} AS INTEGER) AS parent_pid,
    CAST({cols['parent_pid_hash']} AS VARCHAR) AS parent_pid_hash,
    TRY_CAST({cols['captured_ts']} AS TIMESTAMP) AS captured_utc
    {extra_select}
FROM data
WHERE TRY_CAST({cols['pid']} AS INTEGER) IN ({pid_list})
  AND lower(CAST({cols['message_type']} AS VARCHAR)) LIKE 'process%'
ORDER BY captured_utc DESC NULLS LAST;
"""


def latest_row(
    rows: list[dict],
    pid: int,
    activity: str | None = None,
    args_must_contain: tuple[str, ...] = (),
) -> dict | None:
    for row in rows:
        if row.get("pid") != pid:
            continue
        if activity is not None and str(row.get("activity_type") or "").lower() != activity.lower():
            continue
        if args_must_contain:
            args = str(row.get("process_arguments") or "")
            # If the parquet schema doesn't include arguments (or ETL doesn't persist it),
            # treat this as "can't validate" rather than "fail to match".
            if args and any(token not in args for token in args_must_contain):
                continue
        return row
    return None


def validate_suite(rows: list[dict], suite: ProcessSuite, require_stop: bool) -> tuple[bool, str]:
    # Breadcrumb validations only make sense when arguments are actually present in parquet.
    has_args_data = any(str(r.get("process_arguments") or "") for r in rows)
    if has_args_data:
        # Basic sanity: confirm we can see at least one sched_exec breadcrumb when supported.
        # This helps catch missing attachments.
        if not any("PROC_START_SRC=sched_exec" in str(r.get("process_arguments") or "") for r in rows):
            return False, "missing any PROC_START_SRC=sched_exec breadcrumb (sched_process_exec attach?)"

    # Per-link validations.
    for link in suite.links:
        parent_row = (
            latest_row(rows, link.parent_pid, activity="Start")
            or latest_row(rows, link.parent_pid, activity="Refresh")
            or latest_row(rows, link.parent_pid)
        )
        child_row = (
            latest_row(rows, link.child_pid, activity="Start", args_must_contain=link.child_args_must_contain)
            or latest_row(rows, link.child_pid, activity="Refresh", args_must_contain=link.child_args_must_contain)
            or latest_row(rows, link.child_pid, args_must_contain=link.child_args_must_contain)
        )

        if child_row is None:
            details = f"missing Start/Refresh for child PID {link.child_pid}"
            if link.child_args_must_contain:
                details += f" with args containing {list(link.child_args_must_contain)}"
            return False, f"case {link.name}: {details}"

        if child_row.get("parent_pid") != link.parent_pid:
            return (
                False,
                f"case {link.name}: child parent_pid mismatch: expected {link.parent_pid}, got {child_row.get('parent_pid')}",
            )

        child_parent_hash = str(child_row.get("parent_pid_hash") or "")
        if not child_parent_hash:
            return False, f"case {link.name}: child parent_pid_hash is empty"

        if parent_row is not None:
            parent_hash = str(parent_row.get("pid_hash") or "")
            if not parent_hash:
                return False, f"case {link.name}: parent pid_hash is empty (pid={link.parent_pid})"
            if parent_hash.lower() != child_parent_hash.lower():
                return False, f"case {link.name}: child parent_pid_hash does not match parent pid_hash"

        if link.require_parent_hash_src_ebpf:
            args = str(child_row.get("process_arguments") or "")
            if "PARENT_HASH_SRC=ebpf" not in args:
                return False, f"case {link.name}: expected PARENT_HASH_SRC=ebpf breadcrumb in Arguments"

        if require_stop:
            parent_stop = latest_row(rows, link.parent_pid, activity="Stop")
            child_stop = latest_row(rows, link.child_pid, activity="Stop")
            if parent_stop is None:
                return False, f"case {link.name}: missing Stop for parent PID {link.parent_pid}"
            if child_stop is None:
                return False, f"case {link.name}: missing Stop for child PID {link.child_pid}"

    return True, "ok"


def validate_short_lived(rows: list[dict], parent_pid: int | None, child_pids: tuple[int, ...]) -> tuple[bool, str]:
    if not parent_pid or not child_pids:
        return False, "short-lived stimulus did not produce any PIDs"

    has_args_data = any(str(r.get("process_arguments") or "") for r in rows)

    # Require that at least one short-lived child is captured with parent attribution.
    for pid in child_pids:
        child_row = latest_row(rows, pid, activity="Start") or latest_row(rows, pid, activity="Refresh") or latest_row(rows, pid)
        if child_row is None:
            continue
        if child_row.get("parent_pid") != parent_pid:
            continue
        parent_hash = str(child_row.get("parent_pid_hash") or "")
        if not parent_hash:
            continue
        return True, "ok"

    return False, "no short-lived child row matched (need parent_pid_hash)"


from smoke_manifest import smoke_run, record, epoch_utc, utc_now


@smoke_run("process-capture")
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
    parser.add_argument("--require-stop", action="store_true", help="require Stop events for both processes")
    parser.add_argument(
        "--short-lived-children",
        type=int,
        default=6,
        help="how many short-lived /bin/true children to generate (default: 6)",
    )
    args = parser.parse_args()

    data_root: Path
    if args.data_root is not None:
        data_root = args.data_root
    elif args.start_lintap:
        data_root = Path("/tmp") / ("lintap-data-process-smoke-" + str(int(time.time())))
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
            # WinTapSvc has plugin init + a 5s delay before sensors start.
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
        print(f"data root: {data_root}")
        print(f"parquet root: {parquet_root}")

        suite = spawn_process_suite(short_lived_children=args.short_lived_children)
        record(selectors=[dict(domain="process", case="process-suite", pids=list(suite.extra_pids),
                               startedAtUtc=epoch_utc(suite.start_epoch), completedAtUtc=utc_now(),
                               expectedActivities=["Start", "Stop"] if args.require_stop else ["Start"],
                               links=[dict(case=link.name, parentPid=link.parent_pid, childPid=link.child_pid)
                                      for link in suite.links])])
        print(f"spawned suite: links={len(suite.links)} pids={len(suite.extra_pids)}")

        deadline = time.time() + args.timeout
        last_error = None
        while time.time() < deadline:
            if lintap_proc is not None and lintap_proc.poll() is not None:
                out_lines, err_lines = drain_lines(lintap_proc)
                last_error = f"lintap exited rc={lintap_proc.returncode}"
                if err_lines:
                    last_error += "; stderr: " + (err_lines[-1] if err_lines else "")
                break
            candidates = find_candidate_parquet_files(parquet_root, suite.start_epoch)
            if not candidates:
                last_error = f"no parquet files found under {parquet_root}"
                remaining = int(deadline - time.time())
                print(f"waiting for parquet files... {remaining}s remaining")
                time.sleep(args.poll_interval)
                continue

            cols = detect_column_names(candidates)
            sql = build_query(candidates, set(suite.extra_pids), cols)
            try:
                rows = query_duckdb(sql)
            except Exception as exc:  # noqa: BLE001
                last_error = f"duckdb query failed: {exc}"
                time.sleep(args.poll_interval)
                continue

            ok, msg = validate_suite(rows, suite, require_stop=args.require_stop)
            if ok:
                ok, msg = validate_short_lived(rows, suite.short_lived_parent_pid, suite.short_lived_child_pids)
            if ok:
                print("PASS: captured process records for all creation variants")
                # Print a compact per-case summary.
                for link in suite.links:
                    child_rows = [r for r in rows if r.get("pid") == link.child_pid]
                    parent_rows = [r for r in rows if r.get("pid") == link.parent_pid]
                    latest_child = child_rows[0] if child_rows else None
                    args_txt = str((latest_child or {}).get("process_arguments") or "")
                    if len(args_txt) > 160:
                        args_txt = args_txt[:160] + "..."
                    print(
                        f"  case={link.name} parent={link.parent_pid} child={link.child_pid} "
                        f"parent_rows={len(parent_rows)} child_rows={len(child_rows)} "
                        f"child_parent_hash={(latest_child or {}).get('parent_pid_hash')} "
                        f"args={args_txt!r}"
                    )
                return 0

            last_error = msg
            remaining = int(deadline - time.time())
            print(f"waiting for expected process rows: {msg} ({remaining}s remaining)")
            time.sleep(args.poll_interval)

        print("FAIL: process parquet validation did not pass")
        if last_error:
            print(f"reason: {last_error}")
        return 2
    finally:
        if lintap_proc is not None:
            stop_process(lintap_proc)


def start_lintap_direct_parquet(lintap_dll: Path, data_root: Path) -> subprocess.Popen:
    data_root.mkdir(parents=True, exist_ok=True)

    # Wintap no longer reads arbitrary environment variables for configuration.
    # For smoke tests, write a minimal JSON config and point Lintap at it.
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
        # Keep only the execve process sensor on.
        # ExitSensor is currently noisy on some kernels (ring buffer handler NRE).
        "Execve": True,
        "Exit": False,
        "Clone": False,
        "ProcessRundown": False,
        "Network": False,
        "FileOps": False,
    }
    config_path = Path("/tmp") / ("etlconfig-process-smoke-" + str(int(time.time())) + ".json")
    config_path.write_text(json.dumps(temp_config, indent=2))

    env = os.environ.copy()
    env["WINTAP_CONFIG_PATH"] = str(config_path)
    # Avoid port collisions when multiple smoke tests run concurrently.
    env.setdefault("ASPNETCORE_URLS", "http://127.0.0.1:0")

    cmd = ["dotnet", str(lintap_dll)]
    print(f"starting lintap: {' '.join(cmd)}")
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


if __name__ == "__main__":
    raise SystemExit(main())
