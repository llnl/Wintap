"""Optional DuckDB export of smoke evidence into the existing durable-data tree.

No uploader, sensor, daemon, delivery acknowledgement or long-term spool required.
JSON remains the stdlib fallback when DuckDB or the destination is unavailable.
"""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re


def manifest_text(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def publish(value, root, revision, phase, published_at=None):
    import duckdb  # Optional: ordinary smoke workloads remain stdlib-only.

    published_at = published_at or dt.datetime.now(dt.timezone.utc)
    published_at = published_at.astimezone(dt.timezone.utc)
    text = manifest_text(value)
    if len(text.encode()) > 4 * 1024 * 1024:
        raise ValueError("Smoke manifest exceeds 4 MiB; retain JSON and reduce report size")
    host = value["host"]
    safe_host = re.sub(r"[^a-zA-Z0-9_.-]", "_", host["hostname"])[:100] or "host"
    run_id = str(value["runId"])
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", run_id):
        raise ValueError("Unsafe run ID")
    directory = (Path(root).expanduser() / "raw_sensor" / "raw_smoke_test" /
                 f"dayPK={published_at:%Y%m%d}" / f"hourPK={published_at:%H}")
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(text.encode()).hexdigest()
    # Hash suffix permits identical retry, and exposes conflicting same-revision
    # records to readers rather than overwriting an already transferred object.
    target = directory / f"{safe_host}+raw_smoke_test+{run_id}+{revision}+{digest[:16]}.parquet"
    if target.exists():
        return target
    temporary = target.with_suffix(".parquet.active")
    values = [1, value["smokeManifestVersion"], run_id, value["test"], revision,
              host["hostname"], host.get("hostId"), host.get("bootId"),
              value["startedAtUtc"], value.get("completedAtUtc"), published_at.isoformat(),
              phase, value.get("status", "running"), value.get("exitCode"),
              bool(value.get("stimulusOnly")), text, digest]
    with duckdb.connect(":memory:") as con:
        con.execute("SET TimeZone='UTC'")
        con.execute("""CREATE TABLE evidence (
            schema_version INTEGER, manifest_version INTEGER, run_id VARCHAR,
            test_name VARCHAR, revision INTEGER, hostname VARCHAR, host_id VARCHAR,
            boot_id VARCHAR, started_at_utc TIMESTAMPTZ, completed_at_utc TIMESTAMPTZ,
            published_at_utc TIMESTAMPTZ, phase VARCHAR, outcome VARCHAR,
            exit_code INTEGER, stimulus_only BOOLEAN, manifest_json VARCHAR,
            manifest_sha256 VARCHAR)""")
        con.execute("INSERT INTO evidence VALUES (" + ",".join("?" for _ in values) + ")", values)
        escaped = str(temporary).replace("'", "''")
        try:
            con.execute(f"COPY evidence TO '{escaped}' (FORMAT PARQUET, COMPRESSION ZSTD)")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    return target
