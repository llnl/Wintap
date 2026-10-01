# Build And Test

This is the canonical build, run, and troubleshooting guide for Wintap development.

For dated investigation notes, use:

- [`fedora-handoff-2026-06.md`](fedora-handoff-2026-06.md)
- [`linux-tcp-investigation-2026-06.md`](linux-tcp-investigation-2026-06.md)
- [`diagnostics/nesper-repro/README.md`](diagnostics/nesper-repro/README.md)

## Working Directory

The active Makefile and platform projects live in `wintap/wintap/`.

Run the commands below either:

- from the repo root with `make -C wintap/wintap ...`, or
- from inside `wintap/wintap` with plain `make ...`

Examples below assume you are already in `wintap/wintap` unless noted otherwise.

## Recommended Commands

Build everything:

```bash
make all
```

Build only .NET:

```bash
make build_dotnet
```

Build only eBPF tracers:

```bash
make build_ebpf
```

Run Lintap:

```bash
make run
```

Run with eBPF privileges:

```bash
sudo make run
```

Run host only:

```bash
make run-host-only
```

Run the MCP server directly:

```bash
make run-mcp
```

Print runtime paths and active flags:

```bash
make run-env
```

## Linux Build Outputs

For Linux development, the preferred model is:

- keep source in the repo
- load build output from a native filesystem
- keep runtime data under a separate data root

On host-shared filesystems such as `9p`, `virtiofs`, `vboxsf`, `cifs`, `smbfs`, `osxfs`, and other similar mounts, the Makefile automatically redirects Linux .NET outputs to:

```text
/tmp/lintap-build/wintap
```

The usual runtime data root is:

```text
/tmp/lintap-data
```

This avoids .NET apphost mmap failures and shared-mount runtime-codegen issues.

## Important Runtime Variables

- `WINTAP_DATA_ROOT`: runtime data directory
- `NATIVE_BUILD_ROOT`: native output root used on shared mounts
- `WINTAP_DISABLE_MCP`: disable MCP startup
- `WINTAP_DISABLE_DUCKDB_UI`: disable DuckDB UI startup
- `WINTAP_DISABLE_ETL`: disable ETL for isolation
- `WINTAP_DISABLE_SENSORS`: disable sensors for isolation
- `WINTAP_ENABLE_DIRECT_PARQUET`: bypass normal ETL/Esper enrichment and write direct Parquet
- `WINTAP_ENABLE_<SENSOR>_SENSOR`: explicit Linux per-sensor switches
- `WINTAP_SKIP_PROCESS_RESOLVE`
- `WINTAP_SKIP_PARENT_PROCESS_RESOLVE`
- `WINTAP_SKIP_PROCESS_REGISTER`
- `WINTAP_SKIP_ESPER_SEND`

## Common Linux Isolation Recipes

Host only:

```bash
make run-host-only
```

ETL off, sensors still enabled:

```bash
WINTAP_DISABLE_ETL=true make run
```

Sensors off, ETL still enabled:

```bash
WINTAP_DISABLE_SENSORS=true make run
```

Execve only:

```bash
WINTAP_DISABLE_ETL=true \
WINTAP_ENABLE_EXECVE_SENSOR=true \
WINTAP_ENABLE_CLONE_SENSOR=false \
WINTAP_ENABLE_EXIT_SENSOR=false \
WINTAP_ENABLE_NETWORK_SENSOR=false \
WINTAP_ENABLE_FILEOPS_SENSOR=false \
WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR=false \
make run
```

Direct Parquet process bring-up:

```bash
WINTAP_DISABLE_ETL=true \
WINTAP_ENABLE_DIRECT_PARQUET=true \
WINTAP_ENABLE_EXECVE_SENSOR=true \
make run
```

Direct Parquet bypasses Esper serializers and only writes payload fields that are
explicitly flattened by `DirectParquetSink`. SELinux events are currently intended
for the normal ETL path; direct-Parquet SELinux rows may omit SELinux-specific
payload fields until that flattening path is extended.

## Smoke Tests

See [`devtools/README.md`](devtools/README.md) for full details.

Typical examples:

```bash
python3 devtools/network_capture_smoke_test.py --data-root /tmp/lintap-data --timeout 240 --poll-interval 10
python3 devtools/process_capture_smoke_test.py --data-root /tmp/lintap-data --timeout 240 --poll-interval 10
python3 devtools/file_capture_smoke_test.py --data-root /tmp/lintap-data --timeout 240 --poll-interval 10
```

## 30-Minute Soak Test

Create a short-interval config:

```bash
export DATA_ROOT=/tmp/lintap-qa-30m-$(date +%s)
cat > /tmp/etlconfig-soak.json <<EOF
{
  "DataRoot": "${DATA_ROOT}",
  "DisableMCP": true,
  "DisableDuckDBUI": true,
  "WriteToParquet": true,
  "SerializationIntervalSec": 10
}
EOF
sudo env WINTAP_CONFIG_PATH=/tmp/etlconfig-soak.json make run
```

In another shell, run periodic smoke tests:

```bash
for i in 1 2 3 4 5; do
  python3 devtools/network_capture_smoke_test.py --data-root "$DATA_ROOT" --timeout 120 --poll-interval 5 --rounds 1
  python3 devtools/process_capture_smoke_test.py --data-root "$DATA_ROOT" --timeout 120 --poll-interval 5
  python3 devtools/file_capture_smoke_test.py --data-root "$DATA_ROOT" --timeout 120 --poll-interval 5
  sleep 360
done
```

## Backlog / OOM Protection

The ETL and Parquet paths support bounded queues and drop policies.

ETL serializer queues:

- `WINTAP_ETL_MAX_QUEUE_EVENTS=<N>`
- `WINTAP_ETL_MAX_QUEUE_EVENTS_<SERIALIZERNAME>=<N>`
- `WINTAP_ETL_QUEUE_DROP_POLICY=newest|oldest`
- `WINTAP_ETL_QUEUE_DROP_POLICY_<SERIALIZERNAME>=newest|oldest`

Parquet writer backlog:

- `WINTAP_PARQUET_MAX_BATCH_BACKLOG=<N>`
- `WINTAP_PARQUET_BACKLOG_DROP_POLICY=newest|oldest`

Direct Parquet backlog:

- `WINTAP_DIRECT_PARQUET_MAX_QUEUE_EVENTS=<N>`
- `WINTAP_DIRECT_PARQUET_QUEUE_DROP_POLICY=newest|oldest`

Drops increment `EventChannel.DroppedEventCount` and emit throttled warnings.

## Shared-Mount Troubleshooting

If `dotnet build` fails during `CreateAppHost` with `IOException: Invalid argument`, you are likely building on a filesystem that does not fully support the SDK's apphost mmap flow.

Key points:

- Prefer `make`, not `dotnet run`, on shared mounts.
- The Makefile auto-detects common shared mount types.
- On those mounts, it sets `UseAppHost=false` for the outer build and redirects output to native storage.
- `Directory.Build.props` honors `NativeBuildRoot` and `DISABLE_APPHOST`.

Example override:

```bash
make all DOTNET_BUILD_FLAGS='-p:UseAppHost=false'
```

Example custom native build root:

```bash
make all NATIVE_BUILD_ROOT=/tmp/my-lintap-build
```

## MCP Build Notes

`Lintap.csproj` builds the MCP server as a single-file executable.

When apphost is disabled for the outer Linux build, MCP publish is redirected to a native temporary directory first and then copied into the output `mcp/` directory.

Useful commands:

```bash
make run-mcp
make run-env
```

Optional temp override:

```bash
export MCP_PUBLISH_TMP=/tmp/lintap-mcp-temp
make all
```

## Troubleshooting Checklist

1. Confirm the active paths:

```bash
make run-env
```

2. Confirm the .NET SDK:

```bash
dotnet --info
```

3. Avoid `dotnet run` on shared mounts.

4. If eBPF build fails, verify kernel headers, `libbpf`, `clang`, and `llvm` are installed.

5. If `make run` crashes, compare:

- `make run-host-only`
- `WINTAP_DISABLE_ETL=true make run`
- `WINTAP_DISABLE_SENSORS=true make run`
- `make run-mcp`

6. If Linux telemetry behavior changes materially, update this file and keep detailed investigation history in the handoff or diagnostics docs.

## Current Linux Status Summary

Current working assumptions for Linux bring-up:

- native `/tmp` output is the preferred runtime path on shared mounts
- host-only mode is the fastest stability check
- per-sensor enable flags are the preferred way to isolate Linux sensors
- MCP and DuckDB UI should stay disabled during narrow bring-up unless you are explicitly testing them
- `CloneSensor` remains environment-sensitive on some Fedora setups and should be validated separately
