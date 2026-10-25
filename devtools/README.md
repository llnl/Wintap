# Developer Tools

This directory contains small utilities for validating and troubleshooting Wintap, Mactap, and Lintap deployments.

## Experimental short-lived attribution A/B rounds

`attribution_experiment.py` copies the installed package and a candidate build into
private roots and exercises manifest-recorded fork/file/exit cohorts. It never
installs or restarts the service. Requires native Linux/root and space for copied
binaries. Default: six rounds (old/candidate normal and missing-birth capture, then
candidate doubled-burst/restart). `--rounds` selects a subset; `--settle-seconds`
controls post-workload settling, not shutdown correctness. `fixed-legacy-exit`
substitutes a no-start exit object **only in a private copy**. Evidence is not overwritten.
`--experiment-batch-drain` enables an experimental 11s Esper-window wait **after
producer shutdown**; default runtime shutdown behavior remains unchanged. This
isolates final-batch loss from upstream drops, not a release-ready general drain API.
For a same-binary comparison, select `--rounds fixed-missing-birth,fixed-batch-drain`
without the global flag: only the latter enables the barrier. `--shutdown-timeout`
sets the observation deadline; forced termination is always recorded as a failed gate.

Candidate `WINTAP_EXPERIMENT_LIFECYCLE_SHADOW_PATH` enables bounded exit-only JSONL:
experimental ≤1s lifetime rule, weak role labels, numeric UID and clock/start evidence.
No benign verdicts, early role timeline, suppression, raw-schema change or deployment
approval is implied. Compare canonical inputs, unresolved rows, actual birth coverage
and conserved events—not just fewer orphan hashes. Evidence/analysis:
`../Wintap-Analytics/wiki/work/host-process-identity-patch/experiment_results.md`.

## Portable smoke run manifests and results dashboard

The named workload, process/file/network capture tests, clone trace/pipeline/package
validators and runtime-capability validator now accept `--manifest /path/run.json`.
Default: `./smoke-results/<test>-<uuid>.json`. Existing files are refused. The common
`smoke_manifest.py` records run UUID, test hostname/UTC interval, exact stimulus
selectors and success/failure results (including failed validation with no data).
Internal named-workload workers do not create independent manifests.

For automatic ride-along evidence, use a Python environment with `duckdb` and
pass `--smoke-data-root /var/log/lintap/data` (contains `raw_sensor`). All eight
families write typed parquet plus full manifest JSON into
`raw_sensor/raw_smoke_test/dayPK=YYYYMMDD/hourPK=HH/` with UTC publication partitions.
`WINTAP_DATA_ROOT` enables this too; `--no-smoke-parquet` opts out. Interactive
shells do not automatically inherit the service's environment file. Use a writable
smoke subtree and keep stimulus files outside the collector data/runtime roots.

Start/first-selectors/final are up to three immutable UUID/revision snapshots,
published via `.parquet.active`→`.parquet`. Existing transfer moves them alongside
telemetry; normal latency and source deletion are accepted. No uploader changes,
delivery acknowledgements, long-term spool or retry daemon. Missing DuckDB or export
errors warn and retain JSON without changing workload outcome. JSON/manual upload
remains optional. The analysis host need not be the test host; the app automatically
discovers parquet runs. The read-only dashboard lives in sibling Analytics:

```bash
python3 -m streamlit run streamlit/projects/SmokeTests/main.py
```

Run that command **from Wintap-Analytics**, after installing its app-local
`streamlit/projects/SmokeTests/requirements.txt`. Select analysis-local parquet and
data root (or `raw_sensor`) and optionally JSON paths/uploads. Host+time+PID/path/ports scope each run; event rows
do not themselves carry the smoke UUID. Run repeated tests sequentially to avoid
ambiguous overlaps. No legacy inference. See that app's README for VM→Mac examples.

## Named cross-domain stimulus (Linux, field-friendly Python)

UDP now uses independent unconnected and connected client/server workers/sockets,
with separate manifest cases, rather than allowing a connected Receive to satisfy
both phases. Existing canary limits remain stimulus-only; no collector is started.

## Actual-object network qualification (dev-time only)

On a designated idle Linux VM, build a reviewed CO-RE object and the observer:

```bash
make -C wintap/platform/linux/sensor/ebpf/tracers network_ops_tracer.bpf.o
cc -Wall -Wextra -Werror -O2 devtools/network_trace_runner.c -o /path/outside/git/network-trace-runner -lbpf -lelf -lz
python3 devtools/network_trace_smoke_test.py --runner /path/outside/git/network-trace-runner \
  --object wintap/platform/linux/sensor/ebpf/tracers/network_ops_tracer.bpf.o \
  --output /path/outside/git/fresh-network-qualification
```

This **attaches tracers**, so it is not a recurring canary and must not run on
active collection hosts. Noninteractive sudo must already be authorized; the
harness never changes sudo/security policies or collector services. It scopes the
object to the workload PID, requires operation hooks/readiness, checks TCP Accept
and UDP send/receive modes, zero-length/truncated datagrams, nonblocking/oversize
negatives, duplicate rows and emptied context maps, then detaches within 20 seconds.
The observer accepts at most 120 seconds. Evidence stays in the fresh VM-local output;
use `--baseline` only for strict comparison of an older object lacking the new
UDP-send return hook/map (it does not waive failed observation checks).

Passing this proves actual-object scope, **not** managed identity, normal ETL,
installed-package behavior, exact packet/byte conservation or release readiness.
Current core UDP bytes mean successful **protocol-function return**, not final
syscall success or requested length. TCP remains requested-entry/sampled. Per-socket
one-second send/connected-receive sampling stays enabled; peer-buffer UDP receives
remain unsampled. Wildcard non-loopback local addresses and socket-pointer reuse
need separate qualification; incomplete raw observations are not retroactively fixed.

### Field-friendly workload

With the collector **already running**, generate a tiny identifiable dataset:

```bash
python3 devtools/telemetry_smoke_workload.py --output /home/user/qa/smoke-001
```

Stdlib only, no root required, no collector configuration changes, no external
network traffic. Use a **fresh** directory outside collector data/runtime roots
and filtered paths such as `/tmp`; all workload writes are confined there.
The directory retains `manifest.json`, per-process evidence and Python exec
aliases; test files are removed by their lifecycle, not a broad cleanup command.

Cases use `wt_*` names (Linux comm ≤15 bytes), exec aliases and command-line case
labels. Match manifest PID/TID **and time**, file paths and socket endpoints too:
fork birth inherits its parent's name and resolver may normalize Python aliases.
Each invocation has a distinct run ID/output directory.

- Process: fork-only, fork+exec/image replacement, posix_spawn/exec, thread creation
  (negative process-Start case), and normal exits. `posix_spawn` does not guarantee
  a particular libc syscall implementation.
- File: create/open, write/read, file-backed mmap, close, delete, relative
  dirfd openat/unlinkat; extra rename/truncate probes. Current Linux normalized
  activities are Open/Read/Write/Close/Delete; mmap folds into Read.
- Network: IPv4 loopback TCP connect/accept/send/receive/disconnect, both endpoint
  processes; connected and unconnected UDP send/receive. `--ipv6` generates extra
  IPv6 activity but current Linux capture is not certified for IPv6.

For explicit legacy clone/clone3 process/thread, worker-thread fork, and vfork+exec
probes, build the optional existing native helper:

```bash
cc -O2 -pthread -o /home/user/qa/clone-helper devtools/clone_lifecycle_workload.c
python3 devtools/telemetry_smoke_workload.py --output /home/user/qa/smoke-002 \
  --clone-helper /home/user/qa/clone-helper
```

Only one native round runs; naming/extras are enabled by `WINTAP_SMOKE_NAMES=1`
inside this invocation, leaving existing default validation manifests unchanged.
Absent helper is an explicit skip; unsupported clone3 includes errno in the native
manifest. Supplied-but-broken helpers or failed operations return exit 1, with
results retained. `--hold` adjusts Python worker dwell (default 0.2 seconds).

**“generated” proves OS stimulus, not sensor capture.** Compare manifest operations
to existing process/file/network capture tests or query collected parquet after
normal aggregation/serialization/merge. Do not assert one row per syscall. Read
HOST RuntimeCapabilitiesJson for attach/filter evidence; Refresh requires rundown
timing, and HOST/SELinux/security events are not induced here. Workload regression:
`python3 devtools/test_telemetry_smoke_workload.py -v` (Linux).

## Clone Lifecycle Validation (Linux)

`clone_lifecycle_workload.c` produces a PID/TID manifest for 20 rounds of fork,
fork+exec, worker-thread fork, pthread, legacy clone thread, and clone3 process/thread.
Build with `cc -O2 -pthread -o workload clone_lifecycle_workload.c`.
`clone_trace_runner.c` attaches actual tracer objects; build with
`cc -O2 -o runner clone_trace_runner.c -lbpf`. Requires compiler/libbpf headers,
Linux eBPF privileges and a fresh output directory for each run.

```bash
sudo python3 validate_clone_trace.py --object /path/clone_core_tracer.bpf.o \
  --runner /path/runner --workload /path/workload --output /fresh/trace-run
```

Repeat with `clone_tracer.bpf.o`, then `--primary-only` to simulate absent
auxiliary hooks. Optional attach failures are logged; unsupported clone3 is
reported as a skip. The CO-RE path uses authoritative child pid/tgid; the fallback
uses best-effort clone/clone3 flags and can misclassify threads without those hooks.

`validate_clone_pipeline.py --dll /path/Lintap.dll --workload /path/workload
--output /fresh/pipeline-run` requires root and Python `duckdb`. It starts only
clone+exec, waits for both registrations, and checks direct-parquet runtime staging
output (ETL/registration bypassed). Successful fork+exec can generate **three**
Start observations (fork, exec entry, sched exec) sharing one PidHash; this harness
preserves them rather than asserting exactly two rows. Resolver ordering is tested
separately by the `clone-validation` xUnit category. This is not packaged/normal-ETL
acceptance or a cross-kernel compatibility guarantee.

## Network Capture Smoke Test

`network_capture_smoke_test.py` is an integration smoke test for the Lintap/Wintap network capture pipeline. It generates a small amount of outbound HTTP/HTTPS traffic plus a small UDP datagram, waits for parquet output, and queries the captured parquet files with DuckDB to confirm that recent outbound network records were collected.

The test validates the end-to-end path:

```text
generated internet traffic -> eBPF/network sensor -> ETL/parquet writer -> DuckDB query -> expected remote ports/IPs
```

### Requirements

- Lintap/Wintap is already running on the host where the test is executed (or use `--start-lintap`).
- Parquet output is enabled (ETL parquet or direct-parquet).
- `SerializationIntervalSec` / `DirectParquetFlushSeconds` is short enough for the selected timeout.
- Either the Python `duckdb` package is installed or the `duckdb` CLI is available on `PATH`.

### Usage

Run the test on the same host/VM where Lintap is collecting network data:

```bash
  uv run python devtools/network_capture_smoke_test.py \
    --data-root /tmp/lintap-smoke \
    --timeout 240 \
    --poll-interval 10
```

Optional: start Lintap in direct-parquet mode for this test (requires root):

```bash
 sudo uv run python devtools/network_capture_smoke_test.py \
    --start-lintap \
    --lintap-dll /tmp/lintap-build/wintap/bin/Debug/net10.0/Lintap.dll \
    --timeout 240 \
    --poll-interval 10
```

Optional stricter validation requires one of the resolved endpoint IPv4 addresses to appear in captured rows:

```bash
 uv run python devtools/network_capture_smoke_test.py \
    --data-root /tmp/lintap-smoke \
    --require-target-ip-match
```

Exact IP matching is disabled by default because CDN-backed endpoints may resolve or connect differently across attempts.

Note: in locked-down environments, HTTPS probes may fail (TLS intercept / egress restrictions). The smoke test will still pass if it can observe UDP capture, and will emit a warning if no TCP rows were observed.

### Example Passing Output

```text
collected network rows for remote ports 80/443:
  remote=104.20.23.154:80 protocol=TCP rows=4
  remote=104.20.23.154:443 protocol=TCP rows=4
  remote=104.16.124.96:443 protocol=TCP rows=3

PASS: captured recent outbound network records for the generated traffic.
Matched resolved target IPs: 104.16.124.96, 104.20.23.154
```

## Process Capture Smoke Test

`process_capture_smoke_test.py` is an integration smoke test for Linux process capture correctness. It generates several process creation variants (fork/exec, posix_spawn, execveat via fexecve, and short-lived children), waits for parquet output, then queries the parquet files with DuckDB to confirm parent PID/hash linkage and expected breadcrumbs.

It supports both schemas:

- ETL serializer parquet (e.g. `parquet/processserializer/*.parquet` with `ParentPid`/`ParentPidHash`)
- Direct-parquet bring-up mode (e.g. `Process_ParentPID`/`Process_ParentPidHash`)

The script probes the parquet schema first to avoid DuckDB binder errors when columns differ.

The test validates the end-to-end path:

```text
generated process activity -> eBPF process sensors -> parquet writer -> DuckDB query -> expected parent PID/hash (+ breadcrumbs)
```

Usage:

```bash
 uv run python devtools/process_capture_smoke_test.py \
    --data-root /var/log/lintap/data \
    --timeout 240 \
    --poll-interval 10
```

Optional: start Lintap in direct-parquet mode for this test (requires root):

```bash
 sudo uv run python devtools/process_capture_smoke_test.py \
    --start-lintap \
    --lintap-dll /tmp/lintap-build/wintap/bin/Debug/net10.0/Lintap.dll \
    --timeout 240 \
    --poll-interval 10
```

Optional: override the parquet root (defaults to `<data-root>/raw_sensor`):

```bash
 uv run python devtools/process_capture_smoke_test.py \
    --data-root /var/log/lintap/data \
    --parquet-root /var/log/lintap/data/raw_sensor
```

Optional stricter validation requires Stop events for both processes:

```bash
 uv run python devtools/process_capture_smoke_test.py --require-stop
```

Optional: increase the number of short-lived children (helps exercise parent attribution when /proc races occur):

```bash
 uv run python devtools/process_capture_smoke_test.py --short-lived-children 20
```

The captured local endpoint should show the host/VM's routable local address with ephemeral ports, for example:

```text
local=192.168.252.9:37804 -> remote=104.20.23.154:80 proto=TCP rows=2
```

## File Activity Smoke Test

### TCP endpoint normalization smoke

Normal-ETL `network_capture_smoke_test.py` now includes host-relative endpoint
confirmation by default. `--no-verify-endpoints` opts out explicitly; direct-mode
`--start-lintap` defaults to no normalization check (its schema is not normalized).
The dashboard keeps explicit opt-outs yellow rather than implying full confirmation.

To run only the endpoint cases, without Internet HTTP/DNS stimulus:

```bash
uv run --no-project --with duckdb python devtools/network_endpoint_smoke_test.py \
  --data-root /var/log/lintap/data --host-ip 192.168.252.47 --timeout 120
```

Omit `--host-ip` to choose the host's routed IPv4 interface. This must be an assigned
non-loopback address; private LAN addresses are fine. Do not use an external NAT
address that the host cannot bind. Both client and server connect via that address.

Cases: separate client/server PIDs, and one PID owning both socket ends. Require
Send **and** Recv at each end, stable process identity (distinct hashes for separate
processes), correct Local/Remote **IP-and-port pairs**, and preserved directed
SourcePort/DestinationPort. Same-IP/same-PID validation uses the directed ports to
avoid accepting receive rows accidentally swapped between socket roles. The new
provenance fields require a rebuilt sensor; old parquet cannot satisfy this gate.
TCP Accept coverage, receive-byte accuracy, IPv6 collection, and packet-level
completeness are separate gates, not silently certified here.

The decorated standalone test publishes `network-endpoints` manifests/parquet to
the SmokeTests dashboard. The normal network smoke combines these selectors with
its outbound checks. An incomplete/unsupported capture fails the harness rather
than turning successful workload generation into a capture PASS.


`file_capture_smoke_test.py` is an integration smoke test for Linux file activity capture correctness. It generates a small amount of local file activity (create/write/read/delete), waits for parquet output, then queries the parquet files with DuckDB to confirm file-path rows were collected.

Usage:

```bash
 uv run python devtools/file_capture_smoke_test.py \
    --data-root /var/log/lintap/data \
    --timeout 240 \
    --poll-interval 10
```

Optional: start Lintap in direct-parquet mode for this test (requires root):

```bash
 sudo uv run python devtools/file_capture_smoke_test.py \
    --start-lintap \
    --lintap-dll /tmp/lintap-build/wintap/bin/Debug/net10.0/Lintap.dll \
    --timeout 240 \
    --poll-interval 10
```

## 30-Minute Soak Test (Network + Process)

This is a practical validation run for long-running deployments: keep Lintap running for 30 minutes, run both smoke tests 5 times during that window, then produce a compact QA summary from parquet and logs.

Example (foreground run):

```bash
export DATA_ROOT=/tmp/lintap-qa-30m-$(date +%s)
cat > /tmp/etlconfig-soak.json <<EOF
{
  "DataRoot": "${DATA_ROOT}",
  "DisableMCP": true,
  "DisableDuckDBUI": true,
  "DisableETL": false,
  "WriteToParquet": true,
  "SerializationIntervalSec": 10
}
EOF
sudo env WINTAP_CONFIG_PATH=/tmp/etlconfig-soak.json dotnet /tmp/lintap-build/wintap/bin/Debug/net10.0/Lintap.dll
```

In another shell, run 5 rounds (every ~6 minutes):

```bash
for i in 1 2 3 4 5; do
  uv run python devtools/network_capture_smoke_test.py --data-root "$DATA_ROOT" --timeout 120 --poll-interval 5 --rounds 1
  uv run python devtools/process_capture_smoke_test.py --data-root "$DATA_ROOT" --timeout 120 --poll-interval 5
  uv run python devtools/file_capture_smoke_test.py --data-root "$DATA_ROOT" --timeout 120 --poll-interval 5
  sleep 360
done
```

QA summaries (DuckDB CLI):

```bash
duckdb -json -c "SELECT COUNT(*) AS tcp_rows, COUNT(DISTINCT RemotePort) AS distinct_remote_ports FROM read_parquet('$DATA_ROOT/raw_sensor/tcpconnection/**/*.parquet');"
duckdb -json -c "SELECT COUNT(*) AS udp_rows, COUNT(DISTINCT RemotePort) AS distinct_remote_ports FROM read_parquet('$DATA_ROOT/raw_sensor/udppacket/**/*.parquet');"
duckdb -json -c "SELECT COUNT(*) AS process_rows, COUNT(DISTINCT PID) AS distinct_pids, COUNT(*) FILTER (WHERE PidHash IS NULL OR PidHash='') AS missing_pid_hash_rows, COUNT(*) FILTER (WHERE ParentPid IS NOT NULL AND ParentPid>0 AND (ParentPidHash IS NULL OR ParentPidHash='')) AS missing_parent_pid_hash_rows FROM read_parquet('$DATA_ROOT/raw_sensor/process/**/*.parquet');"
```

Backlog / drop signals to check:

- Look for `in-memory backlog limit reached` (per-serializer)
- Look for `ParquetWriter backlog limit reached`
- Track `EventChannel.DroppedEventCount` (increments when drops occur)

## Log Message Semantic Clustering

`log_cluster.py` uses NLP (sentence transformers) to cluster log messages by semantic similarity rather than exact string matching. Perfect for analyzing large log files and identifying recurring issues across TeleTap components (Wintap, Mactap, Lintap).

## Features

- **Semantic grouping**: Groups messages by meaning, not just word matching
- **Log level filtering**: Focus on specific log levels (Error, Warn, Info) or all messages
- **Automatic normalization**: Strips out numbers, paths, and type names
- **Statistical summary**: Shows cluster size, percentage of total logs, and compression ratio
- **Adjustable clustering**: Control granularity with distance threshold parameter

## Installation

```bash
# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Analyze errors only (default)
python log_cluster.py wintap.log

# Analyze warnings
python log_cluster.py wintap.log 0.7 Warn

# Analyze info messages
python log_cluster.py wintap.log 0.7 Info

# Analyze all log levels
python log_cluster.py wintap.log 0.7 all
```

### Advanced Usage

```bash
# Tighter clustering (more specific groups)
python log_cluster.py wintap.log 0.5 Error

# Looser clustering (broader groups)
python log_cluster.py wintap.log 0.9 Error

# Custom threshold with all messages
python log_cluster.py wintap.log 0.6 all
```

## Parameters

1. **log_file** (required): Path to your log file
2. **distance_threshold** (optional, default: 0.7): Controls clustering granularity
   - `0.5` - Tight clusters (very similar messages only)
   - `0.7` - Balanced (recommended)
   - `0.9` - Loose clusters (broadly similar messages)
3. **log_level** (optional, default: Error): Filter by log level
   - `Error` - Error messages only (default)
   - `Warn` - Warning messages only
   - `Info` - Info messages only
   - `all` - No filtering, include all levels

## Example Output

```
Reading log file: wintap.log
Filtering to level: Error
Parsed 156 log messages
Found 23 unique message templates
Loading model: all-MiniLM-L6-v2
Generating embeddings...
Clustering with distance threshold: 0.7

================================================================================
SEMANTIC LOG MESSAGE CLUSTERS
================================================================================

Total clusters: 8
Total messages: 156
Compression ratio: 19.5:1

────────────────────────────────────────────────────────────────────────────────
Cluster 1/8 (Label: 0)
Total occurrences: 89 (57.1%)
Unique variants: 3
────────────────────────────────────────────────────────────────────────────────
    45 | Error creating TcpConnection object on pid: NUM,  exception: SYSTYPE
    32 | Error loading plugin assemblies: No service for type 'TYPE' has been registered.
    12 | Error reading ETLConfig from disk, using default values
```

## Log Format Support

The tool expects logs in this format:
```
MM/DD/YYYY HH:MM:SS [Level] [Source]: Message
```

Example:
```
11/13/2025 10:00:33 [Info]  [CacheManager..ctor]:   Cache Manager is starting up
11/13/2025 10:00:33 [Error] [PluginManager.LoadPluginAssemblies]:   Error loading plugin
```

## How It Works

1. **Parsing**: Extracts log messages and filters by level
2. **Normalization**: Replaces numbers, paths, and type names with placeholders
3. **Embedding**: Uses sentence transformers to convert messages to semantic vectors
4. **Clustering**: Groups semantically similar messages using hierarchical clustering
5. **Analysis**: Shows clusters ranked by frequency with statistics

## Tips

- Start with default settings (Error level, 0.7 threshold)
- If clusters are too broad, decrease threshold (try 0.5)
- If too many small clusters, increase threshold (try 0.9)
- Use `all` level filter to see patterns across all log types
- First run downloads the ML model (~80MB) - subsequent runs are faster

## Troubleshooting

**No messages found**: Check that your log level exists in the file. Try `all` to see everything.

**Out of memory**: Process logs in batches or use a machine with more RAM.

**Slow performance**: First run downloads the model. Subsequent runs are much faster.

## Requirements

- Python 3.8+
- ~1GB RAM for typical log files
- Internet connection (first run only, to download ML model)
### Durable runtime capability receipts

`validate_clone_package.py` tests an idle installed `lintap.service` on a
designated disposable host with normal ETL and untouched default Clone=true.
It checks the 20-round manifest plus bounded 100-round churn, HOST publication,
restart and explicit opt-out; it temporarily edits Clone only and restores the
environment in `finally`. Requires Python duckdb, root and the compiled workload.
Allow two full merge intervals (default 320 seconds each); do not run concurrently
with other app harnesses. `clone_lifecycle_workload.c --rounds=N` supports 1–1000
rounds (default 20); large runs retain thread stacks and are not an unbounded stress tool.

```bash
sudo /native/qa-venv/bin/python validate_clone_package.py --workload /native/clone-workload --output /fresh/package-qa
```

`validate_runtime_capabilities.py` validates startup JSON in published HOST parquet
against the identical `RUNTIME_CAPABILITIES` log record, then checks a restart
against the same root and global sensor disablement. Requires Linux/root and
Python `duckdb`; use a fresh output directory. Run sequentially with other app
harnesses (the API listener may bind a fixed port despite ASPNETCORE_URLS).

```bash
sudo python validate_runtime_capabilities.py --dll /native/build/Lintap.dll --output /fresh/receipt-run
```

Optional `--fallback-dll /separately/staged/fallback/Lintap.dll` verifies the
tracepoint Clone tier and clone3 hook. Stage a separate app payload without
CO-RE objects; never remove objects from the installed/running app for this test.
This is source-build validation, not package or downstream DBT acceptance.
