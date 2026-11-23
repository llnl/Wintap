# Focused Linux sensor tests

`Lintap.Tests` targets `net10.0` and references the actual Linux assembly. It does
not retarget, move, or replace `Wintap.Tests`. Existing central Test SDK/xUnit pins
are reused; the new project has its own lockfile.

## sfx-01 — executable-name fallback and normal-ETL projection

Synthetic tests cover exec/clone metadata selection, rundown messages, procfs
link-reading failures, deleted targets, executable names containing spaces, a
legitimate executable named `exe`, and selected-name preservation through the
normal process serializer/Save queue and Parquet serialization. The serializer
constructor is bypassed to avoid Esper, host inventory, timers, and collectors.
Injected denial/exit-race controls do not certify real procfs permission behavior.
Non-Linux projection controls exercise the existing path/lowercase branch; they
are not Windows runtime acceptance. No eBPF program is loaded or attached.

Run from the repository root with SDK **10.0.402** and an explicit local scratch
root. On the designated development system use `/data/lintap-compactor/sensor-fixes/`:

```sh
SDK="$HOME/.dotnet/wintap-sdk-10.0.402/dotnet"
RUN_ROOT="/data/lintap-compactor/sensor-fixes/sfx-01-local"
mkdir -p "$RUN_ROOT/tmp" "$RUN_ROOT/results" "$RUN_ROOT/bundle-extract"
export TMPDIR="$RUN_ROOT/tmp"
export NUGET_SCRATCH="$RUN_ROOT/tmp/nuget"
export DOTNET_BUNDLE_EXTRACT_BASE_DIR="$RUN_ROOT/bundle-extract"
export WINTAP_DISABLE_SENSORS=true WINTAP_DISABLE_MCP=true WINTAP_DISABLE_DUCKDB_UI=true
export WINTAP_DATA_ROOT="$RUN_ROOT/synthetic-data"
export WINTAP_RUNTIME_ROOT="$RUN_ROOT/synthetic-runtime"
"$SDK" restore tests/Lintap.Tests/Lintap.Tests.csproj --locked-mode \
  -p:NativeBuildRoot="$RUN_ROOT/build/" -p:UseAppHost=false -p:EnableMcpServer=false
"$SDK" test tests/Lintap.Tests/Lintap.Tests.csproj -c Release --no-restore \
  --filter Category=sfx-01 --logger 'trx;LogFileName=sfx-01.trx' \
  --results-directory "$RUN_ROOT/results" \
  -p:NativeBuildRoot="$RUN_ROOT/build/" -p:UseAppHost=false -p:EnableMcpServer=false
```

Tests use only synthetic files in the selected temporary filesystem. No live
capture, historical dataset, S3, service start, or downstream DBT run is involved.

## sfx-02 — observation timing and periodic Refresh

The additive `sfx-02` cases preserve canonical birth/hash while checking raw Linux
kernel occurrence timing, honest UTC-conversion failure, scan-start Refresh timing,
normal/direct Parquet propagation, stable nullable numeric schema, UTC-aligned
scheduling, disabled operation, overlap suppression and disposal waiting. Windows
periodic identity/no-reconciliation coverage remains in `Wintap.Tests` and requires
a native Windows runner for platform acceptance.

Run the focused continuation with the same SDK and isolated roots above, changing
the filter to `Category=sfx-02`. No test starts a collector or attaches BPF.

## sfx-03 — Linux command-line provenance

Synthetic tests distinguish captured, empty, unavailable, read-error and bounded
truncated procfs command lines; ensure truncation emits only complete arguments;
prove clone observations never copy a parent's command line; and preserve additive
source/status fields through normal and direct Parquet projections. Structured
argv, eBPF argv capture, exec-result correlation and DBT selection remain deferred.

Run with the same isolated SDK/root pattern above and filter `Category=sfx-03`.
No focused test starts a collector, attaches BPF, or reads live process metadata.

## sfx-04 — Linux exec observation semantics

`ProcessExecutionObservationTests` distinguishes syscall-entry `exec_attempt`
from scheduler-confirmed `exec_success`, verifies unsupported/non-exec producers
remain nullable, and round-trips the additive field through normal and direct
Parquet projection. Run with `Category=sfx-04`; the tests are synthetic and do
not start a collector or attach BPF.

## sfx-05 — Linux executable-path evidence source

`ProcessExecutablePathSourceTests` preserves existing exec, clone, and rundown
path precedence while labeling event-filename, own-procfs, inherited-parent, and
unavailable evidence. It also verifies normal and null-first direct projection.
Run with `Category=sfx-05`; no focused test starts a collector or attaches BPF.
