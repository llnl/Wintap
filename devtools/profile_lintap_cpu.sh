#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Attach a Linux perf CPU sampler to an already-running Lintap process.

Usage:
  profile_lintap_cpu.sh --pid PID --output NEW_DIRECTORY [--duration SECONDS] [--frequency HZ]

The script requests user and kernel call stacks. It does not start, stop, or signal
Lintap, and it does not install anything. Kernel frames depend on perf permissions
and kernel configuration. Run with sufficient perf permissions (typically sudo).
For managed/JIT method names, set DOTNET_PerfMapEnabled=1 and/or
COMPlus_PerfMapEnabled=1 before starting the target process; attaching cannot enable
those maps retroactively.
Raw DWARF samples may contain sensitive memory. Keep captures local and outside
Git; this script does not upload data.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

PID=""
OUTPUT=""
DURATION=300
FREQUENCY=99

while (($#)); do
  case "$1" in
    --pid)
      (($# >= 2)) || fail "--pid requires a value"
      PID=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || fail "--output requires a value"
      OUTPUT=$2
      shift 2
      ;;
    --duration)
      (($# >= 2)) || fail "--duration requires a value"
      DURATION=$2
      shift 2
      ;;
    --frequency)
      (($# >= 2)) || fail "--frequency requires a value"
      FREQUENCY=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ "$PID" =~ ^[1-9][0-9]*$ ]] || fail "provide a numeric --pid"
[[ -n "$OUTPUT" ]] || fail "provide --output"
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || fail "--duration must be a positive integer"
[[ "$FREQUENCY" =~ ^[1-9][0-9]*$ ]] || fail "--frequency must be a positive integer"
((FREQUENCY <= 1000)) || fail "--frequency must not exceed 1000 Hz"

[[ -d "/proc/$PID" ]] || fail "PID $PID is not running"
[[ -r "/proc/$PID/cmdline" && -r "/proc/$PID/comm" ]] || \
  fail "cannot inspect PID $PID; rerun with sufficient permissions"

# Inspect only to guard against accidentally profiling the wrong process. Do not
# print or persist the command line, which may contain runtime arguments.
target_comm=$(<"/proc/$PID/comm")
target_cmdline=$(tr '\0' ' ' < "/proc/$PID/cmdline")
if [[ "$target_cmdline" != *Lintap.dll* && "$target_comm" != *Lintap* ]]; then
  fail "PID $PID does not appear to be Lintap (comm=$target_comm)"
fi
unset target_cmdline

command -v perf >/dev/null 2>&1 || fail "perf is not installed or not on PATH"
command -v sleep >/dev/null 2>&1 || fail "sleep is not installed or not on PATH"

OUTPUT=${OUTPUT%/}
[[ -n "$OUTPUT" ]] || fail "--output must name a directory"
[[ ! -e "$OUTPUT" ]] || fail "output already exists: $OUTPUT (choose a fresh directory)"

umask 077
mkdir -p -- "$(dirname -- "$OUTPUT")"
ancestor=$(cd -- "$(dirname -- "$OUTPUT")" && pwd -P)
while [[ "$ancestor" != / ]]; do
  [[ ! -e "$ancestor/.git" ]] || fail "debug outputs must be outside Git worktrees"
  ancestor=$(dirname -- "$ancestor")
done
mkdir -- "$OUTPUT"

START_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
PERF_VERSION=$(perf --version 2>&1 | head -n 1)
KERNEL_VERSION=$(uname -r)

{
  printf 'start_utc=%s\n' "$START_UTC"
  printf 'requested_duration_seconds=%s\n' "$DURATION"
  printf 'sample_frequency_hz=%s\n' "$FREQUENCY"
  printf 'perf_version=%s\n' "$PERF_VERSION"
  printf 'kernel=%s\n' "$KERNEL_VERSION"
  printf 'call_graph=dwarf (user and kernel)\n'
  printf 'dotnet_perf_maps=must be enabled before target launch for managed JIT symbols\n'
} > "$OUTPUT/capture.txt"

printf 'Profiling Lintap PID %s (%s) for %s seconds.\n' "$PID" "$target_comm" "$DURATION"
printf 'Output: %s\n' "$OUTPUT"
printf 'This only attaches to the target; it will not stop it.\n'

set +e
perf record \
  --freq "$FREQUENCY" \
  --call-graph dwarf \
  --pid "$PID" \
  --output "$OUTPUT/perf.data" \
  -- sleep "$DURATION" 2>&1 | tee "$OUTPUT/perf-record.log"
PIPE_STATUS=("${PIPESTATUS[@]}")
set -e
PERF_STATUS=${PIPE_STATUS[0]}

END_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
{
  printf 'end_utc=%s\n' "$END_UTC"
  printf 'perf_exit_status=%s\n' "$PERF_STATUS"
} >> "$OUTPUT/capture.txt"

if [[ ! -s "$OUTPUT/perf.data" ]]; then
  printf 'ERROR: perf did not produce a non-empty capture. See %s/perf-record.log\n' "$OUTPUT" >&2
  if ((PERF_STATUS != 0)); then
    exit "$PERF_STATUS"
  fi
  exit 1
fi

if ((PERF_STATUS != 0)); then
  printf 'WARNING: perf exited with status %s; the partial capture was retained.\n' "$PERF_STATUS" >&2
  exit "$PERF_STATUS"
fi

printf 'Capture complete: %s/perf.data\n' "$OUTPUT"
