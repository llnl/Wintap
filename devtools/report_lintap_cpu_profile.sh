#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Generate text reports (and optionally a FlameGraph SVG) from a Lintap perf capture.

Usage:
  report_lintap_cpu_profile.sh PROFILE_DIRECTORY [--percent-limit PERCENT] [--flamegraph]

The script creates a new analysis-* directory under PROFILE_DIRECTORY and never
modifies perf.data. For captures made as root, run this script with sufficient
permissions to read the profile files.
Reports and folded stacks can expose paths, symbols, and process identifiers.
Keep them private, local, and outside Git; no data is uploaded.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

PROFILE_DIR=""
PERCENT_LIMIT=0.5
MAKE_FLAMEGRAPH=0

while (($#)); do
  case "$1" in
    --percent-limit)
      (($# >= 2)) || fail "--percent-limit requires a value"
      PERCENT_LIMIT=$2
      shift 2
      ;;
    --flamegraph)
      MAKE_FLAMEGRAPH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      fail "unknown argument: $1"
      ;;
    *)
      [[ -z "$PROFILE_DIR" ]] || fail "provide only one profile directory"
      PROFILE_DIR=$1
      shift
      ;;
  esac
done

[[ -n "$PROFILE_DIR" ]] || fail "provide a profile directory"
[[ -s "$PROFILE_DIR/perf.data" ]] || fail "missing or empty $PROFILE_DIR/perf.data"
[[ "$PERCENT_LIMIT" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || \
  fail "--percent-limit must be a non-negative number"
awk -v limit="$PERCENT_LIMIT" 'BEGIN { exit !(limit <= 100) }' || \
  fail "--percent-limit must not exceed 100"
command -v perf >/dev/null 2>&1 || fail "perf is not installed or not on PATH"
if ((MAKE_FLAMEGRAPH)); then
  command -v stackcollapse-perf.pl >/dev/null 2>&1 || \
    fail "--flamegraph requires stackcollapse-perf.pl on PATH (from FlameGraph)"
  command -v flamegraph.pl >/dev/null 2>&1 || \
    fail "--flamegraph requires flamegraph.pl on PATH (from FlameGraph)"
fi

OUTPUT_DIR="$PROFILE_DIR/analysis-$(date -u '+%Y%m%dT%H%M%SZ')"
ancestor=$(cd -- "$PROFILE_DIR" && pwd -P)
while [[ "$ancestor" != / ]]; do
  [[ ! -e "$ancestor/.git" ]] || fail "debug outputs must be outside Git worktrees"
  ancestor=$(dirname -- "$ancestor")
done
umask 077
mkdir -- "$OUTPUT_DIR" 2>/dev/null || fail "could not create fresh output directory: $OUTPUT_DIR"

printf 'Writing self-time report...\n'
perf report \
  --input "$PROFILE_DIR/perf.data" \
  --stdio \
  --no-children \
  --percent-limit "$PERCENT_LIMIT" \
  --sort comm,dso,symbol \
  > "$OUTPUT_DIR/self-time.txt"

printf 'Writing call-chain report...\n'
perf report \
  --input "$PROFILE_DIR/perf.data" \
  --stdio \
  --call-graph \
  --percent-limit "$PERCENT_LIMIT" \
  --sort comm,dso,symbol \
  > "$OUTPUT_DIR/call-chains.txt"

if ((MAKE_FLAMEGRAPH)); then
  printf 'Generating folded stacks and FlameGraph...\n'
  perf script --input "$PROFILE_DIR/perf.data" \
    | stackcollapse-perf.pl > "$OUTPUT_DIR/stacks.folded"
  flamegraph.pl --title 'Lintap CPU profile' "$OUTPUT_DIR/stacks.folded" \
    > "$OUTPUT_DIR/cpu-flamegraph.svg"
fi

printf 'Reports written to %s\n' "$OUTPUT_DIR"
