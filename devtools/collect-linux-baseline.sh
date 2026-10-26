#!/usr/bin/env bash
set -u

ROOT_DIR="$(pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname 2>/dev/null || printf unknown)"
OUT_DIR="${BASELINE_OUT_DIR:-/tmp/wintap-baseline-${HOST}-${STAMP}}"
RESULTS="${OUT_DIR}/results.jsonl"

mkdir -p "${OUT_DIR}/commands" "${OUT_DIR}/logs"

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null || sed 's/\/\\/g; s/"/\"/g'
}

emit() {
  local type="$1"
  local name="$2"
  local status="$3"
  local data="$4"
  local escaped
  escaped="$(printf '%s' "${data}" | json_escape)"
  printf '{"type":"%s","name":"%s","status":"%s","data":"%s"}\n' "${type}" "${name}" "${status}" "${escaped}" >> "${RESULTS}"
}

run_cmd() {
  local name="$1"
  shift
  local safe_name output_file exit_code
  safe_name="$(printf '%s' "${name}" | tr -c 'A-Za-z0-9._-' '_')"
  output_file="${OUT_DIR}/commands/${safe_name}.txt"
  "$@" > "${output_file}" 2>&1
  exit_code=$?
  emit "command" "${name}" "exit:${exit_code}" "${output_file}"
  return 0
}

run_shell() {
  local name="$1"
  local command="$2"
  local safe_name output_file exit_code
  safe_name="$(printf '%s' "${name}" | tr -c 'A-Za-z0-9._-' '_')"
  output_file="${OUT_DIR}/commands/${safe_name}.txt"
  bash -lc "${command}" > "${output_file}" 2>&1
  exit_code=$?
  emit "command" "${name}" "exit:${exit_code}" "${output_file}"
  return 0
}

emit "meta" "schema" "ok" "wintap-linux-baseline-v1"
emit "meta" "timestamp_utc" "ok" "${STAMP}"
emit "meta" "root_dir" "ok" "${ROOT_DIR}"
emit "meta" "out_dir" "ok" "${OUT_DIR}"

run_cmd "uname-a" uname -a
run_cmd "architecture" uname -m
run_cmd "os-release" bash -lc 'cat /etc/os-release 2>/dev/null || true'
run_cmd "hostnamectl" bash -lc 'hostnamectl 2>/dev/null || true'
run_cmd "filesystem-root" bash -lc 'stat -f -c "%T %m" . 2>/dev/null || true'
run_cmd "filesystem-tmp" bash -lc 'stat -f -c "%T %m" /tmp 2>/dev/null || true'
run_cmd "mounts-current-path" bash -lc 'awk -v dir="$PWD" "BEGIN{best=\"\";bestlen=0} {mp=\$2; if(index(dir,mp)==1 && length(mp)>bestlen){best=\$0;bestlen=length(mp)}} END{print best}" /proc/mounts 2>/dev/null || true'
run_cmd "getenforce" bash -lc 'getenforce 2>/dev/null || true'
run_cmd "ulimits" bash -lc 'ulimit -a'
run_cmd "sysctl-bpf-perf" bash -lc 'sysctl kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid kernel.kptr_restrict 2>/dev/null || true'
run_cmd "kernel-lockdown" bash -lc 'cat /sys/kernel/security/lockdown 2>/dev/null || true'

run_cmd "which-dotnet" bash -lc 'which dotnet 2>/dev/null; readlink -f "$(which dotnet 2>/dev/null)" 2>/dev/null || true'
run_cmd "dotnet-info" bash -lc 'dotnet --info 2>&1 || true'
run_cmd "dotnet-sdks" bash -lc 'dotnet --list-sdks 2>&1 || true'
run_cmd "dotnet-runtimes" bash -lc 'dotnet --list-runtimes 2>&1 || true'
run_cmd "dotnet-environment" bash -lc 'env | sort | grep -E "^(DOTNET|CORECLR|COMPlus|NUGET|MSBuild|ASPNETCORE)_" || true'

run_cmd "dpkg-dotnet-libbpf-duckdb" bash -lc 'dpkg-query -W -f="${Package}\t${Version}\t${Architecture}\n" "dotnet*" "aspnetcore*" "libbpf*" "bpftool" "clang*" "llvm*" "libduckdb*" "duckdb*" "libc6" 2>/dev/null | sort || true'
run_cmd "apt-policy-dotnet" bash -lc 'apt-cache policy dotnet-sdk-10.0 dotnet-runtime-10.0 aspnetcore-runtime-10.0 2>/dev/null || true'
run_cmd "native-tool-versions" bash -lc 'clang --version 2>/dev/null || true; llvm-objdump --version 2>/dev/null | sed -n "1,3p" || true; bpftool version 2>/dev/null || true; duckdb --version 2>/dev/null || true; ldd --version 2>/dev/null | sed -n "1p" || true'

if [ -f "wintap/Makefile" ] && [ -f "wintap/Lintap.csproj" ]; then
  PROJECT_DIR="${ROOT_DIR}/wintap"
elif [ -f "Makefile" ] && [ -f "Lintap.csproj" ]; then
  PROJECT_DIR="${ROOT_DIR}"
else
  PROJECT_DIR=""
fi

emit "meta" "project_dir" "ok" "${PROJECT_DIR}"

if [ -n "${PROJECT_DIR}" ]; then
  run_shell "git-status" "cd '${ROOT_DIR}' && git status --short 2>&1 || true"
  run_shell "git-rev" "cd '${ROOT_DIR}' && git rev-parse --show-toplevel HEAD 2>&1 || true"
  run_shell "makefile-run-targets" "cd '${PROJECT_DIR}' && make -pn 2>/dev/null | awk -F: '/^[A-Za-z0-9_.-]+:/ {print \$1}' | sort -u | grep -E '^(all|build|build_dotnet|build_ebpf|run|run-host-only|run-env|test)' || true"
  run_shell "project-packages" "cd '${PROJECT_DIR}' && dotnet list Lintap.csproj package --include-transitive 2>&1 || true"
  run_shell "native-libs-in-output" "cd '${PROJECT_DIR}' && if [ -d bin ]; then find bin -type f \( -name '*.so' -o -name '*.dylib' -o -name '*.dll' \) -print | sort; fi"

  if [ "${RUN_BUILD:-0}" = "1" ]; then
    run_shell "make-build-dotnet" "cd '${PROJECT_DIR}' && make build_dotnet"
    run_shell "make-build-ebpf" "cd '${PROJECT_DIR}' && make build_ebpf"
  else
    emit "skip" "builds" "ok" "Set RUN_BUILD=1 to run make build_dotnet and make build_ebpf."
  fi

  if [ "${RUN_SMOKE:-0}" = "1" ]; then
    run_shell "smoke-run-host-only" "cd '${PROJECT_DIR}' && timeout '${SMOKE_TIMEOUT:-45s}' env WINTAP_DATA_ROOT='${WINTAP_DATA_ROOT:-/tmp/lintap-data-baseline}' WINTAP_DISABLE_MCP=true WINTAP_DISABLE_DUCKDB_UI=true WINTAP_DISABLE_ETL=true WINTAP_DISABLE_SENSORS=true make run-host-only"
    run_shell "smoke-etl-only" "cd '${PROJECT_DIR}' && timeout '${SMOKE_TIMEOUT:-75s}' env WINTAP_DATA_ROOT='${WINTAP_DATA_ROOT:-/tmp/lintap-data-baseline}' WINTAP_DISABLE_MCP=true WINTAP_DISABLE_DUCKDB_UI=true WINTAP_DISABLE_ETL=false WINTAP_DISABLE_SENSORS=true make run"
    run_shell "smoke-sensors-only" "cd '${PROJECT_DIR}' && timeout '${SMOKE_TIMEOUT:-75s}' env WINTAP_DATA_ROOT='${WINTAP_DATA_ROOT:-/tmp/lintap-data-baseline}' WINTAP_DISABLE_MCP=true WINTAP_DISABLE_DUCKDB_UI=true WINTAP_DISABLE_ETL=true WINTAP_DISABLE_SENSORS=false make run"
    run_shell "smoke-coredumps" "coredumpctl list dotnet --no-pager 2>/dev/null || true"
    run_shell "smoke-parquet-files" "find '${WINTAP_DATA_ROOT:-/tmp/lintap-data-baseline}' -type f -name '*.parquet' -print 2>/dev/null | sort || true"
  else
    emit "skip" "smoke" "ok" "Set RUN_SMOKE=1 to run host-only, ETL-only, and sensors-only smoke tests."
  fi
else
  emit "warning" "project_dir" "missing" "Could not locate Lintap.csproj/Makefile. Run this script from the repo root or wintap project directory."
fi

tarball="${OUT_DIR}.tar.gz"
tar -czf "${tarball}" -C "$(dirname "${OUT_DIR}")" "$(basename "${OUT_DIR}")"
emit "meta" "tarball" "ok" "${tarball}"

printf 'WINTAP_BASELINE_RESULTS=%s\n' "${RESULTS}"
printf 'WINTAP_BASELINE_TARBALL=%s\n' "${tarball}"
printf 'Paste back %s or attach %s.\n' "${RESULTS}" "${tarball}"
