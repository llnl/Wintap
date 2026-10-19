# Linux Deployment Guide

This guide describes the current Linux deployment flow for `Lintap`.

For build troubleshooting and Fedora/shared-mount notes, see [`../BUILD_AND_TEST.md`](../BUILD_AND_TEST.md).

## Deployment Model

The recommended Linux deployment model is:

1. Build `Lintap` from `wintap/wintap`
2. Copy the built output directory to the target host
3. Run `Lintap.dll` with `dotnet`
4. Configure runtime behavior with environment variables

This is preferred over older docs that assumed a standalone `/opt/lintap/Lintap` binary by default.

## Prerequisites

On the target Linux host, install:

- .NET 8 runtime or SDK
- `libbpf`, `clang`, `llvm`, and kernel headers if building eBPF locally
- root or `sudo` access for eBPF sensor loading

Example Ubuntu packages:

```bash
sudo apt update
sudo apt install -y dotnet-sdk-8.0 aspnetcore-runtime-8.0
sudo apt install -y libbpf-dev libbpf1 clang llvm libelf-dev linux-headers-$(uname -r) build-essential
```

## Build Lintap

From the repo root:

```bash
make -C wintap/wintap all
make -C wintap/wintap run-env
```

`run-env` prints the effective runtime paths, including:

- `LINTAP_DLL`
- `MCP_EXE`
- `NATIVE_BUILD_ROOT`
- `DOTNET_BUILD_FLAGS`

On shared mounts, the effective Linux output directory is typically:

```text
/tmp/lintap-build/wintap/bin/Debug/net8.0
```

On native filesystems, it is typically:

```text
wintap/wintap/bin/Debug/net8.0
```

## Copy Build Output

Copy the entire Linux output directory, not just `Lintap.dll`. The runtime needs the adjacent dependencies, `esper/`, `tracers/`, `ETLConfig.json`, and `mcp/` content.

Example:

```bash
sudo mkdir -p /opt/lintap
sudo rsync -a /tmp/lintap-build/wintap/bin/Debug/net8.0/ /opt/lintap/
```

If your build output is in the repo tree instead of `/tmp`, copy that directory instead.

## Create Data and Runtime Directories

```bash
sudo mkdir -p /var/log/lintap/data /var/log/lintap/runtime
sudo chown -R root:root /opt/lintap /var/log/lintap
```

## Recommended Bring-Up

Before creating a long-running service, do one foreground validation run:

```bash
cd /opt/lintap
sudo env \
  WINTAP_DATA_ROOT=/var/log/lintap/data \
  WINTAP_RUNTIME_ROOT=/var/log/lintap/runtime \
  WINTAP_DISABLE_MCP=true \
  WINTAP_DISABLE_DUCKDB_UI=true \
  WINTAP_DISABLE_ETL=true \
  WINTAP_DISABLE_SENSORS=false \
  WINTAP_ENABLE_EXECVE_SENSOR=true \
  WINTAP_ENABLE_CLONE_SENSOR=false \
  WINTAP_ENABLE_EXIT_SENSOR=false \
  WINTAP_ENABLE_NETWORK_SENSOR=false \
  WINTAP_ENABLE_FILEOPS_SENSOR=false \
  WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR=false \
  dotnet /opt/lintap/Lintap.dll
```

That profile keeps startup narrow and is easier to debug than enabling every sensor immediately.

## Example systemd Service

Create `/etc/systemd/system/lintap.service`:

```ini
[Unit]
Description=Lintap telemetry service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/lintap
ExecStart=/usr/bin/dotnet /opt/lintap/Lintap.dll
Restart=on-failure
RestartSec=10
User=root
Group=root

Environment=WINTAP_DATA_ROOT=/var/log/lintap/data
Environment=WINTAP_RUNTIME_ROOT=/var/log/lintap/runtime
Environment=WINTAP_DISABLE_MCP=true
Environment=WINTAP_DISABLE_DUCKDB_UI=true
Environment=WINTAP_DISABLE_ETL=false
Environment=WINTAP_DISABLE_SENSORS=false
Environment=WINTAP_ENABLE_DIRECT_PARQUET=false
Environment=WINTAP_ENABLE_EXECVE_SENSOR=true
Environment=WINTAP_ENABLE_CLONE_SENSOR=false
Environment=WINTAP_ENABLE_EXIT_SENSOR=true
Environment=WINTAP_ENABLE_NETWORK_SENSOR=true
Environment=WINTAP_ENABLE_FILEOPS_SENSOR=true
Environment=WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR=true

StandardOutput=journal
StandardError=journal
SyslogIdentifier=lintap

[Install]
WantedBy=multi-user.target
```

Notes:

- Running as `root` is expected when loading eBPF programs.
- The per-sensor variables are set explicitly so service behavior stays predictable.
- `CloneSensor` is still a known trouble spot on some Fedora environments; enable it only after validating your kernel and permissions.

## Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable lintap
sudo systemctl start lintap
sudo systemctl status lintap
```

## Verify Deployment

Check service logs:

```bash
sudo journalctl -u lintap -f
```

Check the app log under the configured runtime root:

```bash
sudo tail -f /var/log/lintap/runtime/Logs/Lintap.log
```

Verify the web host:

```bash
curl http://localhost:8099
```

Verify loaded BPF programs:

```bash
sudo bpftool prog list
```

## Smoke Tests

Once `Lintap` is running, use the developer tools from the repo:

```bash
python3 devtools/network_capture_smoke_test.py --data-root /var/log/lintap/data --timeout 240 --poll-interval 10
python3 devtools/process_capture_smoke_test.py --data-root /var/log/lintap/data --timeout 240 --poll-interval 10
python3 devtools/file_capture_smoke_test.py --data-root /var/log/lintap/data --timeout 240 --poll-interval 10
```

See [`../devtools/README.md`](../devtools/README.md) for details.

## Operational Notes

- Prefer `make -C wintap/wintap run-env` during packaging and troubleshooting so you copy the actual active output directory.
- If the repo lives on a host-shared filesystem, copy deployment artifacts from `/tmp/lintap-build/wintap/...`, not from stale in-repo `bin/` directories.
- For Fedora bring-up, keep `WINTAP_DISABLE_MCP=true` and `WINTAP_DISABLE_DUCKDB_UI=true` until the basic host and sensor path is stable.
