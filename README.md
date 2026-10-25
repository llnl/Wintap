<img width="200" src="https://user-images.githubusercontent.com/50601643/218871643-2d3af433-0923-4786-b5e5-24c6a72e803e.png">

# Wintap

Wintap is a researcher-first host telemetry and analytics platform developed at Lawrence Livermore National Laboratory (LLNL).

It is designed for security research, behavioral analysis, and exploratory investigations rather than enterprise-scale endpoint management. The project emphasizes open data formats, direct access to telemetry, and rapid experimentation.

## Platform Layout

- `Wintap.csproj`: Windows build
- `Lintap.csproj`: Linux build
- `Mactap.csproj`: macOS build
- `wintap/wintap/`: active source tree and Makefile

## Quick Start

From the repo root:

```bash
make -C wintap/wintap all
make -C wintap/wintap run
```

For Linux eBPF validation, run with elevated privileges:

```bash
sudo make -C wintap/wintap run
```

On macOS host -> Linux VM shared mounts and similar filesystems, the Makefile automatically redirects Linux build outputs to native `/tmp/lintap-build/wintap` paths to avoid .NET apphost mmap failures.

## Documentation

- Build, run, and troubleshooting: [`BUILD_AND_TEST.md`](BUILD_AND_TEST.md)
- Documentation index: [`documentation/README.md`](documentation/README.md)
- Developer tools and smoke tests: [`devtools/README.md`](devtools/README.md)
- NEsper shared-mount repro: [`diagnostics/nesper-repro/README.md`](diagnostics/nesper-repro/README.md)

## Architecture Summary

Wintap is organized into four main layers:

- Platform-specific collectors and sensors
- Core routing and enrichment through `EventChannel`
- ETL and serialization to Parquet and related outputs
- Optional adapters, plugins, and MCP integrations

Linux sensor work currently centers on eBPF tracers under `wintap/wintap/platform/linux/sensor/ebpf/tracers/` plus fallback and isolation paths documented in `BUILD_AND_TEST.md`.

## Technology

`.NET 10` | `Esper CEP` | `DuckDB` | `Parquet` | `eBPF` | `MEF`

## Release

LLNL-CODE-837816

https://github.com/LLNL/wintap
