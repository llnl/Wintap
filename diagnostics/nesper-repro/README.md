# NEsper Fedora Repro

This standalone repro isolates Fedora NEsper compile/deploy behavior from Lintap service startup, ETL workers, sensors, DuckDB, and plugins.

Run from the repo root:

```bash
dotnet build diagnostics/nesper-repro/nesper-repro.csproj
dotnet diagnostics/nesper-repro/bin/Debug/net10.0/nesper-repro.dll
```

On the Fedora VM shared mount, the repro fails even for:

```text
SELECT * FROM SimpleEvent
```

with:

```text
EPCompileException: Bad IL range
```

Copying the repro and `shared/WintapAPI` to native `/tmp/opencode` and building there makes all queries pass. Running the native-built DLL from the shared repo current directory also passes, while running the shared-built DLL from native `/tmp/opencode` still fails. This narrows the cause to assemblies/output loaded from the shared mount, not current working directory.

## Throughput Benchmark

The same executable can benchmark the production-shaped File EPL independently
of sensors, process attribution, and Parquet I/O:

```bash
dotnet run --project diagnostics/nesper-repro/nesper-repro.csproj -- \
  --benchmark --events 100000 --cardinality 10000 --rounds 3
```

Use `--scenario <name>` to isolate one variant. The benchmark reports ingress
throughput, batch-delivery duration, output rows, and exact event-count/byte
conservation. Its scenarios cover the current string-cast EPL, nested-enum EPL,
the broad subscriber statement, outbound listener threading, concurrent batch
expiration, and the context pattern used by TCP/UDP.

The benchmark uses Esper external time so a 10-second batch can be expired
deterministically without sleeping. Concurrent-expiry scenarios deliberately
advance that clock from another thread while ingress continues; they are stress
tests of runtime locking and boundary behavior, not a production clocking
recommendation.

## Process Identity Cache Benchmark

The same executable can simulate different historical-cache hit rates and
backend lookup costs:

```bash
dotnet run --project diagnostics/nesper-repro/nesper-repro.csproj -- \
  --cache-benchmark --operations 2000 --keys 1000 --capacity 1000 \
  --miss-penalty-us 5000
```

The benchmark reports 100%, 90%, 75%, 50%, and 0% cache-hit workloads. The
miss penalty is a deterministic busy wait used to model a synchronous durable
lookup; it is not a DuckDB benchmark. Use `--keys` greater than `--capacity` to
exercise bounded LRU eviction during setup.
