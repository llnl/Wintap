# Lintap CPU investigation: findings and next test

- Original degradation consumed roughly 12 cores; 44% profile self time was in
  `osq_lock`, through DuckDB scan initialization → `RandomEngine` → `getrandom`
  → DRBG. This indicates RNG lock contention, not proof of its trigger.
- Verified fresh-state default → one-thread → default tests did not reproduce
  the failure: the previously degraded system used roughly 0.64–0.77 cores.
  Application, DuckDB, and runtime hashes, running kernel, and kernel FIPS flags
  matched across systems. Ambient workload and userspace crypto policies differed.
- One-thread resolver SQL averages improved, but changing operation rates/mix
  prevent causal CPU or throughput claims. The limit affects the resolver only;
  ETL opens separate, uncapped DuckDB instances.
- Resolve kernel symbols before interpreting missing RNG frames. Check perf loss
  warnings, measure process CPU-seconds/wall-seconds, and separate startup from
  steady state. Polling/HPET overhead was a separate secondary finding.

## Next experiment

1. On a disposable canary, compare fresh versus representative accumulated
   resolver state with default threads. Make private local snapshots only while
   the source collector is stopped; never open or copy its live database.
2. If the RNG hotspot reproduces, run default → one-thread → default from
   equivalent snapshot copies with matched input rates, identical artifacts,
   60-second warmups, and five-minute measurements. Track operation mix, CPU,
   latency, queues, and losses; downstream counters do not prove no upstream loss.
3. If it does not reproduce, match original launch settings, workload, and run
   duration; then use a bounded identical resolver workload to isolate host effects.

## Safety and operational lessons

- Resolver state follows `WINTAP_RUNTIME_ROOT`, not `WINTAP_DATA_ROOT`. Isolate
  both and verify startup paths, the requested thread-limit message, and zero
  enabled upload adapters before measuring. Supply a complete canary bundle.
- Keep the pidstat service disabled/inactive or absent. Do not change FIPS,
  clocksource, or sysctls; do not upload to S3.
- Publish aggregates only. Keep raw perf, logs, databases, parquet, build caches,
  and detailed symbol/source-path reports private, local, and outside Git.
- For root-squashed shared storage, root reads local aggregate reports and pipes
  them to an extractor running as the designated output owner. Ownership changes
  must be scoped to newly created report subtrees.
