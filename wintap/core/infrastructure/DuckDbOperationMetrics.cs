using System;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading;

namespace gov.llnl.wintap.core.infrastructure
{
    internal enum DuckDbOperation
    {
        RawSensorCopy,
        ResolverReadAttributedPath,
        ResolverResolveAtTime,
        ResolverRegistryTeardown,
        ResolverProcessExists,
        ResolverRegisterProcess,
        ResolverUpsertProcessStart,
        ResolverGetPidHash,
        ResolverGetAllProcesses,
        ResolverDbLockWait,
        ResolverDbLockHold,
        ResolverSqlResolveAtTime,
        ResolverSqlRegisterProcess,
        ResolverSqlGetPidHash,
        ResolverSqlOther,
        Count
    }

    /// <summary>
    /// Low-overhead, opt-in aggregate timing for the DuckDB call paths involved in
    /// ETL materialization and process resolution. No SQL or query parameters are logged.
    /// Enable with WINTAP_DUCKDB_DIAGNOSTICS=1; summaries are emitted at most once a minute.
    /// </summary>
    internal static class DuckDbOperationMetrics
    {
        private const long ReportIntervalSeconds = 60;
        private static readonly bool Enabled = IsEnabled();
        private static readonly Counter[] Counters = CreateCounters();
        private static long _nextReportTimestamp = Stopwatch.GetTimestamp() +
            Stopwatch.Frequency * ReportIntervalSeconds;

        internal static OperationTimer Start(DuckDbOperation operation, bool reportWhenStopped = true)
        {
            return Enabled
                ? new OperationTimer((int)operation + 1, Stopwatch.GetTimestamp(), reportWhenStopped)
                : default;
        }

        private static bool IsEnabled()
        {
            string value = Environment.GetEnvironmentVariable("WINTAP_DUCKDB_DIAGNOSTICS");
            return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
        }

        private static Counter[] CreateCounters()
        {
            var counters = new Counter[(int)DuckDbOperation.Count];
            for (int i = 0; i < counters.Length; i++)
            {
                counters[i] = new Counter();
            }
            return counters;
        }

        private static void Record(int operation, long elapsedTicks, bool report)
        {
            Counter counter = Counters[operation];
            Interlocked.Increment(ref counter.Calls);
            Interlocked.Add(ref counter.ElapsedTicks, elapsedTicks);

            long previousMax = Interlocked.Read(ref counter.MaxTicks);
            while (elapsedTicks > previousMax)
            {
                long observed = Interlocked.CompareExchange(ref counter.MaxTicks, elapsedTicks, previousMax);
                if (observed == previousMax)
                {
                    break;
                }
                previousMax = observed;
            }

            if (report)
            {
                TryReport();
            }
        }

        private static void RecordFailure(int operation)
        {
            Interlocked.Increment(ref Counters[operation].Failures);
        }

        private static void TryReport()
        {
            long now = Stopwatch.GetTimestamp();
            long due = Interlocked.Read(ref _nextReportTimestamp);
            if (now < due || Interlocked.CompareExchange(
                    ref _nextReportTimestamp,
                    now + Stopwatch.Frequency * ReportIntervalSeconds,
                    due) != due)
            {
                return;
            }

            try
            {
                var summary = new StringBuilder("DuckDB operation timing (last ~60s): ");
                bool hasSamples = false;
                for (int i = 0; i < Counters.Length; i++)
                {
                    Counter counter = Counters[i];
                    long calls = Interlocked.Exchange(ref counter.Calls, 0);
                    long elapsedTicks = Interlocked.Exchange(ref counter.ElapsedTicks, 0);
                    long maxTicks = Interlocked.Exchange(ref counter.MaxTicks, 0);
                    long failures = Interlocked.Exchange(ref counter.Failures, 0);
                    if (calls == 0 && failures == 0)
                    {
                        continue;
                    }

                    if (hasSamples)
                    {
                        summary.Append("; ");
                    }
                    hasSamples = true;
                    double totalMs = ToMilliseconds(elapsedTicks);
                    double averageMs = calls == 0 ? 0 : totalMs / calls;
                    summary.Append(OperationName((DuckDbOperation)i))
                        .Append(" calls=").Append(calls)
                        .Append(" total_ms=").Append(totalMs.ToString("F1", CultureInfo.InvariantCulture))
                        .Append(" avg_ms=").Append(averageMs.ToString("F3", CultureInfo.InvariantCulture))
                        .Append(" max_ms=").Append(ToMilliseconds(maxTicks).ToString("F1", CultureInfo.InvariantCulture))
                        .Append(" failures=").Append(failures);
                }

                if (hasSamples)
                {
                    WintapLogger.Log.Append(summary.ToString(), LogLevel.Info);
                }
            }
            catch
            {
                // Diagnostics must never interfere with normal DuckDB operations.
            }
        }

        private static double ToMilliseconds(long stopwatchTicks)
        {
            return stopwatchTicks * 1000.0 / Stopwatch.Frequency;
        }

        private static string OperationName(DuckDbOperation operation)
        {
            switch (operation)
            {
                case DuckDbOperation.RawSensorCopy: return "etl.raw_sensor_copy";
                case DuckDbOperation.ResolverReadAttributedPath: return "resolver.attributed_path";
                case DuckDbOperation.ResolverResolveAtTime: return "resolver.resolve_at_time";
                case DuckDbOperation.ResolverRegistryTeardown: return "resolver.registry_teardown";
                case DuckDbOperation.ResolverProcessExists: return "resolver.process_exists";
                case DuckDbOperation.ResolverRegisterProcess: return "resolver.register_process";
                case DuckDbOperation.ResolverUpsertProcessStart: return "resolver.upsert_process_start";
                case DuckDbOperation.ResolverGetPidHash: return "resolver.get_pid_hash";
                case DuckDbOperation.ResolverGetAllProcesses: return "resolver.get_all_processes";
                case DuckDbOperation.ResolverDbLockWait: return "resolver.db_lock_wait";
                case DuckDbOperation.ResolverDbLockHold: return "resolver.db_lock_hold";
                case DuckDbOperation.ResolverSqlResolveAtTime: return "resolver.sql_resolve_at_time";
                case DuckDbOperation.ResolverSqlRegisterProcess: return "resolver.sql_register_process";
                case DuckDbOperation.ResolverSqlGetPidHash: return "resolver.sql_get_pid_hash";
                case DuckDbOperation.ResolverSqlOther: return "resolver.sql_other";
                default: return "unknown";
            }
        }

        private sealed class Counter
        {
            internal long Calls;
            internal long ElapsedTicks;
            internal long MaxTicks;
            internal long Failures;
        }

        internal readonly struct OperationTimer : IDisposable
        {
            private readonly int _operation;
            private readonly long _startedAt;
            private readonly bool _reportWhenStopped;

            internal OperationTimer(int operation, long startedAt, bool reportWhenStopped)
            {
                _operation = operation;
                _startedAt = startedAt;
                _reportWhenStopped = reportWhenStopped;
            }

            internal void MarkFailed()
            {
                if (_operation > 0)
                {
                    RecordFailure(_operation - 1);
                }
            }

            public void Dispose()
            {
                if (_operation > 0)
                {
                    Record(_operation - 1, Stopwatch.GetTimestamp() - _startedAt, _reportWhenStopped);
                }
            }

            internal void Stop()
            {
                Dispose();
            }
        }
    }
}
