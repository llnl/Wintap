using System;
using System.Threading;
using gov.llnl.wintap.core.shared;

namespace gov.llnl.wintap.core.infrastructure
{
    internal sealed class ProcessRefreshSchedule
    {
        internal const int DefaultIntervalMinutes = 60;
        internal const int DefaultOffsetMinutes = 5;

        internal bool Enabled { get; init; }
        internal TimeSpan Interval { get; init; }
        internal TimeSpan Offset { get; init; }

        internal static ProcessRefreshSchedule FromConfig()
        {
            bool enabled = ConfigManager.GetValue<bool>("ProcessRefreshEnabled");
            int intervalMinutes = ConfigManager.GetValue<int>("ProcessRefreshIntervalMinutes");
            int offsetMinutes = ConfigManager.GetValue<int>("ProcessRefreshOffsetMinutes");

            if (intervalMinutes <= 0)
            {
                intervalMinutes = DefaultIntervalMinutes;
            }
            if (offsetMinutes < 0 || offsetMinutes >= intervalMinutes)
            {
                offsetMinutes = Math.Min(DefaultOffsetMinutes, intervalMinutes - 1);
            }

            RuntimeCapabilities.Setting("processRefresh.enabled", enabled,
                ConfigManager.GetValueSource<bool>("ProcessRefreshEnabled"));
            RuntimeCapabilities.Setting("processRefresh.intervalMinutes", intervalMinutes,
                ConfigManager.GetValueSource<int>("ProcessRefreshIntervalMinutes"));
            RuntimeCapabilities.Setting("processRefresh.offsetMinutes", offsetMinutes,
                ConfigManager.GetValueSource<int>("ProcessRefreshOffsetMinutes"));

            return new ProcessRefreshSchedule
            {
                Enabled = enabled,
                Interval = TimeSpan.FromMinutes(intervalMinutes),
                Offset = TimeSpan.FromMinutes(offsetMinutes)
            };
        }
    }

    /// <summary>
    /// One-shot UTC-aligned scheduler. Each completion computes the next future
    /// boundary, so missed ticks are skipped rather than replayed in a burst.
    /// </summary>
    internal sealed class PeriodicProcessRefreshScheduler : IDisposable
    {
        private readonly object gate = new object();
        private readonly Action refresh;
        private readonly Func<DateTime> utcNow;
        private readonly Action<string, LogLevel> log;
        private readonly ProcessRefreshSchedule schedule;
        private readonly ManualResetEventSlim idle = new ManualResetEventSlim(true);
        private Timer timer;
        private int executing;
        private int disposed;
        private long completedRuns;
        private long skippedOverlaps;

        internal PeriodicProcessRefreshScheduler(
            ProcessRefreshSchedule schedule,
            Action refresh,
            Func<DateTime> utcNow = null,
            Action<string, LogLevel> log = null)
        {
            this.schedule = schedule ?? throw new ArgumentNullException(nameof(schedule));
            this.refresh = refresh ?? throw new ArgumentNullException(nameof(refresh));
            this.utcNow = utcNow ?? (() => DateTime.UtcNow);
            this.log = log ?? ((message, level) => WintapLogger.Log.Append(message, level));
            if (schedule.Interval <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(schedule), "Refresh interval must be positive.");
            if (schedule.Offset < TimeSpan.Zero || schedule.Offset >= schedule.Interval)
                throw new ArgumentOutOfRangeException(nameof(schedule), "Refresh offset must be within the interval.");
        }

        internal long CompletedRuns => Interlocked.Read(ref completedRuns);
        internal long SkippedOverlaps => Interlocked.Read(ref skippedOverlaps);

        internal void Start()
        {
            lock (gate)
            {
                if (!schedule.Enabled || disposed != 0 || timer != null)
                    return;

                DateTime now = utcNow().ToUniversalTime();
                DateTime next = GetNextRunUtc(now, schedule.Interval, schedule.Offset);
                timer = new Timer(OnTimer, null, next - now, Timeout.InfiniteTimeSpan);
                log($"Periodic process Refresh scheduled for {next:O} (UTC interval={schedule.Interval}, offset={schedule.Offset})", LogLevel.Info);
            }
        }

        private void OnTimer(object state)
        {
            TryRunOnce();
            ScheduleNextFutureRun();
        }

        internal bool TryRunOnce()
        {
            lock (gate)
            {
                if (!schedule.Enabled || disposed != 0)
                    return false;
                if (Interlocked.CompareExchange(ref executing, 1, 0) != 0)
                {
                    Interlocked.Increment(ref skippedOverlaps);
                    log("Periodic process Refresh skipped because the prior inventory is still running", LogLevel.Warn);
                    return false;
                }

                // Reset while admission is serialized with Dispose, ensuring
                // shutdown cannot observe idle before this run becomes active.
                idle.Reset();
            }

            try
            {
                refresh();
                Interlocked.Increment(ref completedRuns);
                return true;
            }
            catch (Exception ex)
            {
                log($"Periodic process Refresh failed: {ex.Message}", LogLevel.Error);
                return false;
            }
            finally
            {
                Interlocked.Exchange(ref executing, 0);
                idle.Set();
            }
        }

        private void ScheduleNextFutureRun()
        {
            lock (gate)
            {
                if (disposed != 0 || timer == null)
                    return;

                DateTime now = utcNow().ToUniversalTime();
                DateTime next = GetNextRunUtc(now, schedule.Interval, schedule.Offset);
                timer.Change(next - now, Timeout.InfiniteTimeSpan);
            }
        }

        internal static DateTime GetNextRunUtc(DateTime now, TimeSpan interval, TimeSpan offset)
        {
            if (interval <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(interval));
            if (offset < TimeSpan.Zero || offset >= interval)
                throw new ArgumentOutOfRangeException(nameof(offset));

            DateTime utc = now.ToUniversalTime();
            long elapsedTicks = checked(utc.Ticks - DateTime.UnixEpoch.Ticks - offset.Ticks);
            long completedIntervals = elapsedTicks / interval.Ticks;
            long nextTicks = checked(DateTime.UnixEpoch.Ticks + offset.Ticks +
                checked((completedIntervals + 1) * interval.Ticks));
            return new DateTime(nextTicks, DateTimeKind.Utc);
        }

        public void Dispose()
        {
            Timer current;
            lock (gate)
            {
                if (Interlocked.Exchange(ref disposed, 1) != 0)
                    return;
                current = timer;
                timer = null;
            }

            if (current != null)
            {
                using var callbacksDrained = new ManualResetEvent(false);
                if (current.Dispose(callbacksDrained))
                    callbacksDrained.WaitOne();
            }
            idle.Wait();
            idle.Dispose();
        }
    }
}
