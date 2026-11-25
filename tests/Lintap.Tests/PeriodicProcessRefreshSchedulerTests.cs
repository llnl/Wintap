using System;
using System.Threading;
using System.Threading.Tasks;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Lintap.Tests
{
    [Trait("Category", "sfx-02")]
    [Trait("TestKind", "unit")]
    [Trait("Execution", "synthetic")]
    public class PeriodicProcessRefreshSchedulerTests
    {
        [Theory]
        [InlineData(4, 59, 5, 5)]
        [InlineData(5, 0, 5, 5)]
        [InlineData(5, 5, 6, 5)]
        [InlineData(6, 7, 7, 5)]
        public void HourlyScheduleSelectsNextUtcBoundaryAndSkipsMissedTicks(
            int hour, int minute, int expectedHour, int expectedMinute)
        {
            DateTime now = new(2026, 1, 1, hour, minute, 0, DateTimeKind.Utc);
            DateTime next = PeriodicProcessRefreshScheduler.GetNextRunUtc(
                now, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5));
            Assert.Equal(new DateTime(2026, 1, 1, expectedHour, expectedMinute, 0, DateTimeKind.Utc), next);
        }

        [Fact]
        public void ConfiguredIntervalAndOffsetAlignFromUtcEpoch()
        {
            DateTime next = PeriodicProcessRefreshScheduler.GetNextRunUtc(
                new DateTime(2026, 1, 1, 0, 36, 0, DateTimeKind.Utc),
                TimeSpan.FromMinutes(15),
                TimeSpan.FromMinutes(2));
            Assert.Equal(new DateTime(2026, 1, 1, 0, 47, 0, DateTimeKind.Utc), next);
        }

        [Fact]
        public void DisabledScheduleNeverRuns()
        {
            int calls = 0;
            using var scheduler = Create(enabled: false, () => calls++);
            scheduler.Start();
            Assert.False(scheduler.TryRunOnce());
            Assert.Equal(0, calls);
            Assert.Equal(0, scheduler.CompletedRuns);
        }

        [Fact]
        public async Task OverlapIsSkippedAndShutdownWaitsForActiveInventory()
        {
            using var entered = new ManualResetEventSlim(false);
            using var release = new ManualResetEventSlim(false);
            var scheduler = Create(enabled: true, () =>
            {
                entered.Set();
                release.Wait();
            });

            Task<bool> first = Task.Run(scheduler.TryRunOnce);
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            Assert.False(scheduler.TryRunOnce());
            Assert.Equal(1, scheduler.SkippedOverlaps);

            Task dispose = Task.Run(scheduler.Dispose);
            await Task.Delay(50);
            Assert.False(dispose.IsCompleted);
            release.Set();
            Assert.True(await first);
            await dispose;
            Assert.Equal(1, scheduler.CompletedRuns);
            Assert.False(scheduler.TryRunOnce());
        }

        private static PeriodicProcessRefreshScheduler Create(bool enabled, Action action) => new(
            new ProcessRefreshSchedule
            {
                Enabled = enabled,
                Interval = TimeSpan.FromHours(1),
                Offset = TimeSpan.FromMinutes(5)
            },
            action,
            () => new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            (_, _) => { });
    }
}
