using System;
using System.Collections.Generic;
using System.Linq;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    [Trait("TestKind", "unit")]
    [Trait("Execution", "synthetic")]
    public class FileOpsAggregatorTests
    {
        private const uint OpOpen = 1;
        private const uint OpRead = 2;

        private static (FileOpsAggregator Aggregator, List<FileOpsAggregator.AggregateEntry> Emitted) Create(
            int windowMs = 1000, int maxKeys = 32768)
        {
            var emitted = new List<FileOpsAggregator.AggregateEntry>();
            var aggregator = new FileOpsAggregator(windowMs, maxKeys, emitted.Add);
            return (aggregator, emitted);
        }

        [Fact]
        public void FirstOccurrence_IsNeverAbsorbed()
        {
            var (agg, emitted) = Create();
            bool absorbed = agg.TryAbsorb(100, "/tmp/a", OpOpen, 10, 1_000, "proc", "hash", nowMs: 0);
            Assert.False(absorbed);
            Assert.Empty(emitted);
        }

        [Fact]
        public void RepeatsInsideWindow_AreAbsorbed_AndSummarizedOnFlush()
        {
            var (agg, emitted) = Create(windowMs: 1000);
            agg.TryAbsorb(100, "/tmp/a", OpOpen, 10, 1_000, "proc", "hash", 0);
            Assert.True(agg.TryAbsorb(100, "/tmp/a", OpOpen, 20, 2_000, "proc", "hash", 100));
            Assert.True(agg.TryAbsorb(100, "/tmp/a", OpOpen, 30, 3_000, "proc", "hash", 200));

            agg.FlushExpired(nowMs: 2000);

            var summary = Assert.Single(emitted);
            Assert.Equal(2, summary.RepeatCount);
            Assert.Equal(50, summary.BytesSum);
            Assert.Equal(2_000UL, summary.FirstRepeatNs);
            Assert.Equal(3_000UL, summary.LastRepeatNs);
            Assert.Equal("hash", summary.PidHash);
            Assert.Equal("proc", summary.ProcessName);
            Assert.Equal(0, agg.EntryCount);
        }

        [Fact]
        public void CountConservation_FirstPlusRepeats_EqualsRawEvents()
        {
            var (agg, emitted) = Create(windowMs: 1000);
            const int rawEvents = 7;
            int firstEmits = 0;
            for (int i = 0; i < rawEvents; i++)
            {
                if (!agg.TryAbsorb(1, "/f", OpRead, 1, (ulong)i, "p", "h", nowMs: i))
                {
                    firstEmits++;
                }
            }
            agg.FlushExpired(nowMs: 5000);
            int total = firstEmits + emitted.Sum(e => e.RepeatCount);
            Assert.Equal(rawEvents, total);
        }

        [Fact]
        public void DistinctKeys_DoNotMerge()
        {
            var (agg, _) = Create();
            Assert.False(agg.TryAbsorb(1, "/a", OpOpen, 0, 1, "p", "h", 0));
            Assert.False(agg.TryAbsorb(1, "/a", OpRead, 0, 1, "p", "h", 0)); // different op
            Assert.False(agg.TryAbsorb(1, "/b", OpOpen, 0, 1, "p", "h", 0)); // different path
            Assert.False(agg.TryAbsorb(2, "/a", OpOpen, 0, 1, "p", "h", 0)); // different pid
            Assert.Equal(4, agg.EntryCount);
        }

        [Fact]
        public void WindowRollover_FlushesOldEntry_AndStartsNewFirstOccurrence()
        {
            var (agg, emitted) = Create(windowMs: 1000);
            agg.TryAbsorb(1, "/a", OpOpen, 0, 1, "p", "h", 0);
            Assert.True(agg.TryAbsorb(1, "/a", OpOpen, 0, 2, "p", "h", 500));

            // Past the window: the old entry (1 repeat) flushes, this event is
            // a fresh first occurrence and must NOT be absorbed.
            Assert.False(agg.TryAbsorb(1, "/a", OpOpen, 0, 3, "p", "h", 1500));

            var summary = Assert.Single(emitted);
            Assert.Equal(1, summary.RepeatCount);
            Assert.Equal(1, agg.EntryCount);
        }

        [Fact]
        public void ZeroRepeatEntries_NeverEmitSummaries()
        {
            var (agg, emitted) = Create(windowMs: 1000);
            agg.TryAbsorb(1, "/a", OpOpen, 0, 1, "p", "h", 0);
            agg.FlushExpired(nowMs: 5000);
            Assert.Empty(emitted);
            Assert.Equal(0, agg.EntryCount);
        }

        [Fact]
        public void CapBypass_NeverAbsorbs_AndCounts()
        {
            var (agg, _) = Create(windowMs: 1000, maxKeys: 2);
            agg.TryAbsorb(1, "/a", OpOpen, 0, 1, "p", "h", 0);
            agg.TryAbsorb(1, "/b", OpOpen, 0, 1, "p", "h", 0);

            // Third distinct key: table full -> bypass, event emits per-event.
            Assert.False(agg.TryAbsorb(1, "/c", OpOpen, 0, 1, "p", "h", 0));
            Assert.False(agg.TryAbsorb(1, "/c", OpOpen, 0, 2, "p", "h", 1));
            Assert.Equal(2, agg.TakeCapBypass());

            // Existing keys still aggregate at the cap.
            Assert.True(agg.TryAbsorb(1, "/a", OpOpen, 0, 3, "p", "h", 10));
        }

        [Fact]
        public void FlushAll_DrainsEverything()
        {
            var (agg, emitted) = Create(windowMs: 60_000);
            agg.TryAbsorb(1, "/a", OpOpen, 5, 1, "p", "h", 0);
            agg.TryAbsorb(1, "/a", OpOpen, 5, 2, "p", "h", 1);
            agg.TryAbsorb(2, "/b", OpRead, 7, 3, "q", "i", 2);
            agg.TryAbsorb(2, "/b", OpRead, 7, 4, "q", "i", 3);

            agg.FlushAll();

            Assert.Equal(2, emitted.Count);
            Assert.Equal(0, agg.EntryCount);
            Assert.Equal(2, agg.TakeSummariesEmitted());
        }

        [Fact]
        public void IdentityComesFromFirstOccurrence_NotLaterEvents()
        {
            var (agg, emitted) = Create(windowMs: 1000);
            agg.TryAbsorb(1, "/a", OpOpen, 0, 1, "first-name", "first-hash", 0);
            // Later repeats claim different identity (e.g. comm truncation
            // artifacts); the summary must keep the first-occurrence stamp.
            agg.TryAbsorb(1, "/a", OpOpen, 0, 2, "other-name", "other-hash", 10);
            agg.FlushAll();

            var summary = Assert.Single(emitted);
            Assert.Equal("first-name", summary.ProcessName);
            Assert.Equal("first-hash", summary.PidHash);
        }

        [Fact]
        public void FlushExpired_RecordsTimingForCounterReporting()
        {
            var (agg, _) = Create();
            agg.FlushExpired(nowMs: 1);

            agg.TakeFlushTiming(out long flushCount, out long flushTicks, out long maxFlushTicks);

            Assert.Equal(1, flushCount);
            Assert.True(flushTicks >= 0);
            Assert.True(maxFlushTicks >= 0);

            agg.TakeFlushTiming(out flushCount, out flushTicks, out maxFlushTicks);
            Assert.Equal(0, flushCount);
            Assert.Equal(0, flushTicks);
            Assert.Equal(0, maxFlushTicks);
        }
    }
}
