using System;
using System.Threading.Tasks;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class BoundedEventTimeCacheTests
    {
        [Fact, Trait("Category", "pai-01"), Trait("Category", "pai-03")]
        public void SamePidEvictionKeepsNewIdentityReachable()
        {
            var cache = new BoundedEventTimeCache<string>(1);
            cache.Set(42, "old", BaseTime, BaseTime.AddSeconds(10), "old");
            cache.Set(42, "new", BaseTime.AddSeconds(20), BaseTime.AddSeconds(30), "new");
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(25), out string value));
            Assert.Equal("new", value);
            Assert.False(cache.TryGet(42, BaseTime.AddSeconds(5), out _));
            cache.TakeCounters(out long hits, out long misses, out long evictions, out int entries);
            Assert.Equal(1, hits);
            Assert.Equal(1, misses);
            Assert.Equal(1, evictions);
            Assert.Equal(1, entries);
        }

        [Fact, Trait("Category", "pai-03")]
        public void SamePidEvictionPreservesAnotherPid()
        {
            var cache = new BoundedEventTimeCache<string>(2);
            cache.Set(42, "old", BaseTime, BaseTime.AddSeconds(10), "old");
            cache.Set(7, "other", BaseTime, BaseTime.AddSeconds(30), "other");
            cache.Set(42, "new", BaseTime.AddSeconds(20), BaseTime.AddSeconds(30), "new");

            Assert.False(cache.TryGet(42, BaseTime.AddSeconds(5), out _));
            Assert.True(cache.TryGet(7, BaseTime.AddSeconds(5), out string other));
            Assert.Equal("other", other);
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(25), out string newest));
            Assert.Equal("new", newest);
            cache.TakeCounters(out _, out _, out long evictions, out int entries);
            Assert.Equal(1, evictions);
            Assert.Equal(2, entries);
        }

        [Fact, Trait("Category", "pai-03")]
        public void SamePidEvictionPreservesSurvivingIdentities()
        {
            var cache = new BoundedEventTimeCache<string>(2);
            cache.Set(42, "old", BaseTime, BaseTime.AddSeconds(10), "old");
            cache.Set(42, "middle", BaseTime.AddSeconds(20), BaseTime.AddSeconds(30), "middle");
            cache.Set(42, "new", BaseTime.AddSeconds(40), BaseTime.AddSeconds(50), "new");

            Assert.False(cache.TryGet(42, BaseTime.AddSeconds(5), out _));
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(25), out string middle));
            Assert.Equal("middle", middle);
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(45), out string newest));
            Assert.Equal("new", newest);
            cache.TakeCounters(out _, out _, out long evictions, out int entries);
            Assert.Equal(1, evictions);
            Assert.Equal(2, entries);
        }

        [Fact, Trait("Category", "pai-03")]
        public void RepeatedSamePidEvictionRetainsOnlyLatestWithoutCountingProbes()
        {
            var cache = new BoundedEventTimeCache<int>(1);
            for (int i = 0; i < 100; i++)
            {
                DateTime start = BaseTime.AddSeconds(i * 20);
                cache.Set(42, i.ToString(), start, start.AddSeconds(10), i);
                Assert.True(cache.TryGet(42, start, out int current));
                Assert.Equal(i, current);
                Assert.False(cache.TryGet(42, start.AddTicks(-1), out _));
                Assert.True(cache.TryGetWithoutCounting(42, start, out int probe));
                Assert.Equal(i, probe);
                for (int old = 0; old < i; old++)
                {
                    Assert.False(cache.TryGetWithoutCounting(42, BaseTime.AddSeconds(old * 20), out _));
                }
                Assert.False(cache.TryGetWithoutCounting(42, start.AddSeconds(11), out _));
                cache.TakeCounters(out long hits, out long misses, out long evictions, out int entries);
                Assert.Equal(1, hits);
                Assert.Equal(1, misses);
                Assert.Equal(i == 0 ? 0 : 1, evictions);
                Assert.Equal(1, entries);
            }
            cache.TakeCounters(out long remainingHits, out long remainingMisses, out long remainingEvictions, out int remainingEntries);
            Assert.Equal(0, remainingHits);
            Assert.Equal(0, remainingMisses);
            Assert.Equal(0, remainingEvictions);
            Assert.Equal(1, remainingEntries);
        }

        [Theory, Trait("Category", "pai-01")]
        [InlineData(false)] [InlineData(true)]
        public void CurrentlySamePidControlsRemainReachable(bool updateSameIdentity)
        {
            var cache = new BoundedEventTimeCache<string>(updateSameIdentity ? 1 : 2);
            cache.Set(42, "old", BaseTime, BaseTime.AddSeconds(10), "old");
            cache.Set(42, updateSameIdentity ? "old" : "new", BaseTime.AddSeconds(20), BaseTime.AddSeconds(30), "new");
            // These controls already have the future-correct reachability behavior.
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(25), out string value));
            Assert.Equal("new", value);
            Assert.Equal(!updateSameIdentity, cache.TryGet(42, BaseTime.AddSeconds(5), out _));
            cache.TakeCounters(out _, out _, out long evictions, out int entries);
            Assert.Equal(updateSameIdentity ? 1 : 2, entries); Assert.Equal(0, evictions);
        }
        private static readonly DateTime BaseTime = new DateTime(2026, 8, 30, 12, 0, 0, DateTimeKind.Utc);

        [Fact]
        public void TryGet_RequiresEventInsideClosedInterval()
        {
            var cache = new BoundedEventTimeCache<string>(4);
            cache.Set(42, "instance-a", BaseTime, BaseTime.AddSeconds(10), "a");

            Assert.False(cache.TryGet(42, BaseTime.AddTicks(-1), out _));
            Assert.True(cache.TryGet(42, BaseTime, out string atStart));
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(10), out string atEnd));
            Assert.False(cache.TryGet(42, BaseTime.AddSeconds(10).AddTicks(1), out _));
            Assert.Equal("a", atStart);
            Assert.Equal("a", atEnd);
        }

        [Fact]
        public void TryGet_DistinguishesPidReuseByInterval()
        {
            var cache = new BoundedEventTimeCache<string>(4);
            cache.Set(42, "instance-a", BaseTime, BaseTime.AddSeconds(10), "a");
            cache.Set(42, "instance-b", BaseTime.AddSeconds(20), BaseTime.AddSeconds(30), "b");

            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(5), out string first));
            Assert.False(cache.TryGet(42, BaseTime.AddSeconds(15), out _));
            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(25), out string second));
            Assert.Equal("a", first);
            Assert.Equal("b", second);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void TryGet_OverlappingIntervalsChooseNewestInstance(bool insertNewestFirst)
        {
            var cache = new BoundedEventTimeCache<string>(4);
            void AddOlder() => cache.Set(42, "older", BaseTime, BaseTime.AddSeconds(30), "older");
            void AddNewer() => cache.Set(42, "newer", BaseTime.AddSeconds(20), BaseTime.AddSeconds(40), "newer");

            if (insertNewestFirst)
            {
                AddNewer();
                AddOlder();
            }
            else
            {
                AddOlder();
                AddNewer();
            }

            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(25), out string value));
            Assert.Equal("newer", value);
        }

        [Fact]
        public void Set_UpdatesExistingIdentityIntervalAndValue()
        {
            var cache = new BoundedEventTimeCache<string>(2);
            cache.Set(42, "instance", BaseTime, BaseTime.AddSeconds(10), "old");
            cache.Set(42, "instance", BaseTime, BaseTime.AddSeconds(20), "new");

            Assert.True(cache.TryGet(42, BaseTime.AddSeconds(15), out string value));
            Assert.Equal("new", value);
            cache.TakeCounters(out _, out _, out _, out int entries);
            Assert.Equal(1, entries);
        }

        [Fact]
        public void Set_EvictsLeastRecentlyUsedEntry()
        {
            var cache = new BoundedEventTimeCache<string>(2);
            cache.Set(1, "one", BaseTime, BaseTime.AddMinutes(1), "one");
            cache.Set(2, "two", BaseTime, BaseTime.AddMinutes(1), "two");
            Assert.True(cache.TryGet(1, BaseTime, out _));

            cache.Set(3, "three", BaseTime, BaseTime.AddMinutes(1), "three");

            Assert.True(cache.TryGet(1, BaseTime, out _));
            Assert.False(cache.TryGet(2, BaseTime, out _));
            Assert.True(cache.TryGet(3, BaseTime, out _));
            cache.TakeCounters(out _, out _, out long evictions, out int entries);
            Assert.Equal(1, evictions);
            Assert.Equal(2, entries);
        }

        [Fact]
        public void ConcurrentLookups_PreserveCorrectIdentity()
        {
            var cache = new BoundedEventTimeCache<int>(1024);
            for (int pid = 1; pid <= 1000; pid++)
            {
                cache.Set(pid, pid.ToString(), BaseTime, BaseTime.AddMinutes(1), pid);
            }

            Parallel.For(0, 100_000, i =>
            {
                int pid = i % 1000 + 1;
                Assert.True(cache.TryGet(pid, BaseTime.AddSeconds(30), out int value));
                Assert.Equal(pid, value);
            });

            cache.TakeCounters(out long hits, out long misses, out _, out int entries);
            Assert.Equal(100_000, hits);
            Assert.Equal(0, misses);
            Assert.Equal(1000, entries);
        }

        [Fact]
        public void DisabledCache_DoesNotRetainEntries()
        {
            var cache = new BoundedEventTimeCache<string>(0);
            cache.Set(42, "instance", BaseTime, BaseTime.AddMinutes(1), "value");

            Assert.False(cache.TryGet(42, BaseTime, out _));
            cache.TakeCounters(out long hits, out long misses, out long evictions, out int entries);
            Assert.Equal(0, hits);
            Assert.Equal(1, misses);
            Assert.Equal(0, evictions);
            Assert.Equal(0, entries);
        }

        [Fact]
        public void Clear_RemovesEntriesAndResetsCounters()
        {
            var cache = new BoundedEventTimeCache<string>(2);
            cache.Set(42, "instance", BaseTime, BaseTime.AddMinutes(1), "value");
            Assert.True(cache.TryGet(42, BaseTime, out _));

            cache.Clear();
            cache.TakeCounters(out long hits, out long misses, out long evictions, out int entries);

            Assert.Equal(0, hits);
            Assert.Equal(0, misses);
            Assert.Equal(0, evictions);
            Assert.Equal(0, entries);
            Assert.False(cache.TryGet(42, BaseTime, out _));
        }
    }
}
