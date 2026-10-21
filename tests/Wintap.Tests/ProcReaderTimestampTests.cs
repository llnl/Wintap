using System;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    public class ProcReaderTimestampTests
    {
        [Fact]
        public void OneDateTimeTickBoundarySkewCanonicalizesToSameLinuxClockTick()
        {
            DateTime boot = new DateTime(2026, 10, 21, 0, 0, 0, DateTimeKind.Utc);
            DateTime justBelowBoundary = boot.AddSeconds(100).AddTicks(8_099_999);
            DateTime exactBoundary = boot.AddSeconds(100).AddTicks(8_100_000);

            DateTime first = ProcReader.NormalizeStartTimeUtc(justBelowBoundary, boot, 100);
            DateTime second = ProcReader.NormalizeStartTimeUtc(exactBoundary, boot, 100);

            Assert.Equal(second, first);
            Assert.Equal(exactBoundary, first);
        }

        [Fact]
        public void DistinctLinuxClockTicksRemainDistinct()
        {
            DateTime boot = new DateTime(2026, 10, 21, 0, 0, 0, DateTimeKind.Utc);
            DateTime first = ProcReader.NormalizeStartTimeUtc(boot.AddMilliseconds(800), boot, 100);
            DateTime second = ProcReader.NormalizeStartTimeUtc(boot.AddMilliseconds(810), boot, 100);

            Assert.NotEqual(first, second);
            Assert.Equal(TimeSpan.FromMilliseconds(10), second - first);
        }
    }
}
