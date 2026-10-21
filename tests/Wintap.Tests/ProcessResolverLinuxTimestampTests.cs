using System;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class ProcessResolverLinuxTimestampTests
    {
        [Fact]
        public void ProcStartTicksUseExactIntegerConversion()
        {
            DateTime boot = new DateTime(2026, 10, 21, 0, 0, 0, DateTimeKind.Utc);

            DateTime actual = ProcessResolver.ConvertLinuxProcStartTicksToUtc(boot, 10_081, 100);

            Assert.Equal(boot.AddSeconds(100).AddMilliseconds(810), actual);
            Assert.Equal(0, actual.Ticks % TimeSpan.TicksPerMillisecond);
        }
    }
}
