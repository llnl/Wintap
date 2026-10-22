using System;
using System.IO;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    public sealed class KernelTimestampConverterTests
    {
        [Fact, Trait("Category", "ldq-03")]
        public void ConvertsKernelMonotonicTimestampUsingIntegerNanoseconds()
        {
            const ulong monotonicNs = 12_345_678_901UL;
            const long offsetNs = 1_700_000_000_000_000_000L;

            DateTime actual = KernelTimestampConverter.ToUtcDateTime(monotonicNs, offsetNs);
            DateTime expected = DateTime.UnixEpoch.AddTicks((offsetNs + (long)monotonicNs) / 100);

            Assert.Equal(DateTimeKind.Utc, actual.Kind);
            Assert.Equal(expected, actual);
        }

        [Fact, Trait("Category", "ldq-03")]
        public void NetworkSensorUsesKernelEventTimeInsteadOfCallbackTime()
        {
            string source = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "NetworkSensor.cs"));
            int messageStart = source.IndexOf("var message = new WintapMessage(", StringComparison.Ordinal);
            Assert.True(messageStart >= 0);
            string setup = source.Substring(Math.Max(0, messageStart - 300), Math.Min(500, source.Length - Math.Max(0, messageStart - 300)));

            Assert.Contains("evt.TimestampNs", setup, StringComparison.Ordinal);
            Assert.Contains("eventTimeUtc", setup, StringComparison.Ordinal);
            Assert.DoesNotContain("new WintapMessage(\n                    DateTime.UtcNow", source, StringComparison.Ordinal);
        }
    }
}
