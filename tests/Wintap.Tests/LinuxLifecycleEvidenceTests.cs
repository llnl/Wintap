using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    public class LinuxLifecycleEvidenceTests
    {
        [Theory]
        [InlineData(0UL, 20UL, "unknown", "unknown")]
        [InlineData(100UL, 99UL, "unknown", "unknown")]
        [InlineData(100UL, 100UL, "short-lived", "lt100ms")]
        [InlineData(1UL, 100000001UL, "short-lived", "100ms-1s")]
        [InlineData(1UL, 1000000001UL, "short-lived", "100ms-1s")]
        [InlineData(1UL, 1000000002UL, "longer-lived", "1s-10s")]
        [InlineData(1UL, 10000000001UL, "longer-lived", "1s-10s")]
        [InlineData(1UL, 10000000002UL, "longer-lived", "gt10s")]
        public void DurationUsesSameClockAndExplicitUnknown(ulong start, ulong exit, string lifetime, string bin)
        {
            var row = LinuxLifecycleEvidence.Classify(10, "hash", "kernel-start", "mandb", 42, exit, start, 900);
            Assert.Equal(lifetime, row.LifetimeClass);
            Assert.Equal(bin, row.LifetimeBin);
            Assert.Equal("leader-exit", row.ExitSemantics);
            Assert.Equal("low", row.RoleConfidence);
            Assert.Equal("hash", row.PidHash);
        }

        [Fact]
        public void MissingStartNeverInvokesHashFormula()
        {
            Assert.Equal("unknown", LinuxLifecycleEvidence.SelectExitHash(null, null, null,
                _ => throw new Exception("event time must not be hashed"), "unknown"));
            Assert.Equal("birth", LinuxLifecycleEvidence.SelectExitHash("birth", "live", null,
                _ => throw new Exception(), "unknown"));
            Assert.Equal("live", LinuxLifecycleEvidence.SelectExitHash(null, "live", null,
                _ => throw new Exception(), "unknown"));
        }

        [Fact]
        public void KernelStartGoesToExistingFormulaWithoutExitTime()
        {
            DateTime start = new DateTime(2026, 10, 23, 0, 0, 0, DateTimeKind.Utc);
            long received = 0;
            Assert.Equal("canonical", LinuxLifecycleEvidence.SelectExitHash(null, null, start,
                value => { received = value; return "canonical"; }, "unknown"));
            Assert.Equal(start.ToFileTimeUtc(), received);
        }

        [Fact]
        public void AbiReadsOldPrefixWithoutReadingBeyondIt()
        {
            IntPtr data = Marshal.AllocHGlobal(64);
            try
            {
                Marshal.WriteInt64(data, 48, 123);
                Marshal.WriteInt64(data, 56, 456);
                Assert.Equal((0UL, 0UL), LinuxLifecycleEvidence.ReadStartTimes(data, 48));
                Assert.Equal((123UL, 456UL), LinuxLifecycleEvidence.ReadStartTimes(data, 64));
                Assert.Throws<ArgumentException>(() => LinuxLifecycleEvidence.ReadStartTimes(data, 47));
                Assert.Throws<ArgumentException>(() => LinuxLifecycleEvidence.ReadStartTimes(data, 56));
            }
            finally { Marshal.FreeHGlobal(data); }
        }

        [Fact]
        public void CloneAbiKeepsLegacyPrefixAndRejectsUnsupportedSizes()
        {
            IntPtr data = Marshal.AllocHGlobal(56);
            try
            {
                Marshal.WriteInt64(data, 48, 123);
                Assert.Equal(0UL, LinuxLifecycleEvidence.ReadCloneStart(data, 48));
                Assert.Equal(123UL, LinuxLifecycleEvidence.ReadCloneStart(data, 56));
                foreach (ulong size in new[] { 0UL, 47UL, 49UL, 55UL, 64UL })
                    Assert.Throws<ArgumentException>(() => LinuxLifecycleEvidence.ReadCloneStart(data, size));
            }
            finally { Marshal.FreeHGlobal(data); }
        }

        [Fact]
        public void CloneBirthUsesTaskStartNotForkOccurrenceOrReusedProc()
        {
            DateTime start = new DateTime(2026, 10, 24, 0, 0, 0, DateTimeKind.Utc);
            Assert.Equal(start, LinuxLifecycleEvidence.SelectBirthStart(start, start.AddMilliseconds(10)));
            Assert.Equal(start, LinuxLifecycleEvidence.SelectBirthStart(start, default));
            Assert.Equal(start, LinuxLifecycleEvidence.SelectBirthStart(null, start));
            Assert.Null(LinuxLifecycleEvidence.SelectBirthStart(null, default));
        }

        [Fact]
        public void ShadowWriterDrainsAndRefusesOverwritingEvidence()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".jsonl");
            try
            {
                using (var writer = new LifecycleShadowWriter(path))
                    Assert.True(writer.TryWrite(LinuxLifecycleEvidence.Classify(10, null, "unresolved", "strange", 42, 100, 0, 0)));
                string[] lines = File.ReadAllLines(path);
                Assert.Equal(2, lines.Length);
                using var row = JsonDocument.Parse(lines[0]);
                Assert.Equal("unknown", row.RootElement.GetProperty("LifetimeClass").GetString());
                Assert.Equal(JsonValueKind.Null, row.RootElement.GetProperty("PidHash").ValueKind);
                Assert.Throws<IOException>(() => new LifecycleShadowWriter(path));
            }
            finally { File.Delete(path); }
        }
    }
}
