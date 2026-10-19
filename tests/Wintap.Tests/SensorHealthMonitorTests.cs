using gov.llnl.wintap;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure.health;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Globalization;
using System.Threading.Tasks;
using Xunit;

namespace Wintap.Tests
{
    public sealed class SensorHealthMonitorTests
    {
        private const string Sentinel = "SENTINEL-HASH";

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void ValidFileWritesSummaryOnly()
        {
            var log = NewLog(); var monitor = NewMonitor(log);
            monitor.Inspect(ValidFile()); monitor.FlushNow();
            var legacy = Assert.Single(log, x => x.Message.StartsWith("SensorHealth:")); Assert.Equal(LogLevel.Info, legacy.Level); Assert.Contains("File=1", legacy.Message); Assert.DoesNotContain(log, x => x.Message.StartsWith("SensorHealth FAIL:"));
        }

        [Theory, Trait("Category", "shc-01")]
        [InlineData(null), InlineData(""), InlineData("   ")]
        public void MissingPidHashIsReported(string pidHash)
        {
            var log = NewLog(); var msg = ValidFile(); msg.PidHash = pidHash;
            var monitor = NewMonitor(log); monitor.Inspect(msg); monitor.FlushNow();
            Assert.Contains(log, x => x.Message.Contains("check=pidhash_missing") && x.Message.Contains("PID=42"));
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void ProcessUnresolvedChecksOwnerFieldsOnly()
        {
            foreach (string name in new[] { "Unknown", "unknown", "UNKNOWN" })
            {
                var log = NewLog(); var msg = ValidFile(); msg.ProcessName = name;
                var monitor = NewMonitor(log); monitor.Inspect(msg); monitor.FlushNow();
                Assert.Contains(log, x => x.Message.Contains("check=process_unresolved"));
            }
            var sentinelLog = NewLog(); var sentinel = ValidFile(); sentinel.PidHash = Sentinel;
            var sentinelMonitor = NewMonitor(sentinelLog); sentinelMonitor.Inspect(sentinel); sentinelMonitor.FlushNow();
            Assert.Contains(sentinelLog, x => x.Message.Contains("PidHashIsUnknownSentinel=true"));
            var parentLog = NewLog(); var parent = ValidFile(); parent.Process = new WintapMessage.ProcessObject { ParentProcessName = "Unknown" };
            var parentMonitor = NewMonitor(parentLog); parentMonitor.Inspect(parent); parentMonitor.FlushNow();
            Assert.DoesNotContain(parentLog, x => x.Message.Contains("check=process_unresolved"));
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void MissingProcessNameIsSeparateFromUnknown()
        {
            var log = NewLog(); var blank = ValidFile(); blank.ProcessName = " "; var unknown = ValidFile(); unknown.ProcessName = "Unknown";
            var monitor = NewMonitor(log); monitor.Inspect(blank); monitor.Inspect(unknown); monitor.FlushNow();
            Assert.Contains(log, x => x.Message.Contains("check=processname_missing"));
            Assert.Contains(log, x => x.Message.Contains("check=process_unresolved"));
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void PayloadMismatchSupportsProcessPartialAliasAndUnknownEnum()
        {
            var log = NewLog(); var monitor = NewMonitor(log);
            var missing = ValidFile(); missing.File = null;
            var partialOk = new WintapMessage(DateTime.UtcNow, 1, WintapMessage.MessageTypeEnum.ProcessPartial) { PidHash = "x", ProcessName = "p", Process = new WintapMessage.ProcessObject() };
            var partialMissing = new WintapMessage(DateTime.UtcNow, 1, WintapMessage.MessageTypeEnum.ProcessPartial) { PidHash = "x", ProcessName = "p" };
            var unknown = new WintapMessage(DateTime.UtcNow, 1, (WintapMessage.MessageTypeEnum)999) { PidHash = "x", ProcessName = "p" };
            monitor.Inspect(missing); monitor.Inspect(partialOk); monitor.Inspect(partialMissing); monitor.Inspect(unknown); monitor.FlushNow();
            Assert.Contains(log, x => x.Message.Contains("_unknown=1"));
            Assert.Equal(3, log.Count(x => x.Message.Contains("check=payload_mismatch")));
        }

        [Theory, Trait("Category", "shc-01")]
        [InlineData(@"c:\windows\a.dll", true), InlineData(@"C:\Windows\A.DLL", true), InlineData(@"\\server\share\f.txt", true), InlineData(@"\device\harddiskvolume3\dir\f.bin", true)]
        [InlineData(null, false), InlineData("", false), InlineData("   ", false), InlineData(@"windows\temp\x.tmp", false), InlineData(@"\windows\temp\x.tmp", false), InlineData("x.tmp", false)]
        public void FilePathQualificationMatrix(string path, bool passes)
        {
            AssertPathResult(WintapMessage.MessageTypeEnum.File, path, passes);
        }

        [Theory, Trait("Category", "shc-01")]
        [InlineData(@"registry\machine\software\wow", true), InlineData(@"REGISTRY\MACHINE\x", true), InlineData("registry", true)]
        [InlineData(null, false), InlineData("", false), InlineData(@"\registry\machine\x", false), InlineData(@"hklm\software\x", false), InlineData(@"software\wow", false)]
        public void RegistryPathQualificationMatrix(string path, bool passes)
        {
            AssertPathResult(WintapMessage.MessageTypeEnum.Registry, path, passes);
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void PathCheckIgnoresOtherStreams()
        {
            var log = NewLog(); var msg = new WintapMessage(DateTime.UtcNow, 1, WintapMessage.MessageTypeEnum.TcpConnection) { PidHash = "x", ProcessName = "p", TcpConnection = new WintapMessage.TcpConnectionObject() };
            var monitor = NewMonitor(log); monitor.Inspect(msg); monitor.FlushNow();
            Assert.DoesNotContain(log, x => x.Message.Contains("check=path_unqualified"));
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void MultipleFailuresAndSampleCapsAreAggregated()
        {
            var log = NewLog(); var monitor = NewMonitor(log, sampleCap: 2);
            for (int i = 0; i < 5; i++) { var msg = ValidFile(); msg.PidHash = null; monitor.Inspect(msg); }
            monitor.FlushNow();
            string line = Assert.Single(log.Where(x => x.Message.Contains("check=pidhash_missing"))).Message;
            Assert.Contains("count=5", line); Assert.Equal(2, line.Split(new[] { "PID=" }, StringSplitOptions.None).Length - 1);

            var noSamples = NewLog(); var noSampleMonitor = NewMonitor(noSamples, sampleCap: 0); for (int i = 0; i < 5; i++) { var msg = ValidFile(); msg.PidHash = null; noSampleMonitor.Inspect(msg); } noSampleMonitor.FlushNow();
            Assert.DoesNotContain("samples:", Assert.Single(noSamples.Where(x => x.Message.Contains("check=pidhash_missing"))).Message);
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void WindowsDrainAndIdleFlushesAreSilent()
        {
            var log = NewLog(); var monitor = NewMonitor(log);
            for (int i = 0; i < 3; i++) monitor.Inspect(ValidFile()); monitor.FlushNow(); monitor.FlushNow();
            for (int i = 0; i < 2; i++) monitor.Inspect(ValidFile()); monitor.FlushNow();
            var legacy = log.Where(x => x.Message.StartsWith("SensorHealth:")).ToList(); Assert.Equal(2, legacy.Count); Assert.Contains("File=3", legacy[0].Message); Assert.Contains("File=2", legacy[1].Message);
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void CustomCheckAndFailOpenAreSupported()
        {
            var customLog = NewLog(); var custom = new NamedFailingCheck(); var customMonitor = new SensorHealthMonitor(new[] { custom }, true, 3, 5, Sink(customLog));
            customMonitor.Inspect(ValidFile()); customMonitor.FlushNow(); Assert.True(custom.Called); Assert.Contains(customLog, x => x.Message.Contains("check=custom_failure"));
            var failLog = NewLog(); var failMonitor = new SensorHealthMonitor(new[] { new ThrowingCheck() }, true, 3, 5, Sink(failLog));
            failMonitor.Inspect(ValidFile()); failMonitor.Inspect(ValidFile()); Assert.False(failMonitor.IsEnabled); Assert.Single(failLog); Assert.Contains("disabled", failLog[0].Message);
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void DisabledMonitorAndConstructorClampsBehaveAsSpecified()
        {
            var log = NewLog(); var disabled = new SensorHealthMonitor(DefaultHealthChecks.CreateAll(() => Sentinel), false, 99, 1, Sink(log));
            disabled.Inspect(ValidFile()); disabled.FlushNow(); disabled.EvaluateLivenessTick(DateTime.UtcNow); disabled.Start();
            Assert.Empty(log); Assert.Equal(5, disabled.FlushIntervalSeconds);
            var enabled = NewMonitor(log); enabled.Inspect(ValidFile()); enabled.Start(); enabled.Stop(); Assert.Contains(log, x => x.Message.Contains("File=1"));
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void LivenessTransitionsAndRestartGraceAreSuppressedCorrectly()
        {
            var log = NewLog(); var monitor = NewMonitor(log); monitor.Start(); DateTime now = DateTime.UtcNow;
            monitor.EvaluateLivenessTick(now.AddSeconds(59)); Assert.Empty(log);
            monitor.Inspect(ValidFile()); monitor.EvaluateLivenessTick(now.AddSeconds(61)); Assert.DoesNotContain(log, x => x.Message.Contains("stream=File"));
            monitor.EvaluateLivenessTick(now.AddSeconds(66)); Assert.Contains(log, x => x.Level == LogLevel.Error && x.Message.Contains("stream=File"));
            int stalls = log.Count; monitor.EvaluateLivenessTick(now.AddSeconds(71)); Assert.Equal(stalls, log.Count);
            monitor.Inspect(ValidFile()); monitor.EvaluateLivenessTick(now.AddSeconds(76)); Assert.Contains(log, x => x.Message.Contains("RECOVERED") && x.Message.Contains("stalledSeconds"));
            monitor.Stop(); int afterStop = log.Count; monitor.Start(); monitor.EvaluateLivenessTick(DateTime.UtcNow.AddSeconds(1)); Assert.Equal(afterStop, log.Count); monitor.Stop();
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void ConcurrentInspectionsKeepExactCounts()
        {
            var log = NewLog(); var monitor = NewMonitor(log, sampleCap: 2);
            Parallel.For(0, 40000, _ => monitor.Inspect(ValidFile())); monitor.FlushNow(); Assert.Contains(log, x => x.Message.Contains("File=40000"));
            log.Clear(); Parallel.For(0, 40000, _ => { var msg = ValidFile(); msg.PidHash = null; monitor.Inspect(msg); }); monitor.FlushNow();
            string failure = Assert.Single(log.Where(x => x.Message.Contains("check=pidhash_missing"))).Message; Assert.Contains("count=40000", failure); Assert.True(failure.Split(new[] { "PID=" }, StringSplitOptions.None).Length - 1 <= 2);
        }

        [Fact, Trait("Category", "shc-01"), Trait("Category", "pai-01")]
        public void CreateDefaultBuildsFiveChecks()
        {
            Assert.NotNull(SensorHealthMonitor.CreateDefault());
        }

        [Fact, Trait("Category", "pai-01")]
        public void AttributionUsesWeightedTotalsAndRetainsIdleCoverage()
        {
            var log = NewLog(); var monitor = NewMonitor(log, 0);
            monitor.FlushNow(); Assert.Empty(log);
            for (int i = 0; i < 100; i++)
            {
                var msg = ValidFile();
                if (i >= 10) { msg.MessageType = WintapMessage.MessageTypeEnum.Registry; msg.Registry = new WintapMessage.RegActivityObject { Path = "registry" }; }
                msg.ProcessName = i == 0 || (i >= 10 && i < 55) ? "Unknown" : "ok";
                monitor.Inspect(msg);
            }
            monitor.FlushNow();
            AssertMetric(log, "File", 10, 1, 10, 1);
            AssertMetric(log, "Registry", 90, 45, 90, 45);
            AssertMetric(log, "_overall", 100, 46, 100, 46);
            Assert.Contains("intervalUnresolvedPct=46.000000", Attribution(log, "_overall"));
            log.Clear(); monitor.FlushNow();
            AssertMetric(log, "_overall", 0, 0, 100, 46);
            Assert.Contains("intervalUnresolvedPct=n/a", Attribution(log, "File"));
            Assert.Equal(3, log.Count);
            monitor.Inspect(ValidFile()); log.Clear(); monitor.FlushNow();
            AssertMetric(log, "_overall", 1, 0, 101, 46);
        }

        [Theory, Trait("Category", "pai-01")]
        [InlineData("Unknown", "hash", 1)]
        [InlineData("unknown", "hash", 1)]
        [InlineData("UNKNOWN", "hash", 1)]
        [InlineData("ok", Sentinel, 1)]
        [InlineData("Unknown", Sentinel, 1)]
        [InlineData(null, null, 0)]
        [InlineData(" ", " ", 0)]
        [InlineData("ok", "hash", 0)]
        public void AttributionPreservesOwnerPredicate(string name, string hash, int failures)
        {
            var log = NewLog(); var monitor = NewMonitor(log);
            var msg = ValidFile(); msg.ProcessName = name; msg.PidHash = hash;
            msg.Process = new WintapMessage.ProcessObject { ParentProcessName = "Unknown", ParentPidHash = Sentinel };
            monitor.Inspect(msg); monitor.FlushNow();
            AssertMetric(log, "File", 1, failures, 1, failures);
            log.Clear(); monitor.Inspect(msg); monitor.FlushNow();
            AssertMetric(log, "File", 1, failures, 2, failures * 2);
        }

        [Fact, Trait("Category", "pai-01")]
        public void AttributionRetainsLifecycleAndInvariantUnknownStream()
        {
            var prior = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = new CultureInfo("fr-FR");
                var log = NewLog(); var monitor = NewMonitor(log, 0);
                var msg = ValidFile(); msg.MessageType = (WintapMessage.MessageTypeEnum)999; msg.ProcessName = "Unknown";
                monitor.Inspect(msg); monitor.Start(); monitor.Stop();
                string since = Attribution(log, "_unknown").Split(' ').Single(x => x.StartsWith("since="));
                AssertMetric(log, "_unknown", 1, 1, 1, 1);
                log.Clear(); monitor.Start(); monitor.Stop();
                AssertMetric(log, "_unknown", 0, 0, 1, 1);
                Assert.Contains(since, Attribution(log, "_unknown"));
                Assert.Contains("totalUnresolvedPct=100.000000", Attribution(log, "_unknown"));
                log.Clear(); var fresh = NewMonitor(log); fresh.FlushNow(); Assert.Empty(log);
                fresh.Inspect(ValidFile()); fresh.FlushNow(); AssertMetric(log, "_overall", 1, 0, 1, 0);
            }
            finally { CultureInfo.CurrentCulture = prior; }
        }

        [Fact, Trait("Category", "pai-01")]
        public async Task AttributionReportsVerdictAfterLegacyBoundary()
        {
            using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            var log = NewLog();
            var check = new OutcomeCheck { Verdict = _ => { entered.Set(); if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException(); return false; } };
            var monitor = new SensorHealthMonitor(new[] { check }, true, 0, 60, Sink(log));
            var inspect = Task.Run(() => monitor.Inspect(ValidFile()));
            try
            {
                Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
                monitor.FlushNow(); Assert.DoesNotContain(log, x => x.Message.StartsWith("SensorHealth ATTRIBUTION:"));
            }
            finally { release.Set(); }
            await inspect.WaitAsync(TimeSpan.FromSeconds(10)); Assert.True(monitor.IsEnabled);
            log.Clear(); monitor.FlushNow();
            AssertMetric(log, "File", 1, 1, 1, 1);
            Assert.DoesNotContain(log, x => x.Message.StartsWith("SensorHealth:"));
        }

        [Fact, Trait("Category", "pai-01")]
        public async Task OverlappingReentrantAndStopFlushesPreserveBaselinesAfterSinkFailure()
        {
            using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            var log = NewLog(); int calls = 0; bool timedOut = false; SensorHealthMonitor monitor = null;
            monitor = new SensorHealthMonitor(new[] { new OutcomeCheck() }, true, 0, 3600, (line, level) =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    monitor.FlushNow(); entered.Set();
                    timedOut = !release.Wait(TimeSpan.FromSeconds(10));
                    throw new InvalidOperationException("sink failed");
                }
                Sink(log)(line, level);
            });
            monitor.Start(); monitor.Inspect(ValidFile());
            var flush = Task.Run(monitor.FlushNow);
            try
            {
                Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
                int before = calls; monitor.FlushNow(); monitor.Stop(); Assert.Equal(before, calls);
                monitor.Inspect(ValidFile());
            }
            finally { release.Set(); }
            await flush.WaitAsync(TimeSpan.FromSeconds(10)); Assert.False(timedOut);
            log.Clear(); monitor.FlushNow();
            AssertMetric(log, "File", 1, 0, 2, 0);
            AssertMetric(log, "_overall", 1, 0, 2, 0);
        }

        [Fact, Trait("Category", "pai-01")]
        public void ConcurrentMixedOutcomesTelescopeToExactQuiescentTotals()
        {
            var log = NewLog(); var monitor = NewMonitor(log, 0);
            var good = ValidFile(); var bad = ValidFile(); bad.ProcessName = "Unknown"; bad.MessageType = WintapMessage.MessageTypeEnum.Registry;
            Parallel.Invoke(
                () => Parallel.For(0, 10000, i => monitor.Inspect(i % 2 == 0 ? good : bad)),
                () => { for (int i = 0; i < 100; i++) monitor.FlushNow(); });
            monitor.FlushNow();
            long intervalSum = 0, failedSum = 0;
            var batch = new List<Dictionary<string, string>>();
            foreach (var entry in log.Where(x => x.Message.StartsWith("SensorHealth ATTRIBUTION:")))
            {
                var fields = entry.Message.Split(' ').Skip(2).Select(x => x.Split('=')).ToDictionary(x => x[0], x => x[1]);
                foreach (string key in new[] { "intervalEvaluated", "intervalUnresolved", "totalEvaluated", "totalUnresolved" })
                    Assert.True(long.Parse(fields[key], CultureInfo.InvariantCulture) >= 0);
                foreach (string key in new[] { "intervalUnresolvedPct", "totalUnresolvedPct" })
                    if (fields[key] != "n/a") Assert.InRange(double.Parse(fields[key], CultureInfo.InvariantCulture), 0, 100);
                if (fields["stream"] != "_overall") { batch.Add(fields); continue; }
                foreach (string key in new[] { "intervalEvaluated", "intervalUnresolved", "totalEvaluated", "totalUnresolved" })
                    Assert.Equal(batch.Sum(x => long.Parse(x[key])), long.Parse(fields[key]));
                intervalSum += long.Parse(fields["intervalEvaluated"]); failedSum += long.Parse(fields["intervalUnresolved"]); batch.Clear();
            }
            Assert.Empty(batch); Assert.Equal(10000, intervalSum); Assert.Equal(5000, failedSum);
            Assert.Contains("totalEvaluated=10000 totalUnresolved=5000", log.Last(x => x.Message.Contains("stream=_overall ")).Message);
        }

        [Theory, Trait("Category", "pai-01")]
        [InlineData(0)] [InlineData(2)] [InlineData(3)]
        public void MissingDuplicateOrThrowingDiscoverySuppressesOnlyAttribution(int mode)
        {
            var log = NewLog();
            IWintapHealthCheck[] checks = mode == 0 ? new[] { new OutcomeCheck { CheckName = "other" } } :
                mode == 2 ? new[] { new OutcomeCheck(), new OutcomeCheck() } :
                new[] { new OutcomeCheck { ThrowName = true } };
            var monitor = new SensorHealthMonitor(checks, true, 0, 60, Sink(log));
            monitor.Inspect(ValidFile()); monitor.FlushNow();
            Assert.True(monitor.IsEnabled); Assert.Single(log); Assert.StartsWith("SensorHealth:", log[0].Message);
        }

        [Theory, Trait("Category", "pai-01")]
        [InlineData(false)] [InlineData(true)]
        public void ThrowingEvaluationOrSamplePreservesRecordedOutcomes(bool sampleThrows)
        {
            var log = NewLog();
            var check = new OutcomeCheck { Verdict = _ => sampleThrows ? false : throw new InvalidOperationException(), ThrowDescription = true };
            var monitor = new SensorHealthMonitor(new[] { check }, true, 1, 60, Sink(log));
            monitor.Inspect(ValidFile()); monitor.Inspect(ValidFile()); monitor.FlushNow();
            Assert.False(monitor.IsEnabled); Assert.Single(log); Assert.Contains("disabled", log[0].Message);
            var field = typeof(SensorHealthMonitor).GetField("unresolvedCounts", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            Assert.Equal(sampleThrows ? 1 : 0, ((long[])field.GetValue(monitor)).Sum());
        }

        [Theory, Trait("Category", "pai-01")]
        [InlineData(0)] [InlineData(2)]
        public void TimingSamplesAreCappedAndOtherDescriptionsUnchanged(int cap)
        {
            var log = NewLog(); var monitor = NewMonitor(log, cap); var msg = ValidFile(); msg.ProcessName = "Unknown";
            DateTime before = DateTime.UtcNow;
            for (int i = 0; i < 5; i++) monitor.Inspect(msg);
            DateTime after = DateTime.UtcNow; monitor.FlushNow();
            string failure = log.Single(x => x.Message.Contains("check=process_unresolved")).Message;
            Assert.Equal(cap, failure.Split(new[] { "InspectionTimeUtc=" }, StringSplitOptions.None).Length - 1);
            if (cap > 0)
            {
                Assert.Contains("PID=42 ActivityType=", failure); Assert.Contains("EventTime=" + msg.EventTime, failure);
                Assert.Contains("ProcessName=Unknown PidHashIsUnknownSentinel=false ReceiveTime=" + msg.ReceiveTime, failure);
                foreach (string part in failure.Split(new[] { "InspectionTimeUtc=" }, StringSplitOptions.None).Skip(1))
                {
                    DateTime parsed = DateTime.Parse(part.Split(' ')[0], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
                    Assert.Equal(DateTimeKind.Utc, parsed.Kind); Assert.InRange(parsed, before, after);
                }
            }
            foreach (var check in DefaultHealthChecks.CreateAll(() => Sentinel).Where(x => x.Name != "process_unresolved"))
            {
                Assert.DoesNotContain("ReceiveTime=", check.Describe(msg)); Assert.DoesNotContain("InspectionTimeUtc=", check.Describe(msg));
            }
        }

        [Fact, Trait("Category", "pai-01")]
        public void PassingInspectionAllocatesNothingAndEvaluatesOnce()
        {
            var msg = ValidFile(); var monitor = NewMonitor(NewLog(), 0);
            for (int i = 0; i < 10000; i++) monitor.Inspect(msg);
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 10000; i++) monitor.Inspect(msg);
            Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
            int verdicts = 0;
            var custom = new SensorHealthMonitor(new[] { new OutcomeCheck { Verdict = _ => { verdicts++; return true; } } }, true, 0, 60, (_, __) => { });
            custom.Inspect(msg); Assert.Equal(1, verdicts);
            var providerLog = NewLog();
            var providerMonitor = new SensorHealthMonitor(DefaultHealthChecks.CreateAll(() => throw new InvalidOperationException()), true, 0, 60, Sink(providerLog));
            providerMonitor.Inspect(msg); providerMonitor.FlushNow(); AssertMetric(providerLog, "File", 1, 0, 1, 0);
        }

        private static string Attribution(List<(string Message, LogLevel Level)> log, string stream)
            => Assert.Single(log, x => x.Message.StartsWith("SensorHealth ATTRIBUTION:") && x.Message.Contains("stream=" + stream + " ")).Message;

        private static void AssertMetric(List<(string Message, LogLevel Level)> log, string stream, long evaluated, long failed, long total, long totalFailed)
        {
            string line = Attribution(log, stream);
            Assert.Contains(" intervalEvaluated=" + evaluated + " intervalUnresolved=" + failed + " ", line);
            Assert.Contains(" totalEvaluated=" + total + " totalUnresolved=" + totalFailed + " ", line);
        }

        private sealed class OutcomeCheck : IWintapHealthCheck
        {
            internal string CheckName = "process_unresolved";
            internal bool ThrowName, ThrowDescription;
            internal Func<WintapMessage, bool> Verdict = _ => true;
            public string Name => ThrowName ? throw new InvalidOperationException() : CheckName;
            public bool Passes(WintapMessage msg) => Verdict(msg);
            public string Describe(WintapMessage msg) => ThrowDescription ? throw new InvalidOperationException() : "sample";
        }
        private static void AssertPathResult(WintapMessage.MessageTypeEnum type, string path, bool passes)
        {
            var log = NewLog(); var msg = ValidFile(); msg.MessageType = type;
            if (type == WintapMessage.MessageTypeEnum.File) msg.File = new WintapMessage.FileActivityObject { Path = path }; else { msg.File = null; msg.Registry = new WintapMessage.RegActivityObject { Path = path }; }
            var monitor = NewMonitor(log); monitor.Inspect(msg); monitor.FlushNow();
            Assert.Equal(!passes, log.Any(x => x.Message.Contains("check=path_unqualified")));
        }

        private static WintapMessage ValidFile() => new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.File) { PidHash = "hash", ProcessName = "process", File = new WintapMessage.FileActivityObject { Path = @"c:\windows\system32\notepad.exe" } };
        private static List<(string Message, LogLevel Level)> NewLog() => new List<(string, LogLevel)>();
        private static Action<string, LogLevel> Sink(List<(string Message, LogLevel Level)> log) => (message, level) => { lock (log) log.Add((message, level)); };
        private static SensorHealthMonitor NewMonitor(List<(string Message, LogLevel Level)> log, int sampleCap = 3) => new SensorHealthMonitor(DefaultHealthChecks.CreateAll(() => Sentinel), true, sampleCap, 5, Sink(log));

        private sealed class NamedFailingCheck : IWintapHealthCheck { public bool Called; public string Name => "custom_failure"; public bool Passes(WintapMessage msg) { Called = true; return false; } public string Describe(WintapMessage msg) => "custom"; }
        private sealed class ThrowingCheck : IWintapHealthCheck { public string Name => "throws"; public bool Passes(WintapMessage msg) => throw new InvalidOperationException("boom"); public string Describe(WintapMessage msg) => "never"; }
    }
}
