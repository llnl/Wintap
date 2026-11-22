using gov.llnl.wintap.platform.windows.infrastructure;
using gov.llnl.wintap.platform.windows.collect.etw;
using Microsoft.Diagnostics.Tracing.Parsers;
using gov.llnl.wintap;
using System;
using System.Collections.Generic;
using System.Reflection;
using Xunit;

namespace Wintap.Tests
{
    public class WindowsSubscriptionManagerTests
    {
        [Fact]
        [Trait("Category", "wpc-collector-combinations")]
        public void ComputeFinalKernelFlags_ProcessOnlyUsesProcessFlag()
        {
            KernelTraceEventParser.Keywords flags = WindowsSubscriptionManager.ComputeFinalKernelFlags(null);

            Assert.Equal(KernelTraceEventParser.Keywords.Process, flags);
        }

        [Fact]
        [Trait("Category", "wpc-collector-combinations")]
        public void ComputeFinalKernelFlags_ProcessAndFileIncludesFileIoInitAndDiskFileIo()
        {
            KernelTraceEventParser.Keywords flags = WindowsSubscriptionManager.ComputeFinalKernelFlags(
                new[] { KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.DiskFileIO });

            Assert.Equal(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.DiskFileIO,
                flags);
        }

        [Fact]
        [Trait("Category", "fio-01")]
        public void FileSensor_DeclaresFileIoInitAndDiskFileIoKernelFlags()
        {
            KernelTraceEventParser.Keywords flags = WindowsSubscriptionManager.GetKernelTraceFlags(new FileSensor());

            Assert.True(flags.HasFlag(KernelTraceEventParser.Keywords.FileIOInit));
            Assert.True(flags.HasFlag(KernelTraceEventParser.Keywords.DiskFileIO));
        }

        [Fact]
        [Trait("Category", "fio-02")]
        public void FileSensor_SubscriptionPlanSuppressesCloseAndPreservesDefaultHandlers()
        {
            FileSensor.FileIoSubscription[] plan = FileSensor.BuildSubscriptionPlan(collectFileRead: false);

            Assert.Contains(FileSensor.FileIoSubscription.Write, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Delete, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Name, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Create, plan);
            Assert.DoesNotContain(FileSensor.FileIoSubscription.Read, plan);
            Assert.DoesNotContain(FileSensor.FileIoSubscription.Close, plan);
        }

        [Fact]
        [Trait("Category", "fio-02")]
        public void FileSensor_SubscriptionPlanKeepsReadSettingGateAndStillSuppressesClose()
        {
            FileSensor.FileIoSubscription[] plan = FileSensor.BuildSubscriptionPlan(collectFileRead: true);

            Assert.Contains(FileSensor.FileIoSubscription.Write, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Delete, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Name, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Create, plan);
            Assert.Contains(FileSensor.FileIoSubscription.Read, plan);
            Assert.DoesNotContain(FileSensor.FileIoSubscription.Close, plan);
        }

        [Fact]
        [Trait("Category", "fio-02")]
        public void FileSensor_CloseSuppressionPreservesFileIoInitAndDiskFileIoKernelFlags()
        {
            KernelTraceEventParser.Keywords flags = WindowsSubscriptionManager.GetKernelTraceFlags(new FileSensor());

            Assert.True(flags.HasFlag(KernelTraceEventParser.Keywords.FileIOInit));
            Assert.True(flags.HasFlag(KernelTraceEventParser.Keywords.DiskFileIO));
        }

        [Fact]
        [Trait("Category", "fio-03")]
        public void FileSensor_TraceEventOnlyPathSelectionUsesProvidedFileName()
        {
            string path = FileSensor.SelectTraceEventFileNameOnly(@"c:\temp\traceevent-path.txt");

            Assert.Equal(@"c:\temp\traceevent-path.txt", path);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [Trait("Category", "fio-03")]
        public void FileSensor_TraceEventOnlyPathSelectionDoesNotReplaceMissingFileName(string traceEventFileName)
        {
            string path = FileSensor.SelectTraceEventFileNameOnly(traceEventFileName);

            Assert.Equal(traceEventFileName, path);
        }

        [Fact]
        [Trait("Category", "fio-03")]
        public void FileSensor_DiagnosticFallbackDisablePreservesCloseSuppressionAndKernelFlags()
        {
            FileSensor.FileIoSubscription[] plan = FileSensor.BuildSubscriptionPlan(collectFileRead: true);
            KernelTraceEventParser.Keywords flags = WindowsSubscriptionManager.GetKernelTraceFlags(new FileSensor());

            Assert.DoesNotContain(FileSensor.FileIoSubscription.Close, plan);
            Assert.True(flags.HasFlag(KernelTraceEventParser.Keywords.FileIOInit));
            Assert.True(flags.HasFlag(KernelTraceEventParser.Keywords.DiskFileIO));
        }

        [Fact]
        [Trait("Category", "wpc-collector-combinations")]
        public void CreateStartupPlan_MultipleSharedKernelSensorsComputesSingleFinalMask()
        {
            CollectorStartupPlan plan = WindowsSubscriptionManager.CreateStartupPlan(new[]
            {
                WindowsSubscriptionManager.CreateCollectorEntry("File", new FileSensor()),
                WindowsSubscriptionManager.CreateCollectorEntry("Tcp", new TcpSensor()),
                WindowsSubscriptionManager.CreateCollectorEntry("Udp", new UdpSensor()),
                WindowsSubscriptionManager.CreateCollectorEntry("ImageLoad", new ImageLoadSensor())
            });

            KernelTraceEventParser.Keywords expected =
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.DiskFileIO |
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.ImageLoad;

            Assert.Equal(expected, plan.FinalKernelFlags);
            Assert.Equal(4, plan.SharedKernelSensors.Count);
            Assert.Empty(plan.IndependentSensors);
        }

        [Fact]
        [Trait("Category", "wpc-collector-combinations")]
        public void CreateStartupPlan_RegistryAndCpuTriggerAreIndependent()
        {
            CollectorStartupPlan plan = WindowsSubscriptionManager.CreateStartupPlan(new[]
            {
                WindowsSubscriptionManager.CreateCollectorEntry("Registry", new RegistrySensor()),
                WindowsSubscriptionManager.CreateCollectorEntry("CpuTrigger", new CpuTriggerSensor())
            });

            Assert.Equal(KernelTraceEventParser.Keywords.Process, plan.FinalKernelFlags);
            Assert.Empty(plan.SharedKernelSensors);
            Assert.Equal(2, plan.IndependentSensors.Count);
        }

        [Fact]
        [Trait("Category", "wpc-collector-combinations")]
        public void StartupPlan_EnablesKernelBeforeSharedAndIndependentSensors()
        {
            CollectorStartupPlan plan = WindowsSubscriptionManager.CreateStartupPlan(new[]
            {
                WindowsSubscriptionManager.CreateCollectorEntry("File", new FileSensor()),
                WindowsSubscriptionManager.CreateCollectorEntry("Registry", new RegistrySensor())
            });

            AssertOrder(plan, "EnableKernelProvider", "StartSharedKernelSensors");
            AssertOrder(plan, "EnableKernelProvider", "InitializeProcessBootstrap");
            AssertOrder(plan, "InitializeProcessBootstrap", "StartProcessSensor");
            AssertOrder(plan, "StartProcessSensor", "ReplayBootProcessTrace");
            AssertOrder(plan, "ReplayBootProcessTrace", "InitializeProcessSnapshotDelta");
            AssertOrder(plan, "InitializeProcessSnapshotDelta", "ValidateExplorerProcessLineage");
            AssertOrder(plan, "ValidateExplorerProcessLineage", "StartSharedKernelSensors");
            AssertOrder(plan, "StartSharedKernelSensors", "StartKernelConsumer");
            AssertOrder(plan, "StartKernelConsumer", "StartIndependentSensors");
        }

        [Fact]
        [Trait("Category", "wpc-collector-combinations")]
        public void FileSensor_StartOverridesBaseForSharedKernelSubscriptionPath()
        {
            MethodInfo start = typeof(FileSensor).GetMethod("Start", BindingFlags.Instance | BindingFlags.Public);

            Assert.NotNull(start);
            Assert.Equal(typeof(FileSensor), start.DeclaringType);
            Assert.True(WindowsSubscriptionManager.IsSharedKernelSensor(new FileSensor()));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        [Trait("Category", "wpc-10")]
        public void ExecuteProcessStartup_BootstrapThenReplayThenDeltaBeforeConsumer(bool reset)
        {
            var executed = new List<string>();
            var logs = new List<(string Message, LogLevel Level)>();
            bool seedsReady = false;
            bool replayHistoryReady = false;
            WindowsSubscriptionManager.ExecuteProcessStartup(
                true, "fixture.etl",
                () =>
                {
                    executed.Add(reset ? "clear" : "retain");
                    executed.Add("seeds");
                    seedsReady = true;
                    return true;
                },
                () => executed.Add("start"),
                path =>
                {
                    Assert.Equal("fixture.etl", path);
                    Assert.True(seedsReady);
                    executed.Add("replay");
                    replayHistoryReady = true;
                    return true;
                },
                () =>
                {
                    Assert.True(replayHistoryReady);
                    executed.Add("enumerate/delta");
                    return true;
                },
                () => executed.Add("validation"),
                () => reset,
                () => new WindowsProcessQaCounters { SnapshotCount = 5, BootReplayCount = 7, DedupSuppressed = 3 },
                (message, level) => logs.Add((message, level)));
            executed.Add("shared/consumer");

            Assert.Equal(new[] { reset ? "clear" : "retain", "seeds", "start", "replay", "enumerate/delta", "validation", "shared/consumer" }, executed);
            var summary = Assert.Single(logs);
            Assert.Equal(LogLevel.Info, summary.Level);
            Assert.Contains("store=" + (reset ? "reset" : "retained"), summary.Message);
            Assert.Contains("replay=succeeded delta=succeeded", summary.Message);
            Assert.Contains("snapshot_count=5", summary.Message);
            Assert.Contains("boot_replay_count=7", summary.Message);
            Assert.Contains("dedup_suppressed=3", summary.Message);
        }

        [Theory]
        [InlineData(false, true, true, true, "fixture.etl", "skipped-bootstrap-failed", "skipped-bootstrap-failed")]
        [InlineData(true, false, true, true, "fixture.etl", "failed-or-partial", "succeeded")]
        [InlineData(true, true, false, true, "fixture.etl", "succeeded", "failed")]
        [InlineData(true, false, false, true, "fixture.etl", "failed-or-partial", "failed")]
        [InlineData(true, true, true, true, null, "unavailable", "succeeded")]
        [InlineData(true, true, true, false, null, "disabled", "succeeded")]
        [InlineData(true, true, true, false, "fixture.etl", "disabled", "succeeded")]
        [Trait("Category", "wpc-10")]
        public void ExecuteProcessStartup_FailuresAndAbsentReplayPreserveLiveContinuation(
            bool bootstrapResult, bool replayResult, bool deltaResult, bool enabled, string path,
            string replayOutcome, string deltaOutcome)
        {
            var executed = new List<string>();
            var logs = new List<(string Message, LogLevel Level)>();
            WindowsSubscriptionManager.ExecuteProcessStartup(
                enabled, path,
                () => { executed.Add("bootstrap"); return bootstrapResult; },
                () => executed.Add("start"),
                _ => { executed.Add("replay"); return replayResult; },
                () => { executed.Add("delta"); return deltaResult; },
                () => executed.Add("validation"),
                () => true,
                () => new WindowsProcessQaCounters(),
                (message, level) => logs.Add((message, level)));

            var expected = new List<string> { "bootstrap", "start" };
            if (bootstrapResult && enabled && path != null) expected.Add("replay");
            if (bootstrapResult) expected.Add("delta");
            expected.Add("validation");
            Assert.Equal(expected, executed);
            var summary = Assert.Single(logs.FindAll(entry => entry.Message.StartsWith("Windows process startup summary:")));
            Assert.Contains("bootstrap=" + (bootstrapResult ? "succeeded" : "failed"), summary.Message);
            Assert.Contains("replay=" + replayOutcome + " delta=" + deltaOutcome, summary.Message);
            if (!bootstrapResult) Assert.Contains("store=uncertain", summary.Message);
            if (!bootstrapResult || (enabled && path != null && !replayResult) || !deltaResult)
                Assert.Equal(LogLevel.Warn, summary.Level);
            Assert.Equal(enabled && path == null,
                logs.Exists(entry => entry.Level == LogLevel.Warn && entry.Message.Contains("boot process trace was expected but absent")));
        }

        [Theory]
        [InlineData("bootstrap")]
        [InlineData("replay")]
        [InlineData("delta")]
        [Trait("Category", "wpc-10")]
        public void ExecuteProcessStartup_ThrownInitializationPhaseIsDegradedWithoutRetry(string failingPhase)
        {
            var executed = new List<string>();
            var logs = new List<string>();
            bool Run(string phase)
            {
                executed.Add(phase);
                if (phase == failingPhase) throw new InvalidOperationException("fixture failure");
                return true;
            }

            WindowsSubscriptionManager.ExecuteProcessStartup(
                true, "fixture.etl", () => Run("bootstrap"),
                () => executed.Add("start"), _ => Run("replay"), () => Run("delta"),
                () => executed.Add("validation"), () => false,
                () => new WindowsProcessQaCounters(), (message, _) => logs.Add(message));

            Assert.Equal(failingPhase == "bootstrap"
                ? new[] { "bootstrap", "start", "validation" }
                : new[] { "bootstrap", "start", "replay", "delta", "validation" }, executed);
            Assert.Contains(logs, message => message.Contains("threw: fixture failure"));
            Assert.Single(logs.FindAll(message => message.StartsWith("Windows process startup summary:")));
        }

        [Theory]
        [InlineData(true, true, true)]
        [InlineData(true, false, false)]
        [InlineData(false, true, false)]
        [Trait("Category", "wpc-10")]
        public void ExecuteProcessStartup_MissingExpectedWarningKeepsRebuiltGate(bool enabled, bool reset, bool expectedWarning)
        {
            var logs = new List<string>();
            WindowsSubscriptionManager.ExecuteProcessStartup(
                enabled, null, () => true, () => { }, _ => throw new InvalidOperationException("replay must not run"),
                () => true, () => { }, () => reset, () => new WindowsProcessQaCounters(),
                (message, _) => logs.Add(message));

            Assert.Equal(expectedWarning, logs.Exists(message => message.Contains("boot process trace was expected but absent")));
        }

        private static void AssertOrder(CollectorStartupPlan plan, string earlier, string later)
        {
            int earlierIndex = IndexOf(plan.StartupPhases, earlier);
            int laterIndex = IndexOf(plan.StartupPhases, later);
            Assert.True(earlierIndex >= 0, $"Missing startup phase {earlier}");
            Assert.True(laterIndex >= 0, $"Missing startup phase {later}");
            Assert.True(earlierIndex < laterIndex, $"Expected {earlier} before {later}");
        }

        private static int IndexOf(System.Collections.Generic.IReadOnlyList<string> values, string value)
        {
            for (int i = 0; i < values.Count; i++)
            {
                if (values[i] == value)
                {
                    return i;
                }
            }

            return -1;
        }
    }
}
