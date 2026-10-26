using gov.llnl.wintap;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.infrastructure.health;
using gov.llnl.wintap.core.shared;
using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Wintap.Tests
{
    // MemoryMapSensor and WinTapSvc wiring require a live elevated ETW/service run;
    // they are verified manually rather than in this non-admin integration fixture.
    [CollectionDefinition("shc-02-egress", DisableParallelization = true)]
    public sealed class EgressHealthCollection : ICollectionFixture<EgressHealthFixture>
    {
    }

    [Collection("shc-02-egress")]
    public sealed class EventChannelHealthWireInTests
    {
        [Fact, Trait("Category", "shc-02")]
        public void EsperPathInspectsExactlyOnce()
        {
            WithMonitor((monitor, log) =>
            {
                EventChannel.Send(ValidFile());
                monitor.FlushNow();
                Assert.Contains(log, entry => entry.Message.Contains("File=1"));
                Assert.DoesNotContain(log, entry => entry.Message.Contains("FAIL"));
            });
        }

        [Fact, Trait("Category", "shc-02")]
        public void FailureVisibilityFlowsThroughEgress()
        {
            WithMonitor((monitor, log) =>
            {
                WintapMessage message = ValidFile();
                message.PidHash = string.Empty;
                message.ProcessName = "Unknown";
                EventChannel.Send(message);
                monitor.FlushNow();
                Assert.Contains(log, entry => entry.Message.Contains("check=pidhash_missing") && entry.Message.Contains("count=1"));
                Assert.Contains(log, entry => entry.Message.Contains("check=process_unresolved") && entry.Message.Contains("count=1"));
            });
        }

        [Fact, Trait("Category", "shc-02")]
        public void SelfPidFilterPrecedesInspection()
        {
            WithMonitor((monitor, log) =>
            {
                WintapMessage message = ValidFile();
                message.PID = StateManager.WintapPID;
                EventChannel.Send(message);
                monitor.FlushNow();
                Assert.Empty(log);
            });
        }

        [Fact, Trait("Category", "shc-02")]
        public void CollectorProcessRefreshReachesNormalEgressOnLinuxOnly()
        {
            WithMonitor((monitor, log) =>
            {
                var message = new WintapMessage(DateTime.UtcNow, StateManager.WintapPID, WintapMessage.MessageTypeEnum.Process)
                {
                    ActivityType = WintapMessage.ActivityTypeEnum.Refresh,
                    PidHash = "collector-hash",
                    ProcessName = "Lintap",
                    Process = new WintapMessage.ProcessObject { PID = StateManager.WintapPID, Name = "Lintap", Path = "/usr/lib/lintap/Lintap" }
                };
                EventChannel.Send(message);
                monitor.FlushNow();
                if (OperatingSystem.IsLinux())
                {
                    Assert.Contains(log, entry => entry.Message.Contains("Process=1"));
                    Assert.Equal(StateManager.AgentId.ToString(), message.AgentId);
                    Assert.Equal(WintapMessage.ActivityTypeEnum.Refresh, message.ActivityType);
                }
                else
                {
                    Assert.Empty(log);
                }
            });
        }

        [Fact, Trait("Category", "shc-02")]
        public void DirectParquetPathInspectsExactlyOnce()
        {
            string previous = Environment.GetEnvironmentVariable("WINTAP_ENABLE_DIRECT_PARQUET");
            try
            {
                Environment.SetEnvironmentVariable("WINTAP_ENABLE_DIRECT_PARQUET", "1");
                WithMonitor((monitor, log) =>
                {
                    EventChannel.Send(ValidRegistry());
                    monitor.FlushNow();
                    Assert.Contains(log, entry => entry.Message.Contains("Registry=1"));
                    Assert.DoesNotContain(log, entry => entry.Message.Contains("FAIL"));
                });
            }
            finally
            {
                Environment.SetEnvironmentVariable("WINTAP_ENABLE_DIRECT_PARQUET", previous);
            }
        }

        [Fact, Trait("Category", "shc-02")]
        public void HealthFailureNeverBreaksEgress()
        {
            var checks = new List<IWintapHealthCheck> { new ThrowingCheck() };
            checks.AddRange(DefaultHealthChecks.CreateAll(() => "SENTINEL-HASH"));
            WithMonitor((monitor, log) =>
            {
                EventChannel.Send(ValidFile());
                EventChannel.Send(ValidFile());
                Assert.Single(log);
                Assert.Equal(LogLevel.Warn, log[0].Level);
                Assert.Contains("disabled", log[0].Message);
            }, checks);
        }

        private static void WithMonitor(Action<SensorHealthMonitor, List<(string Message, LogLevel Level)>> action, IReadOnlyList<IWintapHealthCheck> checks = null)
        {
            var log = new List<(string Message, LogLevel Level)>();
            var monitor = new SensorHealthMonitor(
                checks ?? DefaultHealthChecks.CreateAll(() => "SENTINEL-HASH"),
                enabled: true,
                sampleCap: 3,
                flushIntervalSeconds: 60,
                logSink: (message, level) => { lock (log) log.Add((message, level)); });
            EventChannel.HealthMonitorOverride = monitor;
            try
            {
                action(monitor, log);
            }
            finally
            {
                EventChannel.HealthMonitorOverride = null;
            }
        }

        private static WintapMessage ValidFile()
        {
            return new WintapMessage(DateTime.UtcNow, TestPid(), WintapMessage.MessageTypeEnum.File)
            {
                PidHash = "hash",
                ProcessName = "process",
                File = new WintapMessage.FileActivityObject { Path = @"c:\windows\system32\notepad.exe" }
            };
        }

        private static WintapMessage ValidRegistry()
        {
            return new WintapMessage(DateTime.UtcNow, TestPid(), WintapMessage.MessageTypeEnum.Registry)
            {
                PidHash = "hash",
                ProcessName = "process",
                Registry = new WintapMessage.RegActivityObject { Path = @"registry\machine\software\x" }
            };
        }

        private static int TestPid() => Environment.ProcessId == 4242 ? 4243 : 4242;

        private sealed class ThrowingCheck : IWintapHealthCheck
        {
            public string Name => "throws";
            public bool Passes(WintapMessage msg) => throw new InvalidOperationException("boom");
            public string Describe(WintapMessage msg) => "never";
        }
    }

    public sealed class EgressHealthFixture : IDisposable
    {
        private static readonly string[] EnvironmentNames =
        {
            "WINTAP_SKIP_ESPER_SEND",
            "WINTAP_SKIP_PROCESS_RESOLVE",
            "WINTAP_SKIP_PARENT_PROCESS_RESOLVE",
            "WINTAP_SKIP_PROCESS_REGISTER"
        };

        private readonly Dictionary<string, string> originalValues = new Dictionary<string, string>();
        private readonly string dataRoot;

        public EgressHealthFixture()
        {
            dataRoot = Path.Combine(Path.GetTempPath(), "wintap-shc-02-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dataRoot);
            // Best-effort hygiene: tests remain valid if another test initialized Env first.
            Env.SetDataRoot(dataRoot);
            foreach (string name in EnvironmentNames)
            {
                originalValues[name] = Environment.GetEnvironmentVariable(name);
                Environment.SetEnvironmentVariable(name, "1");
            }
            // These routing flags are static: set isolation before first channel access.
            WintapLogger.Log.Init();
            _ = EventChannel.TotalEvents;
            _ = DirectParquetSink.IsEnabled;
        }

        public void Dispose()
        {
            foreach (KeyValuePair<string, string> value in originalValues)
            {
                Environment.SetEnvironmentVariable(value.Key, value.Value);
            }
            EventChannel.HealthMonitorOverride = null;
            Env.SetDataRoot(null);
            try { Directory.Delete(dataRoot, recursive: true); } catch { }
        }
    }
}
