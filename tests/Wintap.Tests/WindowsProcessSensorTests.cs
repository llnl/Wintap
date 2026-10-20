using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using gov.llnl.wintap;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.platform.windows.collect.etw;
using gov.llnl.wintap.platform.windows.collect.etw.helpers;
using Xunit;

namespace Wintap.Tests
{
    public class WindowsProcessSensorTests
    {
        [Fact]
        [Trait("Category", "wpc-02")]
        public void CanonicalizeCreateTimeUtc_NormalizesEtwTimestampToUtc()
        {
            var sensor = CreateSensor(out _);
            var localTimestamp = new DateTime(2026, 8, 17, 9, 15, 30, DateTimeKind.Local);

            DateTime canonical = sensor.CanonicalizeCreateTimeUtc(1234, localTimestamp);

            Assert.Equal(DateTimeKind.Utc, canonical.Kind);
            Assert.Equal(localTimestamp.ToUniversalTime(), canonical);
        }

        [Fact]
        [Trait("Category", "wpc-02")]
        public void EmitStart_ComputesPidHashFromCanonicalEtwStartTime()
        {
            var sensor = CreateSensor(out List<WintapMessage> emitted);
            var startTimestamp = new DateTime(2026, 8, 17, 13, 20, 0, DateTimeKind.Utc);

            WintapMessage message = sensor.EmitStart(
                pid: 4321,
                parentPid: 1234,
                etwStartTimestamp: startTimestamp,
                imageFileName: "example.exe",
                commandLine: "example.exe --flag");

            string expectedPidHash = TestPidHash(4321, startTimestamp.ToFileTimeUtc());
            Assert.Single(emitted);
            Assert.Same(message, emitted[0]);
            Assert.Equal(WintapMessage.MessageTypeEnum.Process, message.MessageType);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Start, message.ActivityType);
            Assert.Equal(expectedPidHash, message.PidHash);
            Assert.Equal(startTimestamp.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(4321, message.Process.PID);
            Assert.Equal(1234, message.Process.ParentPID);
            Assert.Equal(string.Empty, message.Process.ParentPidHash);
            Assert.Equal("example.exe --flag", message.Process.CommandLine);
            Assert.Equal("example.exe --flag", message.Process.Arguments);
        }

        [Fact]
        [Trait("Category", "wpc-02")]
        public void EmitStop_UsesResolverReturnedFields_WhenResolverReturnsRecord()
        {
            var stopTimestamp = new DateTime(2026, 8, 17, 13, 25, 0, DateTimeKind.Utc);
            var resolved = new ProcessRecord
            {
                PidHash = "resolved-pid-hash",
                ParentPidHash = "resolved-parent-hash",
                ProcessId = 4321,
                ParentProcessId = 1234,
                ProcessName = "resolved.exe",
                ProcessPath = "C:\\Tools\\resolved.exe"
            };
            var sensor = CreateSensor(out List<WintapMessage> emitted, (pid, time) => resolved);

            WintapMessage message = sensor.EmitStop(4321, stopTimestamp, "payload.exe", 17);

            Assert.Single(emitted);
            Assert.Same(message, emitted[0]);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Stop, message.ActivityType);
            Assert.Equal("resolved-pid-hash", message.PidHash);
            Assert.Equal("resolved-parent-hash", message.Process.ParentPidHash);
            Assert.Equal(1234, message.Process.ParentPID);
            Assert.Equal("resolved.exe", message.ProcessName);
            Assert.Equal("C:\\Tools\\resolved.exe", message.ProcessPath);
            Assert.Equal("resolved.exe", message.Process.Name);
            Assert.Equal("C:\\Tools\\resolved.exe", message.Process.Path);
            Assert.Equal(17, message.Process.ExitCode);
            Assert.Equal(0, sensor.StopWithoutStartCount);
        }

        [Fact]
        [Trait("Category", "wpc-02")]
        public void EmitStop_UsesResolverLookupResult_ForPidReuse()
        {
            var oldInstance = new ProcessRecord
            {
                PidHash = "old-instance-hash",
                ParentPidHash = "old-parent-hash",
                ProcessId = 5000,
                ParentProcessId = 111,
                ProcessName = "old.exe",
                ProcessPath = "C:\\Old\\old.exe"
            };
            var newerInstance = new ProcessRecord
            {
                PidHash = "new-instance-hash",
                ParentPidHash = "new-parent-hash",
                ProcessId = 5000,
                ParentProcessId = 222,
                ProcessName = "new.exe",
                ProcessPath = "C:\\New\\new.exe"
            };
            var stopTimestamp = new DateTime(2026, 8, 17, 14, 0, 0, DateTimeKind.Utc);
            var sensor = CreateSensor(out _, (pid, time) => time == stopTimestamp ? newerInstance : oldInstance);

            WintapMessage message = sensor.EmitStop(5000, stopTimestamp, "payload.exe", 0);

            Assert.Equal("new-instance-hash", message.PidHash);
            Assert.Equal("new-parent-hash", message.Process.ParentPidHash);
            Assert.Equal(222, message.Process.ParentPID);
            Assert.Equal("new.exe", message.Process.Name);
        }

        [Fact]
        [Trait("Category", "wpc-02")]
        public void EmitStop_IncrementsMissCounterAndUsesStopTimeFallback_WhenResolverReturnsNull()
        {
            var sensor = CreateSensor(out List<WintapMessage> emitted, (pid, time) => null);
            var stopTimestamp = new DateTime(2026, 8, 17, 15, 30, 0, DateTimeKind.Utc);

            WintapMessage message = sensor.EmitStop(6789, stopTimestamp, "fallback.exe", 9);

            string expectedPidHash = TestPidHash(6789, stopTimestamp.ToFileTimeUtc());
            Assert.Single(emitted);
            Assert.Equal(1, sensor.StopWithoutStartCount);
            Assert.Equal(expectedPidHash, message.PidHash);
            Assert.Equal("fallback.exe", message.ProcessName);
            Assert.Equal("fallback.exe", message.ProcessPath);
            Assert.Equal(0, message.Process.ParentPID);
            Assert.Equal(string.Empty, message.Process.ParentPidHash);
            Assert.Equal(9, message.Process.ExitCode);
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_ChoosesLatestParentInstanceBeforeChild()
        {
            DateTime bootTime = BootTime();
            DateTime oldParent = bootTime.AddMinutes(1);
            DateTime latestParent = bootTime.AddMinutes(3);
            DateTime futureParent = bootTime.AddMinutes(5);
            DateTime childTime = bootTime.AddMinutes(4);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                enumerateSnapshot: () => new[]
                {
                    Snapshot(100, 4, oldParent, "parent-old.exe"),
                    Snapshot(100, 4, latestParent, "parent-latest.exe"),
                    Snapshot(100, 4, futureParent, "parent-future.exe"),
                    Snapshot(200, 100, childTime, "child.exe")
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            WintapMessage child = emitted.Single(message => message.PID == 200);
            Assert.Equal(TestPidHash(100, latestParent.ToFileTimeUtc()), child.Process.ParentPidHash);
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_DoesNotChooseFutureParentInstance()
        {
            DateTime bootTime = BootTime();
            DateTime childTime = bootTime.AddMinutes(2);
            DateTime futureParent = bootTime.AddMinutes(3);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                enumerateSnapshot: () => new[]
                {
                    Snapshot(300, 100, childTime, "child.exe"),
                    Snapshot(100, 4, futureParent, "future-parent.exe")
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            WintapMessage child = emitted.Single(message => message.PID == 300);
            Assert.Equal(string.Empty, child.Process.ParentPidHash);
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_EmitsOldestFirstWithPidTieBreaker()
        {
            DateTime bootTime = BootTime();
            DateTime first = bootTime.AddMinutes(1);
            DateTime second = bootTime.AddMinutes(2);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                enumerateSnapshot: () => new[]
                {
                    Snapshot(30, 4, second, "thirty.exe"),
                    Snapshot(20, 4, first, "twenty.exe"),
                    Snapshot(10, 4, second, "ten.exe")
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Equal(new[] { -1, 0, 4, 20, 10, 30 }, emitted.Select(message => message.PID).ToArray());
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_ClearsProcessDbBeforeFirstRefreshEmit()
        {
            var operations = new List<string>();
            var sensor = CreateSensor(
                out _,
                enumerateSnapshot: () => new[] { Snapshot(10, 4, BootTime().AddMinutes(1), "ten.exe") },
                clearProcessDb: () => operations.Add("clear"),
                emitOverride: message => operations.Add($"emit:{message.PID}"));

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Equal("clear", operations[0]);
            Assert.Equal(1, operations.Count(operation => operation == "clear"));
            Assert.StartsWith("emit:", operations[1]);
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_IncludesSyntheticSystemProcessSeeds()
        {
            DateTime bootTime = BootTime();
            var sensor = CreateSensor(out List<WintapMessage> emitted, enumerateSnapshot: () => Array.Empty<SnapshotProcessInfo>());

            Assert.True(sensor.InitializeSnapshotRefresh());

            WintapMessage system = emitted.Single(message => message.PID == 4);
            WintapMessage idle = emitted.Single(message => message.PID == 0);
            WintapMessage unknown = emitted.Single(message => message.PID == -1);

            AssertSyntheticSeed(system, 4, "System", Path.Combine(Environment.SystemDirectory, "ntoskrnl.exe"), bootTime);
            AssertSyntheticSeed(idle, 0, "System Idle Process", "idle", bootTime);
            AssertSyntheticSeed(unknown, -1, "Unknown", "unknown-sys", bootTime);
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_SuppressesDuplicateRefreshWithinTolerance()
        {
            DateTime createTime = BootTime().AddMinutes(1);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => new ProcessRecord { ProcessId = pid, CreateTime = createTime.AddSeconds(1) },
                enumerateSnapshot: () => new[] { Snapshot(400, 4, createTime, "duplicate.exe") });

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.DoesNotContain(emitted, message => message.PID == 400);
            Assert.Equal(1, sensor.SnapshotDedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "wpc-03")]
        public void InitializeSnapshotRefresh_DoesNotSuppressWhenResolverMissesOrOutsideTolerance()
        {
            DateTime createTime = BootTime().AddMinutes(1);
            var nullResolverSensor = CreateSensor(
                out List<WintapMessage> nullResolverEmitted,
                resolver: (pid, time) => null,
                enumerateSnapshot: () => new[] { Snapshot(500, 4, createTime, "miss.exe") });
            var outsideToleranceSensor = CreateSensor(
                out List<WintapMessage> outsideToleranceEmitted,
                resolver: (pid, time) => new ProcessRecord { ProcessId = pid, CreateTime = createTime.AddSeconds(3) },
                enumerateSnapshot: () => new[] { Snapshot(600, 4, createTime, "outside.exe") });

            Assert.True(nullResolverSensor.InitializeSnapshotRefresh());
            Assert.True(outsideToleranceSensor.InitializeSnapshotRefresh());

            Assert.Contains(nullResolverEmitted, message => message.PID == 500);
            Assert.Contains(outsideToleranceEmitted, message => message.PID == 600);
            Assert.Equal(0, nullResolverSensor.SnapshotDedupSuppressedCount);
            Assert.Equal(0, outsideToleranceSensor.SnapshotDedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "ptr-04")]
        public void InitializeSnapshotRefresh_SeedsSyntheticProcessesFromRealSystemStart()
        {
            DateTime systemStart = new DateTime(2026, 8, 17, 7, 59, 58, DateTimeKind.Utc);
            long systemStartFileTimeUtc = systemStart.ToFileTimeUtc();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                probeSystemStartFileTimeUtc: () => systemStartFileTimeUtc);

            Assert.True(sensor.InitializeSnapshotRefresh());

            WintapMessage system = emitted.Single(message => message.PID == 4);
            WintapMessage idle = emitted.Single(message => message.PID == 0);
            WintapMessage unknown = emitted.Single(message => message.PID == -1);
            Assert.All(new[] { system, idle, unknown }, message => Assert.Equal(systemStartFileTimeUtc, message.EventTime));
            Assert.Equal(TestPidHash(4, systemStartFileTimeUtc), system.PidHash);
            Assert.Equal(TestPidHash(4, systemStartFileTimeUtc), idle.Process.ParentPidHash);
            Assert.Equal(TestPidHash(4, systemStartFileTimeUtc), unknown.Process.ParentPidHash);
        }

        [Fact]
        [Trait("Category", "ptr-04")]
        public void InitializeSnapshotRefresh_SystemSeedHashMatchesReconcileLiveIdentity()
        {
            long liveSystemStartFileTimeUtc = new DateTime(2026, 8, 17, 7, 59, 57, DateTimeKind.Utc).ToFileTimeUtc();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                probeSystemStartFileTimeUtc: () => liveSystemStartFileTimeUtc);

            Assert.True(sensor.InitializeSnapshotRefresh());

            string reconcileLivePidHash = TestPidHash(4, liveSystemStartFileTimeUtc);
            Assert.Equal(reconcileLivePidHash, emitted.Single(message => message.PID == 4).PidHash);
        }

        [Fact]
        [Trait("Category", "ptr-04")]
        public void InitializeSnapshotRefresh_ProbeMissFallsBackToWmiBootTimeAndWarns()
        {
            DateTime bootTime = BootTime();
            var logEntries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                probeSystemStartFileTimeUtc: () => null,
                logEntries: logEntries);

            Assert.True(sensor.InitializeSnapshotRefresh());

            AssertFallbackSeeds(emitted, bootTime);
            Assert.Contains(logEntries, entry =>
                entry.Message == "SENSOR HEALTH: PID 4 start time unavailable; System seed falling back to WMI boot time (pid_hash stability degraded)" &&
                entry.Level == LogLevel.Warn);
        }

        [Fact]
        [Trait("Category", "ptr-04")]
        public void InitializeSnapshotRefresh_ProbeExceptionFallsBackWithoutEscaping()
        {
            DateTime bootTime = BootTime();
            var logEntries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                probeSystemStartFileTimeUtc: () => throw new InvalidOperationException("probe failed"),
                logEntries: logEntries);

            Assert.True(sensor.InitializeSnapshotRefresh());

            AssertFallbackSeeds(emitted, bootTime);
            Assert.Contains(logEntries, entry =>
                entry.Message == "SENSOR HEALTH: PID 4 start time unavailable; System seed falling back to WMI boot time (pid_hash stability degraded)" &&
                entry.Level == LogLevel.Warn);
        }

        [Fact]
        [Trait("Category", "ptr-04")]
        public void InitializeSnapshotRefresh_RealSystemStartSkipsWmiBootTime()
        {
            int machineBootTimeCalls = 0;
            long systemStartFileTimeUtc = BootTime().AddSeconds(-2).ToFileTimeUtc();
            var sensor = CreateSensor(
                out _,
                machineBootTimeUtc: () =>
                {
                    machineBootTimeCalls++;
                    return BootTime();
                },
                probeSystemStartFileTimeUtc: () => systemStartFileTimeUtc);

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Equal(0, machineBootTimeCalls);
        }

        [Fact]
        [Trait("Category", "ptr-04")]
        public void HandleReplayedStart_SuppressesSyntheticSeedIdentitiesWithoutCounting()
        {
            DateTime replayedStart = BootTime().AddSeconds(5);
            var sensor = CreateSensor(out List<WintapMessage> emitted, resolver: (pid, time) => null);

            Assert.Null(sensor.HandleReplayedStart(4, 0, replayedStart, "System", string.Empty));
            Assert.Null(sensor.HandleReplayedStart(0, 0, replayedStart, "Idle", string.Empty));
            Assert.Null(sensor.HandleReplayedStart(-1, 0, replayedStart, "Unknown", string.Empty));
            Assert.Empty(emitted);
            Assert.Equal(0, sensor.BootReplayCount);

            WintapMessage normal = sensor.HandleReplayedStart(100, 4, replayedStart, "normal.exe", string.Empty);
            Assert.Same(normal, Assert.Single(emitted));
            Assert.Equal(1, sensor.BootReplayCount);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        public void InitializeSnapshotRefresh_OpenSystemRowKeepsTreeAndEmitsRefreshes()
        {
            int clearCalls = 0;
            var logs = new List<string>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                enumerateSnapshot: () => new[] { Snapshot(100, 4, BootTime().AddMinutes(1), "kept.exe") },
                clearProcessDb: () => clearCalls++,
                logs: logs,
                isProcessRowOpen: hash => true);

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Equal(0, clearCalls);
            Assert.Contains(emitted, message => message.PID == 100 && message.ActivityType == WintapMessage.ActivityTypeEnum.Refresh);
            Assert.Contains(logs, message => message.Contains("retained across restart (boot session match)"));
            Assert.False(sensor.LastRefreshRebuiltFromSnapshot);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        public void InitializeSnapshotRefresh_LookupReceivesExactSystemHash()
        {
            long systemStart = BootTime().AddSeconds(-2).ToFileTimeUtc();
            string capturedHash = null;
            var sensor = CreateSensor(
                out _,
                probeSystemStartFileTimeUtc: () => systemStart,
                isProcessRowOpen: hash =>
                {
                    capturedHash = hash;
                    return true;
                });

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Equal(TestPidHash(4, systemStart), capturedHash);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        [Trait("Category", "wpc-12")]
        public void InitializeSnapshotRefresh_AbsentSystemRowLogsNewBootRebuild()
        {
            var operations = new List<string>();
            var logs = new List<string>();
            var sensor = CreateSensor(
                out _,
                clearProcessDb: () => operations.Add("clear"),
                emitOverride: message => operations.Add($"emit:{message.PID}"),
                logs: logs,
                isProcessRowOpen: hash => false);

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Equal("clear", operations[0]);
            Assert.Equal(1, operations.Count(operation => operation == "clear"));
            Assert.StartsWith("emit:", operations[1]);
            Assert.Contains(
                "Windows process snapshot refresh rebuilt from snapshot: new boot session; early-boot lineage restored by boot ETL replay when armed",
                logs);
            Assert.DoesNotContain(logs, message => message.Contains("lineage degraded"));
            Assert.True(sensor.LastRefreshRebuiltFromSnapshot);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        public void InitializeSnapshotRefresh_ProbeUnavailableRebuildsWithoutLookupAndUsesWmiSeeds()
        {
            int lookupCalls = 0;
            int clearCalls = 0;
            var logs = new List<string>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                probeSystemStartFileTimeUtc: () => null,
                clearProcessDb: () => clearCalls++,
                logs: logs,
                isProcessRowOpen: hash =>
                {
                    lookupCalls++;
                    return true;
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Equal(0, lookupCalls);
            Assert.Equal(1, clearCalls);
            AssertFallbackSeeds(emitted, BootTime());
            Assert.Contains(logs, message => message.Contains("rebuilt from snapshot, lineage degraded"));
            Assert.True(sensor.LastRefreshRebuiltFromSnapshot);
        }

        [Theory]
        [Trait("Category", "ptr-02")]
        [InlineData(true)]
        [InlineData(false)]
        public void InitializeSnapshotRefresh_ThrowingBootSessionSeamDegradesSafely(bool probeThrows)
        {
            int clearCalls = 0;
            var sensor = CreateSensor(
                out _,
                probeSystemStartFileTimeUtc: probeThrows
                    ? () => throw new InvalidOperationException("probe failed")
                    : () => BootTime().ToFileTimeUtc(),
                clearProcessDb: () => clearCalls++,
                isProcessRowOpen: hash => probeThrows
                    ? true
                    : throw new InvalidOperationException("lookup failed"));

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Equal(1, clearCalls);
            Assert.True(sensor.LastRefreshRebuiltFromSnapshot);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        public void InitializeSnapshotRefresh_ReadsProbeOnceAndSharesHashWithSystemSeed()
        {
            int probeCalls = 0;
            long systemStart = BootTime().AddSeconds(-3).ToFileTimeUtc();
            string lookupHash = null;
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                probeSystemStartFileTimeUtc: () =>
                {
                    probeCalls++;
                    return systemStart;
                },
                isProcessRowOpen: hash =>
                {
                    lookupHash = hash;
                    return true;
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Equal(1, probeCalls);
            Assert.Equal(lookupHash, emitted.Single(message => message.PID == 4).PidHash);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        public void InitializeSnapshotRefresh_KillSwitchSkipsProbeAndLookupAndClears()
        {
            int probeCalls = 0;
            int lookupCalls = 0;
            int clearCalls = 0;
            var sensor = CreateSensor(
                out _,
                probeSystemStartFileTimeUtc: () =>
                {
                    probeCalls++;
                    return BootTime().ToFileTimeUtc();
                },
                clearProcessDb: () => clearCalls++,
                isProcessRowOpen: hash =>
                {
                    lookupCalls++;
                    return true;
                },
                bootSessionRecoveryEnabled: false);

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Equal(0, probeCalls);
            Assert.Equal(0, lookupCalls);
            Assert.Equal(1, clearCalls);
            Assert.True(sensor.LastRefreshRebuiltFromSnapshot);
        }

        [Fact]
        [Trait("Category", "ptr-02")]
        public void InitializeSnapshotRefresh_OuterFailureMarksRefreshAsRebuilt()
        {
            var sensor = CreateSensor(
                out _,
                enumerateSnapshot: () => throw new InvalidOperationException("snapshot failed"),
                isProcessRowOpen: hash => true);

            Assert.False(sensor.InitializeSnapshotRefresh());
            Assert.True(sensor.LastRefreshRebuiltFromSnapshot);
        }

        [Fact]
        [Trait("Category", "ptr-03")]
        public void InitializeSnapshotRefresh_KeepPathWritesGapThenReconcilesCompleteLiveSet()
        {
            var operations = new List<string>();
            IReadOnlyCollection<string> capturedLiveSet = null;
            DateTime restart = new DateTime(2026, 8, 23, 14, 0, 0, DateTimeKind.Utc);
            DateTime heartbeat = restart.AddMinutes(-3);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                utcNow: () => restart,
                enumerateSnapshot: () => new[] { Snapshot(100, 4, BootTime().AddMinutes(1), "live.exe") },
                isProcessRowOpen: hash => true,
                readHeartbeat: (out DateTime lastWrite, out string session) =>
                {
                    lastWrite = heartbeat;
                    session = "prior-session";
                    return true;
                },
                writeCollectionGap: (start, end, prior, reason) => operations.Add($"gap:{start:O}:{end:O}:{prior}:{reason}"),
                reconcileStartupOpenRows: (liveSet, end) =>
                {
                    operations.Add("reconcile");
                    capturedLiveSet = new HashSet<string>(liveSet);
                    Assert.Equal(restart, end);
                    return 2;
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.StartsWith("gap:", operations[0]);
            Assert.Equal("reconcile", operations[1]);
            Assert.Contains($":{heartbeat:O}:{restart:O}:prior-session:restart_same_boot", operations[0]);
            Assert.Equal(emitted.Select(message => message.PidHash).OrderBy(hash => hash), capturedLiveSet.OrderBy(hash => hash));
        }

        [Fact]
        [Trait("Category", "ptr-03")]
        public void InitializeSnapshotRefresh_SuppressedDuplicateUsesResolverHashInLiveSet()
        {
            DateTime createTime = BootTime().AddMinutes(1);
            string resolverHash = "resolver-registered-hash";
            IReadOnlyCollection<string> capturedLiveSet = null;
            var sensor = CreateSensor(
                out _,
                resolver: (pid, time) => new ProcessRecord
                {
                    ProcessId = pid,
                    CreateTime = createTime.AddSeconds(1),
                    PidHash = resolverHash
                },
                enumerateSnapshot: () => new[] { Snapshot(500, 4, createTime, "duplicate.exe") },
                isProcessRowOpen: hash => true,
                reconcileStartupOpenRows: (liveSet, end) =>
                {
                    capturedLiveSet = new HashSet<string>(liveSet);
                    return 0;
                });

            Assert.True(sensor.InitializeSnapshotRefresh());

            Assert.Contains(resolverHash, capturedLiveSet);
            Assert.DoesNotContain(TestPidHash(500, createTime.ToFileTimeUtc()), capturedLiveSet);
        }

        [Fact]
        [Trait("Category", "ptr-03")]
        public void InitializeSnapshotRefresh_MissingHeartbeatWritesZeroLengthGap()
        {
            DateTime restart = new DateTime(2026, 8, 23, 15, 0, 0, DateTimeKind.Utc);
            DateTime capturedStart = default;
            DateTime capturedEnd = default;
            string capturedPrior = null;
            string capturedReason = null;
            var sensor = CreateSensor(
                out _,
                utcNow: () => restart,
                isProcessRowOpen: hash => true,
                readHeartbeat: (out DateTime lastWrite, out string session) =>
                {
                    lastWrite = default;
                    session = null;
                    return false;
                },
                writeCollectionGap: (start, end, prior, reason) =>
                {
                    capturedStart = start;
                    capturedEnd = end;
                    capturedPrior = prior;
                    capturedReason = reason;
                });

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Equal(restart, capturedStart);
            Assert.Equal(restart, capturedEnd);
            Assert.Equal(string.Empty, capturedPrior);
            Assert.Equal("restart_same_boot_no_heartbeat", capturedReason);
        }

        [Fact]
        [Trait("Category", "ptr-03")]
        public void InitializeSnapshotRefresh_RebuildPathSkipsGapAndReconcile()
        {
            int gapCalls = 0;
            int reconcileCalls = 0;
            var sensor = CreateSensor(
                out _,
                isProcessRowOpen: hash => false,
                writeCollectionGap: (start, end, prior, reason) => gapCalls++,
                reconcileStartupOpenRows: (liveSet, end) => ++reconcileCalls);

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Equal(0, gapCalls);
            Assert.Equal(0, reconcileCalls);
        }

        [Fact]
        [Trait("Category", "ptr-03")]
        [Trait("Category", "pai-07")]
        public void InitializeSnapshotRefresh_ReconcileFailureWarnsAndContinues()
        {
            var logEntries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out _,
                isProcessRowOpen: hash => true,
                reconcileStartupOpenRows: (liveSet, end) => throw new InvalidOperationException("reconcile failed"),
                logEntries: logEntries);

            Assert.True(sensor.InitializeSnapshotRefresh());
            Assert.Contains(logEntries, entry =>
                entry.Level == LogLevel.Warn &&
                entry.Message == "Windows process startup reconcile failed; continuing with unreconciled history: reconcile failed");
        }

        [Fact]
        [Trait("Category", "ptr-03")]
        public void Stop_UpdatesHeartbeatAndContainsFailure()
        {
            int calls = 0;
            var logEntries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out _,
                updateHeartbeat: () =>
                {
                    calls++;
                    throw new InvalidOperationException("heartbeat failed");
                },
                logEntries: logEntries);

            Exception exception = Record.Exception(() => sensor.Stop());

            Assert.Null(exception);
            Assert.Equal(1, calls);
            Assert.Contains(logEntries, entry =>
                entry.Level == LogLevel.Debug && entry.Message.Contains("heartbeat update failed during shutdown"));
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EnrichStartFields_CachesExtractedSidAccountLookup()
        {
            SecurityIdentifier sid = new SecurityIdentifier("S-1-5-18");
            int lookupCount = 0;
            int tokenCount = 0;
            var sensor = CreateSensor(
                out _,
                lookupAccountSid: value =>
                {
                    lookupCount++;
                    return "NT AUTHORITY\\SYSTEM";
                },
                lookupTokenUserByPid: pid =>
                {
                    tokenCount++;
                    return "TOKEN\\user";
                });

            ProcessFieldEnrichment first = sensor.EnrichStartFields(100, "proc.exe", "proc.exe", sid, SidParseStatus.Extracted);
            ProcessFieldEnrichment second = sensor.EnrichStartFields(101, "proc.exe", "proc.exe", sid, SidParseStatus.Extracted);

            Assert.Equal("NT AUTHORITY\\SYSTEM", first.User);
            Assert.Equal("NT AUTHORITY\\SYSTEM", second.User);
            Assert.Equal(1, lookupCount);
            Assert.Equal(0, tokenCount);
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EnrichStartFields_BoundsSidAccountCacheAndEvictsDeterministically()
        {
            int lookupCount = 0;
            var sid18 = new SecurityIdentifier("S-1-5-18");
            var sid19 = new SecurityIdentifier("S-1-5-19");
            var sid20 = new SecurityIdentifier("S-1-5-20");
            var sensor = CreateSensor(
                out _,
                lookupAccountSid: sid =>
                {
                    lookupCount++;
                    return $"ACCOUNT-{sid.Value}";
                },
                sidAccountCacheMaxSize: 2);

            sensor.EnrichStartFields(1, "one.exe", "one.exe", sid18, SidParseStatus.Extracted);
            sensor.EnrichStartFields(2, "two.exe", "two.exe", sid19, SidParseStatus.Extracted);
            sensor.EnrichStartFields(3, "three.exe", "three.exe", sid20, SidParseStatus.Extracted);
            sensor.EnrichStartFields(4, "one.exe", "one.exe", sid18, SidParseStatus.Extracted);

            Assert.Equal(2, sensor.SidAccountCacheCount);
            Assert.Equal(4, lookupCount);
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EnrichStartFields_UsesExpectedUserFallbackMatrix()
        {
            SecurityIdentifier sid = new SecurityIdentifier("S-1-5-18");
            int sidLookupCount = 0;
            int tokenLookupCount = 0;
            var sensor = CreateSensor(
                out _,
                lookupAccountSid: value =>
                {
                    sidLookupCount++;
                    return "DOMAIN\\sid-user";
                },
                lookupTokenUserByPid: pid =>
                {
                    tokenLookupCount++;
                    return pid == 44 ? string.Empty : $"TOKEN\\pid-{pid}";
                });

            ProcessFieldEnrichment extracted = sensor.EnrichStartFields(42, "p.exe", "p.exe", sid, SidParseStatus.Extracted);
            ProcessFieldEnrichment noSid = sensor.EnrichStartFields(43, "p.exe", "p.exe", null, SidParseStatus.NoSid);
            ProcessFieldEnrichment malformed = sensor.EnrichStartFields(44, "p.exe", "p.exe", null, SidParseStatus.Malformed);

            Assert.Equal("DOMAIN\\sid-user", extracted.User);
            Assert.Equal("TOKEN\\pid-43", noSid.User);
            Assert.Equal(string.Empty, malformed.User);
            Assert.Equal(1, sidLookupCount);
            Assert.Equal(2, tokenLookupCount);
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EnrichStartFields_UsesExpectedCommandLineFallbackMatrix()
        {
            int pebLookupCount = 0;
            var sensor = CreateSensor(
                out _,
                lookupPebCommandLineByPid: pid =>
                {
                    pebLookupCount++;
                    if (pid == 52)
                    {
                        throw new InvalidOperationException("PEB unavailable");
                    }

                    return pid == 51 ? "from-peb.exe --fallback" : string.Empty;
                });

            ProcessFieldEnrichment etwWins = sensor.EnrichStartFields(50, "p.exe", "from-etw.exe --flag", null, SidParseStatus.Extracted);
            ProcessFieldEnrichment pebFallback = sensor.EnrichStartFields(51, "p.exe", string.Empty, null, SidParseStatus.Extracted);
            ProcessFieldEnrichment pebFails = sensor.EnrichStartFields(52, "p.exe", string.Empty, null, SidParseStatus.Extracted);

            Assert.Equal("from-etw.exe --flag", etwWins.CommandLine);
            Assert.Equal("from-peb.exe --fallback", pebFallback.CommandLine);
            Assert.Equal(string.Empty, pebFails.CommandLine);
            Assert.Equal(2, pebLookupCount);
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EnrichStartFields_UsesExpectedPathFallbackMatrix()
        {
            var fullPathSensor = CreateSensor(
                out _,
                lookupFullProcessImagePathByPid: pid => "C:\\Live\\live.exe");
            var translatedSensor = CreateSensor(
                out _,
                lookupFullProcessImagePathByPid: pid => string.Empty,
                translateDevicePath: path => "C:\\Translated\\translated.exe");
            var etwFallbackSensor = CreateSensor(
                out _,
                lookupFullProcessImagePathByPid: pid => string.Empty,
                translateDevicePath: path => string.Empty);

            ProcessFieldEnrichment fullPath = fullPathSensor.EnrichStartFields(60, @"\Device\HarddiskVolume1\payload.exe", "", null, SidParseStatus.Extracted);
            ProcessFieldEnrichment translated = translatedSensor.EnrichStartFields(61, @"\Device\HarddiskVolume1\payload.exe", "", null, SidParseStatus.Extracted);
            ProcessFieldEnrichment etw = etwFallbackSensor.EnrichStartFields(62, "payload.exe", "", null, SidParseStatus.Extracted);

            Assert.Equal("C:\\Live\\live.exe", fullPath.Path);
            Assert.Equal("live.exe", fullPath.Name);
            Assert.Equal("C:\\Translated\\translated.exe", translated.Path);
            Assert.Equal("translated.exe", translated.Name);
            Assert.Equal("payload.exe", etw.Path);
            Assert.Equal("payload.exe", etw.Name);
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EmitStart_UsesEnrichedFieldsAndEtwStartTimestampPidHash()
        {
            SecurityIdentifier sid = new SecurityIdentifier("S-1-5-18");
            DateTime startTimestamp = new DateTime(2026, 8, 17, 16, 0, 0, DateTimeKind.Utc);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                lookupAccountSid: value => "DOMAIN\\enriched-user",
                lookupFullProcessImagePathByPid: pid => "C:\\Enriched\\enriched.exe");

            WintapMessage message = sensor.EmitStart(700, 42, startTimestamp, "payload.exe", "enriched.exe --from-etw", sid, SidParseStatus.Extracted);

            Assert.Single(emitted);
            Assert.Same(message, emitted[0]);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Start, message.ActivityType);
            Assert.Equal(TestPidHash(700, startTimestamp.ToFileTimeUtc()), message.PidHash);
            Assert.Equal("enriched.exe", message.ProcessName);
            Assert.Equal("C:\\Enriched\\enriched.exe", message.ProcessPath);
            Assert.Equal("enriched.exe", message.Process.Name);
            Assert.Equal("C:\\Enriched\\enriched.exe", message.Process.Path);
            Assert.Equal("enriched.exe --from-etw", message.Process.CommandLine);
            Assert.Equal("enriched.exe --from-etw", message.Process.Arguments);
            Assert.Equal("DOMAIN\\enriched-user", message.Process.User);
        }

        [Fact]
        [Trait("Category", "wpc-04")]
        public void EmitStart_EnrichmentExceptionsDoNotPreventEmission()
        {
            DateTime startTimestamp = new DateTime(2026, 8, 17, 17, 0, 0, DateTimeKind.Utc);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                lookupFullProcessImagePathByPid: pid => throw new InvalidOperationException("path denied"),
                translateDevicePath: path => throw new InvalidOperationException("translation denied"),
                lookupPebCommandLineByPid: pid => throw new InvalidOperationException("peb denied"),
                lookupTokenUserByPid: pid => throw new InvalidOperationException("token denied"));

            WintapMessage message = sensor.EmitStart(800, 1, startTimestamp, "fallback.exe", string.Empty, null, SidParseStatus.NoSid);

            Assert.Single(emitted);
            Assert.Same(message, emitted[0]);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Start, message.ActivityType);
            Assert.Equal("fallback.exe", message.ProcessName);
            Assert.Equal("fallback.exe", message.ProcessPath);
            Assert.Equal(string.Empty, message.Process.CommandLine);
            Assert.Equal(string.Empty, message.Process.Arguments);
            Assert.Equal(string.Empty, message.Process.User);
        }

        [Fact]
        [Trait("Category", "wpc-05")]
        public void StopMetricCorrelationWindowHit_MergesMetricsForBothOrderingCases()
        {
            DateTime stopTime = new DateTime(2026, 8, 17, 18, 0, 0, DateTimeKind.Utc);
            var resolved = new ProcessRecord
            {
                PidHash = "resolver-pid-hash",
                ParentPidHash = "resolver-parent-hash",
                ProcessId = 900,
                ParentProcessId = 42,
                ProcessName = "resolver.exe",
                ProcessPath = "C:\\Resolver\\resolver.exe"
            };

            var manifestFirstSensor = CreateSensor(out List<WintapMessage> manifestFirstEmitted, resolver: (pid, time) => resolved);
            manifestFirstSensor.EnqueueManifestStopMetrics(Metrics(900, stopTime.AddSeconds(1)));
            manifestFirstSensor.EnqueueKernelStop(900, stopTime, "payload.exe", 23);

            var kernelFirstSensor = CreateSensor(out List<WintapMessage> kernelFirstEmitted, resolver: (pid, time) => resolved);
            kernelFirstSensor.EnqueueKernelStop(900, stopTime, "payload.exe", 23);
            Assert.Empty(kernelFirstEmitted);
            kernelFirstSensor.EnqueueManifestStopMetrics(Metrics(900, stopTime.AddSeconds(-1)));

            WintapMessage manifestFirst = Assert.Single(manifestFirstEmitted);
            WintapMessage kernelFirst = Assert.Single(kernelFirstEmitted);
            AssertMergedStop(manifestFirst, resolved, 23);
            AssertMergedStop(kernelFirst, resolved, 23);
        }

        [Fact]
        [Trait("Category", "wpc-05")]
        public void StopMetricCorrelationMiss_EmitsDefaultsAfterExpiry()
        {
            DateTime now = new DateTime(2026, 8, 17, 18, 30, 0, DateTimeKind.Utc);
            DateTime stopTime = now;
            var resolved = new ProcessRecord
            {
                PidHash = "default-pid-hash",
                ParentPidHash = "default-parent-hash",
                ProcessId = 901,
                ParentProcessId = 43,
                ProcessName = "default.exe",
                ProcessPath = "C:\\Default\\default.exe"
            };
            var sensor = CreateSensor(out List<WintapMessage> emitted, resolver: (pid, time) => resolved, utcNow: () => now);

            sensor.EnqueueKernelStop(901, stopTime, "payload.exe", 99);
            Assert.Empty(emitted);

            now = stopTime + WindowsProcessSensor.StopMetricCorrelationWindow + TimeSpan.FromMilliseconds(1);
            sensor.DrainStopMetricCorrelation();

            WintapMessage message = Assert.Single(emitted);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Stop, message.ActivityType);
            Assert.Equal("default-pid-hash", message.PidHash);
            Assert.Equal("default-parent-hash", message.Process.ParentPidHash);
            Assert.Equal(43, message.Process.ParentPID);
            Assert.Equal(99, message.Process.ExitCode);
            AssertDefaultStopMetrics(message);
        }

        [Fact]
        [Trait("Category", "wpc-05")]
        public void StopMetricExpiry_IncrementsManifestMetricMissesAndDoesNotBlockCallback()
        {
            DateTime now = new DateTime(2026, 8, 17, 19, 0, 0, DateTimeKind.Utc);
            var sensor = CreateSensor(out List<WintapMessage> emitted, utcNow: () => now);

            sensor.EnqueueKernelStop(902, now, "miss.exe", 7);

            Assert.Empty(emitted);
            Assert.Equal(0, sensor.ManifestMetricMissesCount);

            now = now + WindowsProcessSensor.StopMetricCorrelationWindow;
            sensor.DrainStopMetricCorrelation();

            Assert.Single(emitted);
            Assert.Equal(1, sensor.ManifestMetricMissesCount);
            AssertDefaultStopMetrics(emitted[0]);
        }

        [Fact]
        [Trait("Category", "wpc-05")]
        public void StopMetricCorrelation_UsesNearestMetricsAndResolverTimestampForPidReuse()
        {
            DateTime now = new DateTime(2026, 8, 17, 20, 0, 0, DateTimeKind.Utc);
            DateTime firstStop = now;
            DateTime secondStop = now.AddSeconds(20);
            var firstRecord = new ProcessRecord
            {
                PidHash = "first-pid-hash",
                ParentPidHash = "first-parent-hash",
                ProcessId = 903,
                ParentProcessId = 100,
                ProcessName = "first.exe",
                ProcessPath = "C:\\First\\first.exe"
            };
            var secondRecord = new ProcessRecord
            {
                PidHash = "second-pid-hash",
                ParentPidHash = "second-parent-hash",
                ProcessId = 903,
                ParentProcessId = 200,
                ProcessName = "second.exe",
                ProcessPath = "C:\\Second\\second.exe"
            };
            var resolverCalls = new List<DateTime>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) =>
                {
                    resolverCalls.Add(time);
                    return time == secondStop ? secondRecord : firstRecord;
                },
                utcNow: () => now);

            sensor.EnqueueKernelStop(903, firstStop, "first-payload.exe", 1);
            sensor.EnqueueKernelStop(903, secondStop, "second-payload.exe", 2);
            sensor.EnqueueManifestStopMetrics(Metrics(903, secondStop.AddMilliseconds(100)));

            WintapMessage second = Assert.Single(emitted);
            Assert.Equal("second-pid-hash", second.PidHash);
            Assert.Equal("second-parent-hash", second.Process.ParentPidHash);
            Assert.Equal(200, second.Process.ParentPID);
            Assert.Equal(123456789, second.Process.CPUCycleCount);

            now = firstStop + WindowsProcessSensor.StopMetricCorrelationWindow;
            sensor.DrainStopMetricCorrelation();

            Assert.Equal(2, emitted.Count);
            WintapMessage first = emitted.Single(message => message.PidHash == "first-pid-hash");
            Assert.Equal("first-parent-hash", first.Process.ParentPidHash);
            Assert.Equal(100, first.Process.ParentPID);
            AssertDefaultStopMetrics(first);
            Assert.Contains(firstStop, resolverCalls);
            Assert.Contains(secondStop, resolverCalls);
        }

        [Fact]
        [Trait("Category", "wpc-06")]
        public void QaCounterSnapshot_UsesExpectedNamesAndFormatExactlyOnce()
        {
            var counters = new WindowsProcessQaCounters
            {
                SidExtracted = 1,
                SidNull = 2,
                SidMalformed = 3,
                SidFallback = 4,
                CmdlineEmpty = 5,
                CmdlinePebRecovered = 6,
                StopWithoutStart = 7,
                ManifestMetricMisses = 8,
                SnapshotCount = 9,
                BootReplayCount = 10,
                DedupSuppressed = 11
            };

            string formatted = WindowsProcessSensor.FormatQaCounterSnapshot(counters);

            Assert.StartsWith("Windows process QA counters:", formatted);
            AssertQaCounterName(formatted, "sid_extracted", "1");
            AssertQaCounterName(formatted, "sid_null", "2");
            AssertQaCounterName(formatted, "sid_malformed", "3");
            AssertQaCounterName(formatted, "sid_fallback", "4");
            AssertQaCounterName(formatted, "cmdline_empty", "5");
            AssertQaCounterName(formatted, "cmdline_peb_recovered", "6");
            AssertQaCounterName(formatted, "stop_without_start", "7");
            AssertQaCounterName(formatted, "manifest_metric_misses", "8");
            AssertQaCounterName(formatted, "snapshot_count", "9");
            AssertQaCounterName(formatted, "boot_replay_count", "10");
            AssertQaCounterName(formatted, "dedup_suppressed", "11");
        }

        [Fact]
        [Trait("Category", "wpc-06")]
        public void QaCounterSnapshot_ReportsExpectedValuesAfterSimulatedActivity()
        {
            DateTime now = BootTime().AddHours(10);
            DateTime duplicateCreateTime = BootTime().AddMinutes(1);
            var sensor = CreateSensor(
                out _,
                resolver: (pid, time) => pid == 400
                    ? new ProcessRecord { ProcessId = pid, CreateTime = duplicateCreateTime.AddSeconds(1) }
                    : null,
                utcNow: () => now,
                enumerateSnapshot: () => new[]
                {
                    Snapshot(400, 4, duplicateCreateTime, "duplicate.exe"),
                    Snapshot(401, 4, duplicateCreateTime.AddMinutes(1), "refresh.exe")
                },
                lookupAccountSid: sid => "NT AUTHORITY\\SYSTEM",
                lookupTokenUserByPid: pid => string.Empty,
                lookupPebCommandLineByPid: pid => pid == 101 ? "from-peb.exe --recovered" : string.Empty);

            sensor.EnrichStartFields(100, "extracted.exe", "from-etw.exe", new SecurityIdentifier("S-1-5-18"), SidParseStatus.Extracted);
            sensor.EnrichStartFields(101, "nosid.exe", string.Empty, null, SidParseStatus.NoSid);
            sensor.EnrichStartFields(102, "malformed.exe", string.Empty, null, SidParseStatus.Malformed);
            Assert.True(sensor.InitializeSnapshotRefresh());
            sensor.EmitStop(500, now, "miss.exe", 1);
            sensor.EnqueueKernelStop(600, now, "metric-miss.exe", 2);
            now = now + WindowsProcessSensor.StopMetricCorrelationWindow;
            sensor.DrainStopMetricCorrelation();

            WindowsProcessQaCounters snapshot = sensor.GetQaCounterSnapshot();
            Assert.Equal(1, snapshot.SidExtracted);
            Assert.Equal(1, snapshot.SidNull);
            Assert.Equal(1, snapshot.SidMalformed);
            Assert.Equal(2, snapshot.SidFallback);
            Assert.Equal(2, snapshot.CmdlineEmpty);
            Assert.Equal(1, snapshot.CmdlinePebRecovered);
            Assert.Equal(2, snapshot.StopWithoutStart);
            Assert.Equal(1, snapshot.ManifestMetricMisses);
            Assert.Equal(4, snapshot.SnapshotCount);
            Assert.Equal(0, snapshot.BootReplayCount);
            Assert.Equal(1, snapshot.DedupSuppressed);
        }

        [Fact]
        [Trait("Category", "wpc-06")]
        public void Stop_LogsFinalQaCountersWithSameSnapshotFormat()
        {
            var logs = new List<string>();
            var sensor = CreateSensor(out _, logs: logs);
            sensor.EnrichStartFields(101, "nosid.exe", string.Empty, null, SidParseStatus.NoSid);

            sensor.Stop();

            string qaLine = Assert.Single(logs, line => line.StartsWith("Windows process QA counters:"));
            AssertQaCounterName(qaLine, "sid_null", "1");
            AssertQaCounterName(qaLine, "sid_fallback", "1");
            AssertQaCounterName(qaLine, "cmdline_empty", "1");
        }

        [Theory]
        [Trait("Category", "wpc-07")]
        [InlineData(@"c:/programdata/wintap/./boot-process-trace.etl", @"C:\ProgramData\Wintap\boot-process-trace.etl", true)]
        [InlineData(@"C:\ProgramData\Other\boot-process-trace.etl", @"C:\ProgramData\Wintap\boot-process-trace.etl", false)]
        [InlineData(null, @"C:\ProgramData\Wintap\boot-process-trace.etl", false)]
        [InlineData("", @"C:\ProgramData\Wintap\boot-process-trace.etl", false)]
        [InlineData("   ", @"C:\ProgramData\Wintap\boot-process-trace.etl", false)]
        [InlineData("\0", @"C:\ProgramData\Wintap\boot-process-trace.etl", false)]
        public void BootTraceOwnershipPredicate_MatchesOnlyConfiguredNormalizedPath(string sessionPath, string configuredPath, bool expected)
        {
            Assert.Equal(expected, BootProcessTraceHelper.IsOwnedBootSession(sessionPath, configuredPath));
        }

        [Fact]
        [Trait("Category", "wpc-07")]
        public void HandleReplayedStart_SuppressesDuplicateWithinToleranceWithoutIncrementingBootReplayCount()
        {
            DateTime replayedStart = BootTime().AddMinutes(10);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => new ProcessRecord { ProcessId = pid, CreateTime = replayedStart.AddSeconds(1) });

            WintapMessage message = sensor.HandleReplayedStart(1000, 4, replayedStart, "duplicate.exe", "duplicate.exe", null, SidParseStatus.Extracted);

            Assert.Null(message);
            Assert.Empty(emitted);
            Assert.Equal(0, sensor.BootReplayCount);
        }

        [Fact]
        [Trait("Category", "wpc-07")]
        public void HandleReplayedStart_EmitsPidReuseOutsideToleranceWithReplayedTimestamp()
        {
            DateTime replayedStart = BootTime().AddMinutes(11);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => new ProcessRecord { ProcessId = pid, CreateTime = replayedStart.AddSeconds(3) });

            WintapMessage message = sensor.HandleReplayedStart(1001, 4, replayedStart, "outside.exe", "outside.exe --boot", null, SidParseStatus.Extracted);

            Assert.Single(emitted);
            Assert.Same(message, emitted[0]);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Start, message.ActivityType);
            Assert.Equal(replayedStart.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(TestPidHash(1001, replayedStart.ToFileTimeUtc()), message.PidHash);
            Assert.Equal("outside.exe --boot", message.Process.CommandLine);
            Assert.Equal(1, sensor.BootReplayCount);
        }

        [Fact]
        [Trait("Category", "wpc-07")]
        public void HandleReplayedStart_EmitsResolverMissAndIncrementsBootReplayCount()
        {
            DateTime replayedStart = BootTime().AddMinutes(12);
            var sensor = CreateSensor(out List<WintapMessage> emitted, resolver: (pid, time) => null);

            WintapMessage message = sensor.HandleReplayedStart(1002, 1001, replayedStart, "miss.exe", string.Empty, null, SidParseStatus.Extracted);

            Assert.Single(emitted);
            Assert.Same(message, emitted[0]);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Start, message.ActivityType);
            Assert.Equal(1002, message.Process.PID);
            Assert.Equal(1001, message.Process.ParentPID);
            Assert.Equal(replayedStart.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(1, sensor.BootReplayCount);
        }

        [Fact]
        [Trait("Category", "wpc-12")]
        public void LogBootReplayComplete_ReportsReplayPassOutcomes()
        {
            var entries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(out _, logEntries: entries);

            sensor.LogBootReplayComplete(@"C:\ProgramData\Wintap\boot.etl", 7, 11, 3);

            (string message, LogLevel level) = Assert.Single(entries);
            Assert.Equal(
                @"Windows process boot ETL replay complete from 'C:\ProgramData\Wintap\boot.etl': starts_emitted=7 duplicates_suppressed=11 parent_links_repaired=3",
                message);
            Assert.Equal(LogLevel.Info, level);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(true)]
        [InlineData(false)]
        public void HandleReplayedStart_DuplicateRepairsOnlyUnknownParent(bool unknownParent)
        {
            DateTime replayedStart = BootTime().AddMinutes(13);
            string storedParentHash = unknownParent ? TestPidHash(-1, 0) : "healthy-parent";
            var repairs = new List<(string PidHash, int ParentPid, string ParentPidHash)>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => pid == 1100
                    ? new ProcessRecord
                    {
                        PidHash = "child-hash",
                        ParentPidHash = storedParentHash,
                        ProcessId = pid,
                        CreateTime = replayedStart
                    }
                    : new ProcessRecord { PidHash = "resolved-parent", ProcessId = pid },
                repairParentLinkage: (pidHash, parentPid, parentPidHash) =>
                {
                    repairs.Add((pidHash, parentPid, parentPidHash));
                    return true;
                });

            WintapMessage message = sensor.HandleReplayedStart(
                1100, 1099, replayedStart, "child.exe", string.Empty);

            Assert.Null(message);
            Assert.Empty(emitted);
            Assert.Equal(1, sensor.DedupSuppressedCount);
            Assert.Equal(0, sensor.BootReplayCount);
            if (unknownParent)
            {
                Assert.Equal(("child-hash", 1099, "resolved-parent"), Assert.Single(repairs));
            }
            else
            {
                Assert.Empty(repairs);
            }
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void HandleLiveStart_DuplicateRepairsUnknownParentAtChildCreateTime()
        {
            DateTime liveStart = BootTime().AddMinutes(14);
            DateTime parentLookupTime = default;
            var repairs = new List<(string PidHash, int ParentPid, string ParentPidHash)>();
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) =>
                {
                    if (pid == 1200)
                    {
                        return new ProcessRecord
                        {
                            PidHash = "live-child",
                            ParentPidHash = string.Empty,
                            ProcessId = pid,
                            CreateTime = liveStart
                        };
                    }

                    parentLookupTime = time;
                    return new ProcessRecord { PidHash = "live-parent", ProcessId = pid };
                },
                repairParentLinkage: (pidHash, parentPid, parentPidHash) =>
                {
                    repairs.Add((pidHash, parentPid, parentPidHash));
                    return true;
                });

            WintapMessage message = sensor.HandleLiveStart(
                1200, 1199, liveStart, "live-child.exe", string.Empty);

            Assert.Null(message);
            Assert.Empty(emitted);
            Assert.Equal(liveStart, parentLookupTime);
            Assert.Equal(("live-child", 1199, "live-parent"), Assert.Single(repairs));
            Assert.Equal(1, sensor.DedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "wpc-12")]
        public void HandleReplayedStart_UnspecifiedUtcDuplicateIsSuppressedAndRepairsParentOnce()
        {
            DateTime replayedStartUtc = BootTime().AddMinutes(15);
            DateTime storedCreateTime = DateTime.SpecifyKind(replayedStartUtc, DateTimeKind.Unspecified);
            int repairCalls = 0;
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => pid == 1300
                    ? new ProcessRecord
                    {
                        PidHash = "replay-child",
                        ParentPidHash = TestPidHash(-1, 0),
                        ProcessId = pid,
                        CreateTime = storedCreateTime
                    }
                    : new ProcessRecord { PidHash = "replay-parent", ProcessId = pid },
                repairParentLinkage: (pidHash, parentPid, parentPidHash) =>
                {
                    repairCalls++;
                    Assert.Equal("replay-child", pidHash);
                    Assert.Equal(1299, parentPid);
                    Assert.Equal("replay-parent", parentPidHash);
                    return true;
                });

            WintapMessage message = sensor.HandleReplayedStart(
                1300, 1299, replayedStartUtc, "replay-child.exe", string.Empty);

            Assert.Null(message);
            Assert.Empty(emitted);
            Assert.Equal(1, sensor.DedupSuppressedCount);
            Assert.Equal(0, sensor.BootReplayCount);
            Assert.Equal(1, repairCalls);
        }

        [Fact]
        [Trait("Category", "wpc-12")]
        public void HandleLiveStart_UnspecifiedUtcDuplicateIsSuppressedAndRepairsParentOnce()
        {
            DateTime liveStartUtc = BootTime().AddMinutes(16);
            DateTime storedCreateTime = DateTime.SpecifyKind(liveStartUtc, DateTimeKind.Unspecified);
            int repairCalls = 0;
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => pid == 1400
                    ? new ProcessRecord
                    {
                        PidHash = "live-child",
                        ParentPidHash = string.Empty,
                        ProcessId = pid,
                        CreateTime = storedCreateTime
                    }
                    : new ProcessRecord { PidHash = "live-parent", ProcessId = pid },
                repairParentLinkage: (pidHash, parentPid, parentPidHash) =>
                {
                    repairCalls++;
                    Assert.Equal("live-child", pidHash);
                    Assert.Equal(1399, parentPid);
                    Assert.Equal("live-parent", parentPidHash);
                    return true;
                });

            WintapMessage message = sensor.HandleLiveStart(
                1400, 1399, liveStartUtc, "live-child.exe", string.Empty);

            Assert.Null(message);
            Assert.Empty(emitted);
            Assert.Equal(1, sensor.DedupSuppressedCount);
            Assert.Equal(1, repairCalls);
        }

        [Fact]
        [Trait("Category", "wpc-07")]
        public void QaCounterLineIncludesBootReplayCount()
        {
            var counters = new WindowsProcessQaCounters { BootReplayCount = 42 };

            string formatted = WindowsProcessSensor.FormatQaCounterSnapshot(counters);

            AssertQaCounterName(formatted, "boot_replay_count", "42");
        }

        [Fact]
        [Trait("Category", "wpc-10")]
        public void HandleLiveStart_SuppressesSnapshotOverlapAndOnlyIncrementsDedupCounter()
        {
            DateTime liveStart = BootTime().AddMinutes(20);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => new ProcessRecord
                {
                    ProcessId = pid,
                    CreateTime = liveStart.AddSeconds(1)
                });

            WintapMessage message = sensor.HandleLiveStart(
                2000, 4, liveStart, "overlap.exe", "overlap.exe", null, SidParseStatus.Extracted);

            Assert.Null(message);
            Assert.Empty(emitted);
            Assert.Equal(1, sensor.DedupSuppressedCount);
            Assert.Equal(0, sensor.BootReplayCount);
            Assert.Equal(0, sensor.StopWithoutStartCount);
        }

        [Fact]
        [Trait("Category", "wpc-10")]
        public void HandleLiveStart_ResolverMissEmitsStart()
        {
            DateTime liveStart = BootTime().AddMinutes(21);
            var sensor = CreateSensor(out List<WintapMessage> emitted, resolver: (pid, time) => null);

            WintapMessage message = sensor.HandleLiveStart(
                2001, 2000, liveStart, "miss.exe", "miss.exe --live", null, SidParseStatus.Extracted);

            Assert.Same(message, Assert.Single(emitted));
            Assert.Equal(WintapMessage.ActivityTypeEnum.Start, message.ActivityType);
            Assert.Equal(liveStart.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(TestPidHash(2001, liveStart.ToFileTimeUtc()), message.PidHash);
            Assert.Equal(0, sensor.DedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "wpc-10")]
        public void HandleLiveStart_SamePidOutsideToleranceEmitsAsPidReuse()
        {
            DateTime liveStart = BootTime().AddMinutes(22);
            var sensor = CreateSensor(
                out List<WintapMessage> emitted,
                resolver: (pid, time) => new ProcessRecord
                {
                    ProcessId = pid,
                    CreateTime = liveStart.AddSeconds(3)
                });

            WintapMessage message = sensor.HandleLiveStart(
                2002, 4, liveStart, "reused.exe", "reused.exe", null, SidParseStatus.Extracted);

            Assert.Same(message, Assert.Single(emitted));
            Assert.Equal(TestPidHash(2002, liveStart.ToFileTimeUtc()), message.PidHash);
            Assert.Equal(0, sensor.DedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "wpc-10")]
        public void QaCounterNames_RemainExactAfterLiveOverlapDedup()
        {
            string formatted = WindowsProcessSensor.FormatQaCounterSnapshot(new WindowsProcessQaCounters());
            string[] names = formatted
                .Substring("Windows process QA counters: ".Length)
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(pair => pair.Split('=')[0])
                .ToArray();

            Assert.Equal(new[]
            {
                "sid_extracted",
                "sid_null",
                "sid_malformed",
                "sid_fallback",
                "cmdline_empty",
                "cmdline_peb_recovered",
                "stop_without_start",
                "manifest_metric_misses",
                "snapshot_count",
                "boot_replay_count",
                "dedup_suppressed"
            }, names);
        }

        [Fact]
        [Trait("Category", "wpc-10a")]
        public void ValidateProcessLineage_MultiHopChainReachesSystemKernelSeed()
        {
            var records = new[]
            {
                new ProcessRecord { PidHash = "wintap", ParentPidHash = "service", ProcessId = 300 },
                new ProcessRecord { PidHash = "service", ParentPidHash = "system", ProcessId = 200 },
                new ProcessRecord { PidHash = "system", ParentPidHash = "system", ProcessId = 4, ProcessPath = @"C:\Windows\System32\NTOSKRNL.EXE" }
            };

            bool valid = WindowsProcessSensor.ValidateProcessLineage(records, "wintap", TestPidHash, out int hops, out string reason);

            Assert.True(valid, reason);
            Assert.Equal(2, hops);
            Assert.Null(reason);
        }

        [Theory]
        [Trait("Category", "wpc-10a")]
        [InlineData("missing")]
        [InlineData("empty")]
        [InlineData("cycle")]
        [InlineData("unknown")]
        [InlineData("bounded")]
        public void ValidateProcessLineage_MalformedChainsTerminate(string scenario)
        {
            IReadOnlyList<ProcessRecord> records;
            if (scenario == "missing")
            {
                records = new[] { new ProcessRecord { PidHash = "start", ParentPidHash = "absent", ProcessId = 10 } };
            }
            else if (scenario == "empty")
            {
                records = new[] { new ProcessRecord { PidHash = "start", ParentPidHash = string.Empty, ProcessId = 10 } };
            }
            else if (scenario == "cycle")
            {
                records = new[]
                {
                    new ProcessRecord { PidHash = "start", ParentPidHash = "parent", ProcessId = 10 },
                    new ProcessRecord { PidHash = "parent", ParentPidHash = "start", ProcessId = 11 }
                };
            }
            else if (scenario == "unknown")
            {
                records = new[]
                {
                    new ProcessRecord { PidHash = "start", ParentPidHash = "unknown", ProcessId = 10 },
                    new ProcessRecord { PidHash = "unknown", ParentPidHash = "unknown", ProcessId = -1 }
                };
            }
            else
            {
                records = Enumerable.Range(0, 34)
                    .Select(index => new ProcessRecord
                    {
                        PidHash = "hash-" + index,
                        ParentPidHash = "hash-" + (index + 1),
                        ProcessId = 100 + index
                    })
                    .ToArray();
            }

            bool valid = WindowsProcessSensor.ValidateProcessLineage(
                records,
                scenario == "bounded" ? "hash-0" : "start",
                TestPidHash,
                out _,
                out string reason);

            Assert.False(valid);
            Assert.False(string.IsNullOrWhiteSpace(reason));
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void ValidateProcessLineage_SentinelDeadEndReportsUnknownParentHash()
        {
            var records = new[]
            {
                new ProcessRecord
                {
                    PidHash = "explorer",
                    ParentPidHash = TestPidHash(-1, 0),
                    ProcessId = 1300
                }
            };

            bool valid = WindowsProcessSensor.ValidateProcessLineage(
                records,
                "explorer",
                TestPidHash,
                out int hops,
                out string reason);

            Assert.False(valid);
            Assert.Equal(0, hops);
            Assert.Equal("unknown parent hash", reason);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void ValidateProcessLineage_RepairedBootChainReachesSystemKernelSeed()
        {
            var records = new[]
            {
                new ProcessRecord { PidHash = "explorer", ParentPidHash = "userinit", ProcessId = 1400, ProcessName = "explorer.exe" },
                new ProcessRecord { PidHash = "userinit", ParentPidHash = "winlogon", ProcessId = 1300, ProcessName = "userinit.exe" },
                new ProcessRecord { PidHash = "winlogon", ParentPidHash = "smss", ProcessId = 1200, ProcessName = "winlogon.exe" },
                new ProcessRecord { PidHash = "smss", ParentPidHash = "system", ProcessId = 1100, ProcessName = "smss.exe" },
                new ProcessRecord { PidHash = "system", ParentPidHash = "system", ProcessId = 4, ProcessPath = @"C:\Windows\System32\ntoskrnl.exe" }
            };

            bool valid = WindowsProcessSensor.ValidateProcessLineage(
                records,
                "explorer",
                TestPidHash,
                out int hops,
                out string reason);

            Assert.True(valid, reason);
            Assert.Equal(4, hops);
            Assert.Null(reason);
        }

        [Fact]
        [Trait("Category", "wpc-10a")]
        public void LogExplorerProcessLineageValidation_UsesActiveExplorerAndEmitsOnePassLine()
        {
            var records = new[]
            {
                new ProcessRecord
                {
                    PidHash = "old-explorer",
                    ParentPidHash = "missing",
                    ProcessId = 299,
                    ProcessName = "explorer.exe",
                    CreateTime = BootTime().AddHours(2),
                    ExitTime = BootTime().AddHours(3)
                },
                new ProcessRecord
                {
                    PidHash = "explorer",
                    ParentPidHash = "userinit",
                    ProcessId = 300,
                    ProcessPath = @"C:\Windows\explorer.exe",
                    CreateTime = BootTime().AddHours(1)
                },
                new ProcessRecord { PidHash = "userinit", ParentPidHash = "system", ProcessId = 200, ProcessName = "userinit.exe" },
                new ProcessRecord { PidHash = "system", ParentPidHash = "system", ProcessId = 4, ProcessPath = "ntoskrnl.exe" }
            };
            var entries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out _,
                logEntries: entries,
                getProcessHistory: () => records);

            bool logged = sensor.TryLogExplorerProcessLineageValidation();

            (string message, LogLevel level) = Assert.Single(entries);
            Assert.True(logged);
            Assert.Equal("Process lineage validation PASS: pid=300 root=ntoskrnl.exe hops=2", message);
            Assert.Equal(LogLevel.Info, level);
        }

        [Fact]
        [Trait("Category", "wpc-10a")]
        [Trait("Category", "wpc-12")]
        public void LogExplorerProcessLineageValidation_MalformedExplorerEmitsOneWarningAndDoesNotThrow()
        {
            var entries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out _,
                logEntries: entries,
                getProcessHistory: () => new[]
                {
                    new ProcessRecord { PidHash = "explorer", ParentPidHash = "missing", ProcessId = 301, ProcessName = "explorer.exe" }
                });

            bool logged = sensor.TryLogExplorerProcessLineageValidation();

            (string message, LogLevel level) = Assert.Single(entries);
            Assert.True(logged);
            Assert.Equal("Process lineage validation FAIL: pid=301 reason=parent record missing hops=1 stopped_at=explorer.exe pid=301", message);
            Assert.Equal(LogLevel.Warn, level);
        }

        [Fact]
        [Trait("Category", "wpc-12")]
        public void LogExplorerProcessLineageValidation_WhenExplorerMissingLogsDeferredOnce()
        {
            var entries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out _,
                logEntries: entries,
                getProcessHistory: () => Array.Empty<ProcessRecord>());

            Assert.False(sensor.TryLogExplorerProcessLineageValidation());
            Assert.False(sensor.TryLogExplorerProcessLineageValidation());

            (string message, LogLevel level) = Assert.Single(entries);
            Assert.Equal(
                "Process lineage validation deferred: no explorer record found; will retry on first live explorer Start",
                message);
            Assert.Equal(LogLevel.Info, level);
        }

        [Fact]
        [Trait("Category", "wpc-10a")]
        public void HandleLiveStart_WhenExplorerAppearsLogsLineageOnce()
        {
            DateTime startTime = BootTime().AddHours(1);
            var history = new List<ProcessRecord>
            {
                new ProcessRecord { PidHash = "userinit", ParentPidHash = "system", ProcessId = 200, ProcessName = "userinit.exe" },
                new ProcessRecord { PidHash = "system", ParentPidHash = "system", ProcessId = 4, ProcessPath = "ntoskrnl.exe" }
            };
            var entries = new List<(string Message, LogLevel Level)>();
            var sensor = CreateSensor(
                out _,
                resolver: (pid, time) => null,
                emitOverride: message => history.Add(new ProcessRecord
                {
                    PidHash = message.PidHash,
                    ParentPidHash = "userinit",
                    ProcessId = message.PID,
                    ProcessName = message.ProcessName,
                    ProcessPath = message.ProcessPath,
                    CreateTime = DateTime.FromFileTimeUtc(message.EventTime)
                }),
                logEntries: entries,
                getProcessHistory: () => history);

            sensor.HandleLiveStart(302, 200, startTime, "explorer.exe", string.Empty);
            sensor.TryLogExplorerProcessLineageValidation();

            (string message, LogLevel level) = Assert.Single(entries);
            Assert.Equal("Process lineage validation PASS: pid=302 root=ntoskrnl.exe hops=2", message);
            Assert.Equal(LogLevel.Info, level);
        }

        [Theory]
        [Trait("Category", "wpc-09")]
        [InlineData(true, false, false, false, false, false, false, true, false)]
        [InlineData(true, true, true, true, true, true, true, true, true)]
        [InlineData(false, true, true, true, true, true, true, false, false)]
        [InlineData(true, true, false, true, true, false, false, true, false)]
        [InlineData(false, false, false, true, true, false, true, false, false)]
        public void BootTraceLifecycleDecision_CoversEnableDisableAndForeignSessionSafety(
            bool settingEnabled,
            bool activeSessionPresent,
            bool ownedActiveSession,
            bool bootEtlExists,
            bool registryOwned,
            bool expectedStop,
            bool expectedDisarm,
            bool expectedArm,
            bool expectedReplay)
        {
            BootTraceLifecycleDecision decision = BootProcessTraceHelper.DecideLifecycle(
                settingEnabled,
                activeSessionPresent,
                ownedActiveSession,
                bootEtlExists,
                registryOwned);

            Assert.Equal(expectedStop, decision.StopOwnedSession);
            Assert.Equal(expectedDisarm, decision.DisarmOwnedRegistry);
            Assert.Equal(expectedArm, decision.ArmForNextBoot);
            Assert.Equal(expectedReplay, decision.ReplayBootEtl);
        }

        private static WindowsProcessSensor CreateSensor(
            out List<WintapMessage> emitted,
            Func<int, DateTime, ProcessRecord> resolver = null,
            Func<DateTime> utcNow = null,
            Func<IReadOnlyList<SnapshotProcessInfo>> enumerateSnapshot = null,
            Action clearProcessDb = null,
            Action<WintapMessage> emitOverride = null,
            Func<SecurityIdentifier, string> lookupAccountSid = null,
            Func<int, string> lookupTokenUserByPid = null,
            Func<int, string> lookupPebCommandLineByPid = null,
            Func<int, string> lookupFullProcessImagePathByPid = null,
            Func<string, string> translateDevicePath = null,
            int sidAccountCacheMaxSize = 1024,
            List<string> logs = null,
            Func<DateTime> machineBootTimeUtc = null,
            Func<long?> probeSystemStartFileTimeUtc = null,
            List<(string Message, LogLevel Level)> logEntries = null,
            Func<string, bool> isProcessRowOpen = null,
            bool? bootSessionRecoveryEnabled = true,
            WindowsProcessSensor.TryReadHeartbeatDelegate readHeartbeat = null,
            Func<IReadOnlyCollection<string>, DateTime, int> reconcileStartupOpenRows = null,
            Action<DateTime, DateTime, string, string> writeCollectionGap = null,
            Action updateHeartbeat = null,
            Func<IReadOnlyList<ProcessRecord>> getProcessHistory = null,
            Func<string, int, string, bool> repairParentLinkage = null)
        {
            emitted = new List<WintapMessage>();
            List<WintapMessage> captured = emitted;
            return new WindowsProcessSensor(
                resolveProcessAtTime: resolver ?? ((pid, eventTimeUtc) => null),
                emit: emitOverride ?? captured.Add,
                utcNow: utcNow ?? (() => new DateTime(2026, 8, 17, 0, 0, 0, DateTimeKind.Utc)),
                genPidHash: TestPidHash,
                enumerateSnapshot: enumerateSnapshot ?? (() => Array.Empty<SnapshotProcessInfo>()),
                clearProcessDb: clearProcessDb ?? (() => { }),
                machineBootTimeUtc: machineBootTimeUtc ?? BootTime,
                probeSystemStartFileTimeUtc: probeSystemStartFileTimeUtc ?? (() => BootTime().ToFileTimeUtc()),
                isProcessRowOpen: isProcessRowOpen ?? (hash => false),
                bootSessionRecoveryEnabled: bootSessionRecoveryEnabled,
                readHeartbeat: readHeartbeat ?? ((out DateTime lastWrite, out string session) =>
                {
                    lastWrite = default;
                    session = string.Empty;
                    return false;
                }),
                reconcileStartupOpenRows: reconcileStartupOpenRows ?? ((liveSet, end) => 0),
                writeCollectionGap: writeCollectionGap ?? ((start, end, prior, reason) => { }),
                updateHeartbeat: updateHeartbeat ?? (() => { }),
                log: (message, level) =>
                {
                    logs?.Add(message);
                    logEntries?.Add((message, level));
                },
                lookupAccountSid: lookupAccountSid ?? (sid => string.Empty),
                lookupTokenUserByPid: lookupTokenUserByPid ?? (pid => string.Empty),
                lookupPebCommandLineByPid: lookupPebCommandLineByPid ?? (pid => string.Empty),
                lookupFullProcessImagePathByPid: lookupFullProcessImagePathByPid ?? (pid => string.Empty),
                translateDevicePath: translateDevicePath ?? (path => string.Empty),
                getProcessHistory: getProcessHistory ?? (() => Array.Empty<ProcessRecord>()),
                repairParentLinkage: repairParentLinkage ?? ((pidHash, parentPid, parentPidHash) => false),
                sidAccountCacheMaxSize: sidAccountCacheMaxSize,
                enableQaCounterTimer: false);
        }

        private static void AssertQaCounterName(string formatted, string name, string value)
        {
            Assert.Equal(1, CountOccurrences(formatted, name + "="));
            Assert.Contains(name + "=" + value, formatted);
        }

        private static int CountOccurrences(string value, string search)
        {
            int count = 0;
            int index = 0;
            while ((index = value.IndexOf(search, index, StringComparison.Ordinal)) >= 0)
            {
                count++;
                index += search.Length;
            }

            return count;
        }

        private static ManifestStopMetrics Metrics(int pid, DateTime timestampUtc)
            => new ManifestStopMetrics
            {
                Pid = pid,
                TimestampUtc = timestampUtc,
                ImageName = "manifest.exe",
                ExitCode = 222,
                CPUCycleCount = 123456789,
                CommitCharge = 111,
                CommitPeak = 222,
                HardFaultCount = 333,
                ReadOperationCount = 444,
                ReadTransferKiloBytes = 555,
                TokenElevationType = 2,
                WriteOperationCount = 666,
                WriteTransferKiloBytes = 777,
                ActivityId = "activity-id",
                CorrelationId = "correlation-id"
            };

        private static string TestPidHash(int pid, long fileTimeUtc)
            => $"pid={pid};fileTimeUtc={fileTimeUtc}";

        private static DateTime BootTime()
            => new DateTime(2026, 8, 17, 8, 0, 0, DateTimeKind.Utc);

        private static SnapshotProcessInfo Snapshot(int pid, int parentPid, DateTime createTimeUtc, string name)
            => new SnapshotProcessInfo
            {
                Pid = pid,
                ParentPid = parentPid,
                CreateTimeUtc = createTimeUtc,
                Name = name,
                Path = $"C:\\Tools\\{name}",
                CommandLine = $"{name} --flag",
                User = "DOMAIN\\user"
            };

        private static void AssertSyntheticSeed(WintapMessage message, int pid, string name, string path, DateTime bootTime)
        {
            Assert.Equal(WintapMessage.ActivityTypeEnum.Refresh, message.ActivityType);
            Assert.Equal(bootTime.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(TestPidHash(pid, bootTime.ToFileTimeUtc()), message.PidHash);
            Assert.Equal(name, message.ProcessName);
            Assert.Equal(path, message.ProcessPath);
            Assert.Equal(pid, message.Process.PID);
            Assert.Equal(4, message.Process.ParentPID);
            Assert.Equal(TestPidHash(4, bootTime.ToFileTimeUtc()), message.Process.ParentPidHash);
            Assert.Equal(name, message.Process.Name);
            Assert.Equal(path, message.Process.Path);
            Assert.Equal(string.Empty, message.Process.CommandLine);
            Assert.Equal(string.Empty, message.Process.Arguments);
            Assert.Equal("SYSTEM", message.Process.User);
        }

        private static void AssertFallbackSeeds(IReadOnlyList<WintapMessage> emitted, DateTime bootTime)
        {
            foreach (int pid in new[] { 4, 0, -1 })
            {
                WintapMessage seed = emitted.Single(message => message.PID == pid);
                Assert.Equal(bootTime.ToFileTimeUtc(), seed.EventTime);
                Assert.Equal(TestPidHash(pid, bootTime.ToFileTimeUtc()), seed.PidHash);
                Assert.Equal(TestPidHash(4, bootTime.ToFileTimeUtc()), seed.Process.ParentPidHash);
            }
        }

        private static void AssertMergedStop(WintapMessage message, ProcessRecord resolved, long exitCode)
        {
            Assert.Equal(WintapMessage.ActivityTypeEnum.Stop, message.ActivityType);
            Assert.Equal(resolved.PidHash, message.PidHash);
            Assert.Equal(resolved.ParentPidHash, message.Process.ParentPidHash);
            Assert.Equal(resolved.ParentProcessId, message.Process.ParentPID);
            Assert.Equal(resolved.ProcessName, message.ProcessName);
            Assert.Equal(resolved.ProcessPath, message.ProcessPath);
            Assert.Equal(resolved.ProcessName, message.Process.Name);
            Assert.Equal(resolved.ProcessPath, message.Process.Path);
            Assert.Equal(exitCode, message.Process.ExitCode);
            Assert.Equal(123456789, message.Process.CPUCycleCount);
            Assert.Equal(0, message.Process.CPUUtilization);
            Assert.Equal(111, message.Process.CommitCharge);
            Assert.Equal(222, message.Process.CommitPeak);
            Assert.Equal(333, message.Process.HardFaultCount);
            Assert.Equal(444, message.Process.ReadOperationCount);
            Assert.Equal(555, message.Process.ReadTransferKiloBytes);
            Assert.Equal(2, message.Process.TokenElevationType);
            Assert.Equal(666, message.Process.WriteOperationCount);
            Assert.Equal(777, message.Process.WriteTransferKiloBytes);
            Assert.Equal("activity-id", message.ActivityId);
            Assert.Equal("correlation-id", message.CorrelationId);
        }

        private static void AssertDefaultStopMetrics(WintapMessage message)
        {
            Assert.Equal(0, message.Process.CPUCycleCount);
            Assert.Equal(0, message.Process.CPUUtilization);
            Assert.Equal(0, message.Process.CommitCharge);
            Assert.Equal(0, message.Process.CommitPeak);
            Assert.Equal(0, message.Process.HardFaultCount);
            Assert.Equal(0, message.Process.ReadOperationCount);
            Assert.Equal(0, message.Process.ReadTransferKiloBytes);
            Assert.Equal(0, message.Process.TokenElevationType);
            Assert.Equal(0, message.Process.WriteOperationCount);
            Assert.Equal(0, message.Process.WriteTransferKiloBytes);
        }
    }
}
