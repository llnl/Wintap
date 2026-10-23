using System;
using System.Diagnostics;
using DuckDB.NET.Data;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class ProcessResolverTests
    {
        [Fact, Trait("Category", "clone-validation")]
        public void UnmarkedDuplicateStart_CharacterizesExistingMetadataOverwrite()
        {
            using var connection = CreateEventStore();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false,
                registrationLogSink: (_, _) => { });
            RegisterLifecycle(connection, resolver, "duplicate", WintapMessage.ActivityTypeEnum.Start, 0, 0, null);
            var late = new WintapMessage(BaseTime, 42, WintapMessage.MessageTypeEnum.Process)
            {
                PidHash = "duplicate", ActivityType = WintapMessage.ActivityTypeEnum.Start,
                Process = new WintapMessage.ProcessObject
                {
                    Name = "inherited", Path = "inherited", ParentPID = 1,
                    CommandLine = "inherited", User = "fixture"
                }
            };
            resolver.RegisterProcess(late);
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT process_name FROM process WHERE pid_hash='duplicate'";
            Assert.Equal("inherited", read.ExecuteScalar());
            Assert.Equal(1L, ScalarLong(connection, "SELECT COUNT(*) FROM process"));
        }

        [Theory, Trait("Category", "clone-validation")]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        public void CloneAndExec_KeepOneIdentityAndExecMetadata(bool execFirst, bool stopped)
        {
            using var connection = CreateEventStore();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false,
                registrationLogSink: (_, _) => { });
            WintapMessage Start(string name, string source) => new WintapMessage(
                BaseTime, 42, WintapMessage.MessageTypeEnum.Process)
            {
                PidHash = "clone-exec-identity",
                ActivityType = WintapMessage.ActivityTypeEnum.Start,
                Process = new WintapMessage.ProcessObject
                {
                    PID = 42, ParentPID = 1, ParentPidHash = "parent", Name = name,
                    Path = "/bin/" + name, CommandLine = name + " args", User = "fixture",
                    Arguments = "PROC_START_SRC=" + source, MD5 = name, SHA2 = name
                }
            };
            var clone = Start("inherited", "sched_fork");
            var exec = Start("executed", "sched_exec");
            if (!execFirst) resolver.RegisterProcess(clone);
            resolver.RegisterProcess(exec);
            if (stopped)
            {
                var stop = Start("executed", "sched_exec");
                stop.ActivityType = WintapMessage.ActivityTypeEnum.Stop;
                stop.EventTime = BaseTime.AddSeconds(2).ToFileTimeUtc();
                resolver.RegisterProcess(stop);
            }
            // Include a duplicate birth even in ordinary Clone->Exec order.
            resolver.RegisterProcess(clone);
            Assert.Equal(1L, ScalarLong(connection, "SELECT COUNT(*) FROM process"));
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT process_name, image_path, command_line, md5_hash FROM process";
            using (var row = read.ExecuteReader())
            {
                Assert.True(row.Read());
                Assert.Equal("executed", row.GetString(0));
                Assert.Equal("/bin/executed", row.GetString(1));
                Assert.Equal("executed args", row.GetString(2));
                Assert.Equal("executed", row.GetString(3));
            }
            AssertStoredLifetime(connection, "clone-exec-identity", BaseTime,
                stopped ? BaseTime.AddSeconds(2) : (DateTime?)null);
            Assert.Equal(!stopped, resolver.TryResolveCurrentProcessAtTime(42,
                BaseTime.AddSeconds(3), out var active));
            if (!stopped) Assert.Equal("executed", active.ProcessName);
        }

        [Theory, Trait("Category", "pai-07")]
        [InlineData(true, true, false)]
        [InlineData(true, false, false)]
        [InlineData(false, true, true)]
        [InlineData(false, false, false)]
        public void ContinuousReconciliation_UsesEffectivePlatformPolicy(
            bool isWindows, bool requested, bool expected)
        {
            Assert.Equal(expected, ProcessResolver.IsContinuousReconciliationEnabled(isWindows, requested));
            using var connection = CreateEventStore();
            DateTime now = BaseTime.AddHours(3);
            int calls = 0;
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: true,
                registrationLogSink: (_, _) => { }, requestedReconciliation: requested,
                isWindows: isWindows, maintenanceClock: () => now,
                reconciliationStep: observed =>
                {
                    Assert.Equal(now, observed);
                    calls++;
                });
            Assert.Null(resolver.ResolveProcessAtTime(999, BaseTime));
            Assert.Equal(expected ? 1 : 0, calls);
            AssertMaintenanceHeartbeat(connection, now);
            now = now.AddMinutes(4);
            Assert.Null(resolver.ResolveProcessAtTime(999, BaseTime));
            Assert.Equal(expected ? 1 : 0, calls);
            AssertMaintenanceHeartbeat(connection, now.AddMinutes(-4));
            now = now.AddMinutes(1);
            Assert.Null(resolver.ResolveProcessAtTime(999, BaseTime));
            Assert.Equal(expected ? 2 : 0, calls);
            AssertMaintenanceHeartbeat(connection, now);
        }

        [Fact, Trait("Category", "pai-07")]
        public void WindowsSweeps_PreservePublishedIdentityAndContinueHousekeepingAndStops()
        {
            using var connection = CreateEventStore();
            DateTime now = BaseTime.AddHours(3);
            DateTime initialSweep = now;
            int reconcileCalls = 0;
            var logs = new System.Collections.Generic.List<string>();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: true,
                registrationLogSink: (message, _) => logs.Add(message),
                requestedReconciliation: true, isWindows: true, maintenanceClock: () => now,
                reconciliationStep: _ =>
                {
                    reconcileCalls++;
                    throw new InvalidOperationException("Windows must not reconcile during maintenance");
                });

            RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Start, 0, 0, null);
            InsertProcess(connection, "child", 43, "child", BaseTime.AddMinutes(1), null);
            InsertProcess(connection, "parent", 1, "parent", BaseTime.AddHours(-1), BaseTime.AddMinutes(-1));
            InsertProcess(connection, "grandparent", 2, "grandparent", BaseTime.AddHours(-2), BaseTime.AddHours(-1));
            InsertProcess(connection, "expired", 44, "expired", BaseTime, BaseTime.AddMinutes(10));
            InsertProcess(connection, "recent", 45, "recent", BaseTime, initialSweep.AddMinutes(-10));
            using (var links = connection.CreateCommand())
            {
                links.CommandText = "UPDATE process SET parent_pid_hash='A' WHERE pid_hash='child'; " +
                    "UPDATE process SET parent_pid_hash='grandparent' WHERE pid_hash='parent'";
                links.ExecuteNonQuery();
            }

            // Cold durable calls exercise maintenance without any live OS fallback.
            now = initialSweep.AddMinutes(4);
            Assert.Equal("child", resolver.ResolveProcessAtTime(43, BaseTime.AddMinutes(2)).PidHash);
            AssertMaintenanceHeartbeat(connection, initialSweep);
            Assert.Equal(1L, ScalarLong(connection, "SELECT COUNT(*) FROM process WHERE pid_hash='expired'"));

            foreach (int minute in new[] { 5, 10 })
            {
                now = initialSweep.AddMinutes(minute);
                var child = resolver.ResolveProcessAtTime(43, BaseTime.AddMinutes(2));
                Assert.Equal("child", child.PidHash);
                Assert.Equal("A", child.ParentPidHash);
                AssertStoredLifetime(connection, "A", BaseTime, null);
                Assert.True(resolver.TryResolveCurrentProcessAtTime(42, now, out var active));
                Assert.Equal("A", active.PidHash);
                Assert.Equal(BaseTime, active.CreateTime);
                Assert.Null(active.ExitTime);
                Assert.Equal(0, reconcileCalls);
                AssertMaintenanceHeartbeat(connection, now);
                Assert.Equal(0L, ScalarLong(connection, "SELECT COUNT(*) FROM process WHERE pid_hash='expired'"));
                Assert.Equal(3L, ScalarLong(connection,
                    "SELECT COUNT(*) FROM process WHERE pid_hash IN ('parent','grandparent','recent')"));
                Assert.Equal(0L, ScalarLong(connection,
                    "SELECT COUNT(*) FROM process_retention_telemetry WHERE metric_name IN ('live_hash_repaired','reconciled_closed')"));
            }
            Assert.Equal(1L, ScalarLong(connection,
                "SELECT CAST(SUM(metric_value) AS BIGINT) FROM process_retention_telemetry WHERE metric_name='retention_deleted'"));
            resolver.TakeHistoricalIdentityCacheCounters(out _, out _, out _, out _);
            var historical = resolver.ResolveProcessIdentityAtTime(44, BaseTime.AddMinutes(5));
            Assert.Equal("expired", historical.PidHash);
            Assert.Equal(BaseTime, historical.CreateTime);
            Assert.Equal(BaseTime.AddMinutes(10), historical.ExitTime);
            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out _, out _, out _);
            Assert.Equal(1, hits);

            // The real Stop still closes the issued key at event time; duplicate Stop is idempotent.
            RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Stop, 11400, 0, 11400);
            RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Stop, 11400, 0, 11400);
            Assert.False(resolver.TryResolveCurrentProcessAtTime(42, now, out _));
            now = initialSweep.AddMinutes(15);
            Assert.Equal("child", resolver.ResolveProcessAtTime(43, BaseTime.AddMinutes(2)).PidHash);
            AssertStoredLifetime(connection, "A", BaseTime, BaseTime.AddSeconds(11400));
            Assert.Equal(1L, ScalarLong(connection,
                "SELECT CAST(SUM(metric_value) AS BIGINT) FROM process_retention_telemetry WHERE metric_name='stop_closed'"));
            Assert.Equal(1L, ScalarLong(connection, "SELECT COUNT(*) FROM process WHERE pid_hash='A'"));
            Assert.Equal(0, reconcileCalls);
            Assert.DoesNotContain(logs, message => message.Contains("live_hash_repaired") ||
                message.Contains("reconciled_closed") || message.Contains("failed", StringComparison.OrdinalIgnoreCase));
            AssertMaintenanceHeartbeat(connection, now);
        }

        private static long ScalarLong(DuckDBConnection connection, string sql)
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToInt64(command.ExecuteScalar());
        }

        private static void AssertMaintenanceHeartbeat(DuckDBConnection connection, DateTime expected)
        {
            Assert.True(ProcessResolver.TryReadHeartbeat(connection, out DateTime heartbeat, out string session));
            Assert.Equal(expected, heartbeat);
            Assert.Equal("test", session);
        }

        private readonly Xunit.Abstractions.ITestOutputHelper _output;

        public ProcessResolverTests(Xunit.Abstractions.ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        [Trait("Category", "profile")]
        public void RepeatedUnresolvedOwnerLookups_ProfileDurableResolverCost()
        {
            using var connection = CreateEventStore();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false,
                registrationLogSink: (_, _) => { });
            const int lookups = 1000;
            var stopwatch = Stopwatch.StartNew();

            for (int i = 0; i < lookups; i++)
            {
                Assert.Null(resolver.ResolveProcessAtTime(999999, BaseTime));
            }

            stopwatch.Stop();
            _output.WriteLine($"Repeated unresolved durable lookups: count={lookups}; elapsed_ms={stopwatch.Elapsed.TotalMilliseconds:F2}; avg_us={(stopwatch.Elapsed.TotalMilliseconds * 1000 / lookups):F2}");
        }

        [Theory, Trait("Category", "pai-08"), Trait("Category", "pai-04"), Trait("Category", "pai-06")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Normal active hit", 5, "A", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Normal active hit", 5, "A", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Normal active hit", 5, "A", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Normal active hit", 5, "A", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Active miss durable open", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Active miss durable open", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Active miss durable open", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Active miss durable open", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Active miss closed history cold", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Active miss closed history cold", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Active miss closed history cold", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Active miss closed history cold", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Active miss closed history warm", 5, "A", "historical-cache")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Active miss closed history warm", 5, "A", "historical-cache")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Active miss closed history warm", 5, "A", "historical-cache")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Active miss closed history warm", 5, "A", "historical-cache")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Disjoint PID reuse A", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Disjoint PID reuse A", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Disjoint PID reuse A", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Disjoint PID reuse A", 5, "A", "durable")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Disjoint PID reuse gap", 15, null, "unresolved")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Disjoint PID reuse gap", 15, null, "unresolved")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Disjoint PID reuse gap", 15, null, "unresolved")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Disjoint PID reuse gap", 15, null, "unresolved")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Disjoint PID reuse B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Disjoint PID reuse B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Disjoint PID reuse B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Disjoint PID reuse B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.File, "Late Stop A preserves B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.Registry, "Late Stop A preserves B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection, "Late Stop A preserves B", 25, "B", "active")]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad, "Late Stop A preserves B", 25, "B", "active")]
        public void OwnerIdentityLifecycle_Controls(
            WintapMessage.MessageTypeEnum type, string scenario, int lookupSecond, string expected, string expectedComponent)
        {
            using var connection = CreateEventStore();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false, registrationLogSink: (_, _) => { });
            if (scenario == "Active miss durable open")
            {
                InsertProcess(connection, "A", 42, "A", BaseTime, null);
                AssertStoredLifetime(connection, "A", BaseTime, null);
            }
            else
            {
                RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Start, 0, 0, null);
                if (scenario != "Normal active hit")
                {
                    RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Stop, 10, 0, 10);
                    if (scenario.StartsWith("Disjoint") || scenario == "Late Stop A preserves B")
                        RegisterLifecycle(connection, resolver, "B", WintapMessage.ActivityTypeEnum.Start, 20, 20, null);
                    if (scenario == "Late Stop A preserves B")
                        RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Stop, 10, 0, 10);
                    if (scenario == "Active miss closed history warm")
                        Assert.Equal("A", ResolveOwnerComponents(resolver, type, 5, out _).PidHash);
                }
            }

            ProcessRecord observed = ResolveOwnerComponents(resolver, type, lookupSecond, out string component);
            ReportFileIdentity(connection, scenario, lookupSecond, expected, observed, component);
            Assert.Equal(expected, observed?.PidHash);
            Assert.Equal(expected, observed?.ProcessName);
            Assert.Equal(expectedComponent, component);
            if (observed != null)
            {
                Assert.Equal(42, observed.ProcessId);
                Assert.Equal(BaseTime.AddSeconds(expected == "B" ? 20 : 0), observed.CreateTime);
                Assert.Equal(component == "active" || scenario == "Active miss durable open"
                    ? (DateTime?)null : BaseTime.AddSeconds(10), observed.ExitTime);
            }
        }


        [Theory, Trait("Category", "pai-06")]
        [InlineData(@"C:\apps\owner.exe", "stored_identity")]
        [InlineData(@"\\server\share\owner.exe", "stored_identity")]
        [InlineData(@"\Device\HarddiskVolume3\owner.exe", "stored_identity")]
        [InlineData("", "path_missing")]
        [InlineData("owner.exe", "path_not_full")]
        [InlineData(@"C:owner.exe", "path_not_full")]
        [InlineData(@"\owner.exe", "path_not_full")]
        public void AttributedPathRequiresExactStoredIdentity(string path, string status)
        {
            using var connection = CreateProcessDatabase();
            InsertProcess(connection, "A", 42, "A", BaseTime, BaseTime.AddSeconds(10));
            InsertProcess(connection, "B", 42, "B", BaseTime.AddSeconds(20), null);
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE process SET image_path=$path WHERE pid_hash='A'";
            update.Parameters.Add(new DuckDBParameter("path", path));
            update.ExecuteNonQuery();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: true);
            var result = resolver.ReadAttributedProcessPath("A", 42);
            Assert.Equal(status, result.Status);
            Assert.Equal(status == "stored_identity" ? path : null, result.Path);
            Assert.Equal("identity_not_found", resolver.ReadAttributedProcessPath("A", 43).Status);
            Assert.Equal("identity_not_found", resolver.ReadAttributedProcessPath("missing", 42).Status);
            Assert.Equal("path_missing", resolver.ReadAttributedProcessPath("B", 42).Status);
            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out long evictions, out int entries);
            Assert.Equal(0, hits + misses + evictions + entries);
            using var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM process";
            Assert.Equal(2L, Convert.ToInt64(count.ExecuteScalar())); // no retention maintenance
        }

        [Theory, Trait("Category", "pai-06")]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("Unknown")]
        [InlineData(" ")]
        public void MissingAttributedIdentitySkipsDatabase(string hash)
        {
            using var connection = CreateProcessDatabase();
            var resolver = new ProcessResolver(connection, 16);
            using var drop = connection.CreateCommand();
            drop.CommandText = "DROP TABLE process";
            drop.ExecuteNonQuery();
            Assert.Equal("missing_identity", resolver.ReadAttributedProcessPath(hash, 42).Status);
            string sentinel = new gov.llnl.wintap.core.shared.helpers.ProcessHash().GenKeyForProcess("llnl", Environment.MachineName, Guid.Empty, -1, 0, "Process");
            Assert.Equal("missing_identity", resolver.ReadAttributedProcessPath(sentinel, 42).Status);
            Assert.Equal("lookup_failed", resolver.ReadAttributedProcessPath("A", 42).Status);
        }

        [Fact, Trait("Category", "pai-06")]
        public async System.Threading.Tasks.Task BusyAttributedPathReturnsWithoutWaitingForOwner()
        {
            using var connection = CreateProcessDatabase();
            var resolver = new ProcessResolver(connection, 16);
            object sync = typeof(ProcessResolver).GetField("_dbLock",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetValue(resolver);
            using var entered = new System.Threading.ManualResetEventSlim();
            using var release = new System.Threading.ManualResetEventSlim();
            var holder = System.Threading.Tasks.Task.Run(() =>
            {
                lock (sync) { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(5))); }
            });
            try
            {
                Assert.True(entered.Wait(TimeSpan.FromSeconds(2)));
                var read = System.Threading.Tasks.Task.Run(() => resolver.ReadAttributedProcessPath("A", 42));
                var result = await read.WaitAsync(TimeSpan.FromSeconds(2));
                Assert.Equal("resolver_busy", result.Status);
                Assert.Null(result.Path);
                Assert.False(holder.IsCompleted);
            }
            finally { release.Set(); await holder; }
        }

        [Theory, Trait("Category", "pai-06"), Trait("Category", "pai-08")]
        [InlineData(WintapMessage.MessageTypeEnum.File)]
        [InlineData(WintapMessage.MessageTypeEnum.Registry)]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection)]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad)]
        public void DelayedDisjointInstanceUsesDurableThenCacheWhileNewInstanceIsActive(WintapMessage.MessageTypeEnum type)
        {
            using var connection = CreateEventStore();
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false, registrationLogSink: (_, _) => { });
            RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Start, 0, 0, null);
            RegisterLifecycle(connection, resolver, "A", WintapMessage.ActivityTypeEnum.Stop, 10, 0, 10);
            RegisterLifecycle(connection, resolver, "B", WintapMessage.ActivityTypeEnum.Start, 20, 20, null);
            foreach (string expectedComponent in new[] { "durable", "historical-cache" })
            {
                var old = ResolveOwnerComponents(resolver, type, 5, out string component);
                Assert.Equal(42, old.ProcessId);
                Assert.Equal("A", old.PidHash);
                Assert.Equal("A", old.ProcessName);
                Assert.Equal(expectedComponent, component);
                var current = ResolveOwnerComponents(resolver, type, 25, out string active);
                Assert.Equal(42, current.ProcessId);
                Assert.Equal("B", current.PidHash);
                Assert.Equal("B", current.ProcessName);
                Assert.Equal("active", active);
                Assert.Null(ResolveOwnerComponents(resolver, type, 15, out string gap));
                Assert.Equal("unresolved", gap);
            }
        }

        private static void RegisterLifecycle(DuckDBConnection connection, ProcessResolver resolver,
            string identity, WintapMessage.ActivityTypeEnum activity, int eventSecond, int createdSecond, int? exitedSecond)
        {
            var message = new WintapMessage(BaseTime.AddSeconds(eventSecond), 42, WintapMessage.MessageTypeEnum.Process)
            {
                PID = 42,
                PidHash = identity,
                EventTime = BaseTime.AddSeconds(eventSecond).ToFileTimeUtc(),
                ActivityType = activity,
                Process = new WintapMessage.ProcessObject
                {
                    PID = 42, Name = identity, ParentPID = 1, ParentPidHash = "parent",
                    Path = identity, CommandLine = identity, User = "fixture", MD5 = "", SHA2 = ""
                }
            };
            resolver.RegisterProcess(message);
            // RegisterProcess swallows some errors: verify each mutation independently.
            AssertStoredLifetime(connection, identity, BaseTime.AddSeconds(createdSecond),
                exitedSecond.HasValue ? BaseTime.AddSeconds(exitedSecond.Value) : (DateTime?)null);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT process_id, process_name, parent_process_id FROM process WHERE pid_hash = $hash";
            command.Parameters.Add(new DuckDBParameter("hash", identity));
            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(42, reader.GetInt32(0));
            Assert.Equal(identity, reader.GetString(1));
            Assert.Equal(1, reader.GetInt32(2));
        }

        private static ProcessRecord ResolveOwnerComponents(ProcessResolver resolver, WintapMessage.MessageTypeEnum type,
            int second, out string component)
        {
            resolver.TakeHistoricalIdentityCacheCounters(out _, out _, out _, out _);
            DateTime time = BaseTime.AddSeconds(second);
            var message = new WintapMessage(time, 42, type);
            ProcessRecord record = EventOwnerSelection.ResolveOwner(resolver, message, time, true, out _);
            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out _, out _);
            component = hits > 0 ? "historical-cache" : misses > 0
                ? (record == null ? "unresolved" : "durable") : "active";
            return record;
        }

        private void ReportFileIdentity(DuckDBConnection connection, string scenario, int second,
            string expected, ProcessRecord observed, string component)
        {
            bool correct = observed?.PidHash == expected && observed?.ProcessName == expected;
            _output.WriteLine(
                $"{scenario}: T={BaseTime:O}; lookup=T+{second}; expected hash/name={expected ?? "none"}/{expected ?? "none"}; " +
                $"observed hash/name={observed?.PidHash ?? "none"}/{observed?.ProcessName ?? "none"}; " +
                $"component={component}; correctness={(correct ? "PASS" : "FAIL")}");
            _output.WriteLine(observed == null ? "returned lifetime=none" :
                $"returned lifetime=[{observed.CreateTime:O}, {observed.ExitTime?.ToString("O") ?? "open"}]");
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT pid_hash, process_name, create_time, exit_time FROM process WHERE process_id = 42 ORDER BY create_time";
            using var reader = command.ExecuteReader();
            int rows = 0;
            while (reader.Read())
            {
                rows++;
                _output.WriteLine($"stored hash/name={reader.GetString(0)}/{reader.GetString(1)}; " +
                    $"lifetime=[{reader.GetDateTime(2):O}, {(reader.IsDBNull(3) ? "open" : reader.GetDateTime(3).ToString("O"))}]");
            }
            if (rows == 0) _output.WriteLine("stored lifetime=none (no process rows)");
        }
        private static readonly DateTime BaseTime = new DateTime(2026, 8, 30, 12, 0, 0, DateTimeKind.Utc);

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(null, 10, true)]
        [InlineData("", 20, true)]
        [InlineData("unknown-parent", 30, true)]
        [InlineData("healthy-parent", 40, false)]
        public void TryRepairParentLinkage_OnlyReplacesMissingOrSentinelParent(
            string storedParentHash,
            int storedParentPid,
            bool expectedRepair)
        {
            using var connection = CreateProcessTable();
            using (var insert = connection.CreateCommand())
            {
                insert.CommandText = @"
                    INSERT INTO process (pid_hash, parent_pid_hash, process_id, parent_process_id)
                    VALUES ($pid_hash, $parent_pid_hash, 100, $parent_process_id)";
                insert.Parameters.Add(new DuckDBParameter("pid_hash", "child"));
                insert.Parameters.Add(new DuckDBParameter("parent_pid_hash", storedParentHash == null ? DBNull.Value : storedParentHash));
                insert.Parameters.Add(new DuckDBParameter("parent_process_id", storedParentPid));
                insert.ExecuteNonQuery();
            }

            bool repaired = ProcessResolver.TryRepairParentLinkage(
                connection,
                "child",
                50,
                "resolved-parent",
                "unknown-parent");

            Assert.Equal(expectedRepair, repaired);
            using var select = connection.CreateCommand();
            select.CommandText = "SELECT parent_pid_hash, parent_process_id FROM process WHERE pid_hash = 'child'";
            using var reader = select.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(expectedRepair ? "resolved-parent" : storedParentHash, reader.GetString(0));
            Assert.Equal(expectedRepair ? 50 : storedParentPid, reader.GetInt32(1));
        }

        [Theory]
        [Trait("Category", "wpc-09")]
        [InlineData("cmd.exe /c \"unterminated")]
        [InlineData("powershell.exe -Command \"Write-Output 'quoted value'\"")]
        [InlineData("tool.exe --value=\"double quoted\"")]
        [InlineData("C:\\Program Files\\Example App\\tool.exe /path C:\\Temp\\some file.txt")]
        public void UpsertProcessStart_PreservesHostileCommandLineExactly(string commandLine)
        {
            using var connection = new DuckDBConnection("Data Source=:memory:");
            connection.Open();
            using (var create = connection.CreateCommand())
            {
                create.CommandText = @"
                    CREATE TABLE process (
                        pid_hash VARCHAR PRIMARY KEY,
                        parent_pid_hash VARCHAR,
                        process_id INTEGER,
                        parent_process_id INTEGER,
                        process_name VARCHAR,
                        image_path VARCHAR,
                        command_line VARCHAR,
                        create_time TIMESTAMP,
                        exit_time TIMESTAMP,
                        exit_code INTEGER,
                        source VARCHAR,
                        user_name VARCHAR,
                        md5_hash VARCHAR,
                        sha2_hash VARCHAR);";
                create.ExecuteNonQuery();
            }

            DateTime createTime = new DateTime(2026, 8, 18, 12, 0, 0, DateTimeKind.Utc);
            var message = new WintapMessage(createTime, 6080, WintapMessage.MessageTypeEnum.Process)
            {
                ActivityType = WintapMessage.ActivityTypeEnum.Start,
                PidHash = "hostile-command-line-hash",
                Process = new WintapMessage.ProcessObject
                {
                    PID = 6080,
                    ParentPID = 100,
                    ParentPidHash = "parent's-hash",
                    Name = "WmiPrvSE.exe",
                    Path = @"C:\Windows\system32\wbem\wmiprvse.exe",
                    CommandLine = commandLine,
                    User = @"DOMAIN\user",
                    MD5 = "md5'value",
                    SHA2 = "sha2\"value"
                }
            };

            ProcessResolver.UpsertProcessStart(connection, message, createTime);

            using var select = connection.CreateCommand();
            select.CommandText = "SELECT command_line FROM process WHERE pid_hash = 'hostile-command-line-hash'";
            Assert.Equal(commandLine, select.ExecuteScalar()?.ToString());
        }

        [Fact]
        [Trait("Category", "wpc-12")]
        public void DuckDbProcessTimestampReader_AttachesUtcKindWithoutChangingValues()
        {
            using var connection = CreateEventStore();
            DateTime createTimeUtc = new DateTime(2026, 8, 31, 14, 20, 30, DateTimeKind.Utc);
            DateTime exitTimeUtc = createTimeUtc.AddMinutes(2);
            var message = new WintapMessage(createTimeUtc, 7000, WintapMessage.MessageTypeEnum.Process)
            {
                ActivityType = WintapMessage.ActivityTypeEnum.Start,
                PidHash = "utc-kind-process",
                Process = new WintapMessage.ProcessObject
                {
                    PID = 7000,
                    ParentPID = 4,
                    ParentPidHash = "system",
                    Name = "utc-kind.exe"
                }
            };

            ProcessResolver.UpsertProcessStart(connection, message, createTimeUtc);
            using (var update = connection.CreateCommand())
            {
                update.CommandText = "UPDATE process SET exit_time = $exit_time WHERE pid_hash = $pid_hash";
                update.Parameters.Add(new DuckDBParameter("exit_time", exitTimeUtc));
                update.Parameters.Add(new DuckDBParameter("pid_hash", message.PidHash));
                Assert.Equal(1, update.ExecuteNonQuery());
            }

            using var select = connection.CreateCommand();
            select.CommandText = "SELECT create_time, exit_time FROM process WHERE pid_hash = $pid_hash";
            select.Parameters.Add(new DuckDBParameter("pid_hash", message.PidHash));
            using var reader = select.ExecuteReader();
            Assert.True(reader.Read());

            DateTime createTime = ProcessResolver.ReadUtcDateTime(reader, 0);
            DateTime? exitTime = ProcessResolver.ReadNullableUtcDateTime(reader, 1);
            Assert.Equal(createTimeUtc, createTime);
            Assert.Equal(DateTimeKind.Utc, createTime.Kind);
            Assert.Equal(exitTimeUtc, exitTime);
            Assert.Equal(DateTimeKind.Utc, exitTime.Value.Kind);
        }

        [Fact]
        [Trait("Category", "wpc-12")]
        public void ClearProcessRows_DeletesWithoutReconcileTelemetry()
        {
            using var connection = CreateEventStore();
            using (var insert = connection.CreateCommand())
            {
                insert.CommandText = @"
                    INSERT INTO process (pid_hash, process_id, process_name, create_time, source)
                    VALUES ('stale-open', 7001, 'stale.exe', TIMESTAMP '2026-08-31 14:00:00', 'real_time')";
                insert.ExecuteNonQuery();
            }

            long deleted = ProcessResolver.ClearProcessRows(connection);

            Assert.Equal(1, deleted);
            using var processCount = connection.CreateCommand();
            processCount.CommandText = "SELECT COUNT(*) FROM process";
            Assert.Equal(0L, Convert.ToInt64(processCount.ExecuteScalar()));
            using var reconcileCount = connection.CreateCommand();
            reconcileCount.CommandText = "SELECT COUNT(*) FROM process_retention_telemetry WHERE metric_name = 'reconciled_closed'";
            Assert.Equal(0L, Convert.ToInt64(reconcileCount.ExecuteScalar()));
        }

        [Fact]
        [Trait("Category", "wpc-13"), Trait("Category", "pai-02")]
        public void ResolveProcessAtTimeQuery_ResolvesParentCreatedEarlierInSameSecond()
        {
            using var connection = CreateEventStore();
            DateTime second = new DateTime(2026, 8, 31, 15, 31, 55, DateTimeKind.Utc);
            InsertProcess(connection, "parent", 8100, second.AddMilliseconds(800));

            object result = ExecuteResolveProcessAtTimeQuery(connection, 8100, second.AddMilliseconds(900));

            Assert.Equal("parent", result?.ToString());
        }

        [Fact]
        [Trait("Category", "wpc-13"), Trait("Category", "pai-02")]
        public void ResolveProcessAtTimeQuery_DoesNotResolveParentCreatedLaterInSameSecond()
        {
            using var connection = CreateEventStore();
            DateTime second = new DateTime(2026, 8, 31, 15, 31, 55, DateTimeKind.Utc);
            InsertProcess(connection, "parent", 8100, second.AddMilliseconds(800));

            object result = ExecuteResolveProcessAtTimeQuery(connection, 8100, second.AddMilliseconds(700));

            Assert.Null(result);
        }

        [Theory, Trait("Category", "pai-01"), Trait("Category", "pai-02")]
        [InlineData(0, "new")]
        [InlineData(1, null)]
        [InlineData(2, "new")]
        public void DurableLookupsPreserveSubmillisecondLifetimes(int scenario, string expected)
        {
            using var connection = CreateEventStore();
            DateTime second = new DateTime(2026, 10, 5, 12, 0, 0, DateTimeKind.Utc);
            if (scenario != 0)
                InsertProcess(connection, "old", 42, "old", second.AddSeconds(-1), second.AddTicks(scenario == 2 ? 4000 : 5000));
            if (scenario != 1)
                InsertProcess(connection, "new", 42, "new", second.AddTicks(5000), second.AddSeconds(1));
            using (var read = connection.CreateCommand())
            {
                read.CommandText = "SELECT pid_hash, create_time, exit_time FROM process ORDER BY pid_hash";
                using var reader = read.ExecuteReader();
                int rows = 0;
                while (reader.Read())
                {
                    bool old = reader.GetString(0) == "old";
                    Assert.Equal(old ? second.AddSeconds(-1) : second.AddTicks(5000), reader.GetDateTime(1));
                    Assert.Equal(old ? second.AddTicks(scenario == 2 ? 4000 : 5000) : second.AddSeconds(1), reader.GetDateTime(2));
                    rows++;
                }
                Assert.Equal(scenario == 2 ? 2 : 1, rows);
            }
            DateTime lookup = second.AddTicks(8000);
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false);
            AssertDurableOwner(connection, resolver, 42, lookup, expected);
            Assert.Equal(expected, ExecuteResolveProcessAtTimeQuery(connection, 42, lookup)?.ToString());
        }

        [Theory, Trait("Category", "pai-02")]
        [InlineData(4990, null)]
        [InlineData(5000, "owner")]
        [InlineData(8000, "owner")]
        [InlineData(9000, "owner")]
        [InlineData(9010, null)]
        public void DurableLookupsRespectInclusiveMicrosecondBoundaries(long ticks, string expected)
        {
            using var connection = CreateEventStore();
            InsertProcess(connection, "owner", 42, "owner", BaseTime.AddTicks(5000), BaseTime.AddTicks(9000));
            AssertStoredLifetime(connection, "owner", BaseTime.AddTicks(5000), BaseTime.AddTicks(9000));
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false);
            AssertDurableOwner(connection, resolver, 42, BaseTime.AddTicks(ticks), expected);
            AssertDurableOwner(connection, resolver, 43, BaseTime.AddTicks(ticks), null);
        }

        [Fact, Trait("Category", "pai-02")]
        public void DurableLookupsSelectNewestOverlappingOrOpenLifetime()
        {
            using var connection = CreateEventStore();
            InsertProcess(connection, "old", 42, "old", BaseTime, BaseTime.AddSeconds(2));
            InsertProcess(connection, "new", 42, "new", BaseTime.AddTicks(5000), null);
            InsertProcess(connection, "other-pid", 43, "other", BaseTime.AddTicks(6000), null);
            AssertStoredLifetime(connection, "new", BaseTime.AddTicks(5000), null);
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false);
            AssertDurableOwner(connection, resolver, 42, BaseTime.AddTicks(8000), "new");
            AssertDurableOwner(connection, resolver, 42, BaseTime.AddDays(1), "new");
            AssertDurableOwner(connection, resolver, 43, BaseTime.AddTicks(8000), "other-pid");
            // A stored, artificial hash proves this success returns before live fallback.
            Assert.Equal("new", resolver.GetPidHash(42, BaseTime.AddTicks(8000)));
        }

        [Fact, Trait("Category", "pai-02")]
        public void DurableLookupsNormalizeUtcLocalAndUnspecifiedInputs()
        {
            using var connection = CreateEventStore();
            DateTime utc = BaseTime.AddTicks(8000);
            DateTime local = utc.ToLocalTime();
            DateTime unspecified = DateTime.SpecifyKind(utc, DateTimeKind.Unspecified);
            DateTime interpretedUtc = unspecified.ToUniversalTime();
            InsertProcess(connection, "utc", 42, "utc", utc.AddTicks(-10), utc.AddTicks(10));
            InsertProcess(connection, "unspecified", 43, "unspecified", interpretedUtc.AddTicks(-10), interpretedUtc.AddTicks(10));
            AssertStoredLifetime(connection, "unspecified", interpretedUtc.AddTicks(-10), interpretedUtc.AddTicks(10));
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false);
            AssertDurableOwner(connection, resolver, 42, utc, "utc");
            AssertDurableOwner(connection, resolver, 42, local, "utc");
            AssertDurableOwner(connection, resolver, 43, unspecified, "unspecified");
            AssertDurableOwner(connection, resolver, 43, interpretedUtc, "unspecified");
        }

        [Fact, Trait("Category", "pai-02")]
        public void ClosedSubmillisecondIdentityAgreesAcrossColdAndWarmCache()
        {
            using var connection = CreateEventStore();
            DateTime created = BaseTime.AddTicks(5000), exited = BaseTime.AddTicks(9000);
            InsertProcess(connection, "closed", 42, "closed", created, exited);
            AssertStoredLifetime(connection, "closed", created, exited);
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: false);
            var cold = resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddTicks(8000));
            var warm = resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddTicks(8000));
            Assert.NotNull(cold); Assert.NotNull(warm);
            Assert.Equal("closed", cold.PidHash); Assert.Equal(cold.PidHash, warm.PidHash);
            Assert.Equal(created, cold.CreateTime); Assert.Equal(cold.CreateTime, warm.CreateTime);
            Assert.Equal(exited, cold.ExitTime); Assert.Equal(cold.ExitTime, warm.ExitTime);
            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out long evictions, out int entries);
            Assert.Equal(1, hits); Assert.Equal(1, misses); Assert.Equal(0, evictions); Assert.Equal(1, entries);
        }

        private static void AssertDurableOwner(DuckDBConnection connection, ProcessResolver resolver, int pid, DateTime time, string expected)
        {
            ProcessRecord record = resolver.ResolveProcessAtTime(pid, time);
            Assert.Equal(expected, record?.PidHash);
            Assert.Equal(expected, ProcessResolver.ResolveStoredPidHashAtTime(connection, pid, time));
            if (record != null)
            {
                Assert.Equal(pid, record.ProcessId);
                Assert.Equal(DateTimeKind.Utc, record.CreateTime.Kind);
                if (record.ExitTime.HasValue) Assert.Equal(DateTimeKind.Utc, record.ExitTime.Value.Kind);
            }
        }

        private static void AssertStoredLifetime(DuckDBConnection connection, string hash, DateTime created, DateTime? exited)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT create_time, exit_time FROM process WHERE pid_hash = $hash";
            command.Parameters.Add(new DuckDBParameter("hash", hash));
            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(created, reader.GetDateTime(0));
            if (exited.HasValue) Assert.Equal(exited.Value, reader.GetDateTime(1));
            else Assert.True(reader.IsDBNull(1));
            Assert.False(reader.Read());
        }
        private static object ExecuteResolveProcessAtTimeQuery(
            DuckDBConnection connection,
            int pid,
            DateTime eventTime)
        {
            using var command = connection.CreateCommand();
            command.CommandText = ProcessResolver.BuildResolveProcessAtTimeQuery();
            command.Parameters.Add(new DuckDBParameter("process_id", pid));
            command.Parameters.Add(new DuckDBParameter("event_time", eventTime.ToUniversalTime()));
            return command.ExecuteScalar();
        }

        private static void InsertProcess(
            DuckDBConnection connection,
            string pidHash,
            int pid,
            DateTime createTime)
        {
            using var insert = connection.CreateCommand();
            insert.CommandText = @"
                INSERT INTO process (pid_hash, process_id, create_time)
                VALUES ($pid_hash, $process_id, $create_time)";
            insert.Parameters.Add(new DuckDBParameter("pid_hash", pidHash));
            insert.Parameters.Add(new DuckDBParameter("process_id", pid));
            insert.Parameters.Add(new DuckDBParameter("create_time", createTime));
            insert.ExecuteNonQuery();
        }

        private static DuckDBConnection CreateProcessTable()
        {
            var connection = new DuckDBConnection("Data Source=:memory:");
            connection.Open();
            using var create = connection.CreateCommand();
            create.CommandText = @"
                CREATE TABLE process (
                    pid_hash VARCHAR PRIMARY KEY,
                    parent_pid_hash VARCHAR,
                    process_id INTEGER,
                    parent_process_id INTEGER);";
            create.ExecuteNonQuery();
            return connection;
        }

        private static DuckDBConnection CreateEventStore()
        {
            var connection = new DuckDBConnection("Data Source=:memory:");
            connection.Open();
            ProcessResolver.EnsureEventStoreTables(connection);
            return connection;
        }

        [Fact]
        public void ResolveProcessIdentityAtTime_PreservesSubsecondPidReuseAndCachesClosedRows()
        {
            using var connection = CreateProcessDatabase();
            InsertProcess(connection, "first", 42, "first-process", BaseTime.AddMilliseconds(100), BaseTime.AddMilliseconds(200));
            InsertProcess(connection, "second", 42, "second-process", BaseTime.AddMilliseconds(300), BaseTime.AddMilliseconds(400));
            var resolver = new ProcessResolver(connection, 16);

            Assert.Equal("first", resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddMilliseconds(150)).PidHash);
            Assert.Equal("second", resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddMilliseconds(350)).PidHash);
            Assert.Equal("first", resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddMilliseconds(150)).PidHash);
            Assert.Equal("second", resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddMilliseconds(350)).PidHash);

            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out _, out int entries);
            Assert.Equal(2, hits);
            Assert.Equal(2, misses);
            Assert.Equal(2, entries);
        }

        [Fact]
        public void RetentionDeletion_SeedsHistoricalIdentityBeforeDeletingRow()
        {
            using var connection = CreateProcessDatabase();
            DateTime now = DateTime.UtcNow;
            DateTime createTime = now.AddHours(-3);
            DateTime exitTime = now.AddHours(-2);
            InsertProcess(connection, "expired", 42, "expired-process", createTime, exitTime);
            var resolver = new ProcessResolver(connection, 16, enableMaintenance: true);

            ProcessRecord resolved = resolver.ResolveProcessIdentityAtTime(42, createTime.AddMinutes(30));

            using var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM process";
            Assert.Equal(0L, count.ExecuteScalar());
            Assert.Equal("expired", resolved.PidHash);
            Assert.Equal("expired-process", resolved.ProcessName);
        }

        [Fact]
        public void ResolveProcessIdentityAtTime_DoesNotCacheOpenEndedRows()
        {
            using var connection = CreateProcessDatabase();
            InsertProcess(connection, "open", 42, "open-process", BaseTime, null);
            var resolver = new ProcessResolver(connection, 16);

            Assert.Equal("open", resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddSeconds(1)).PidHash);
            Assert.Equal("open", resolver.ResolveProcessIdentityAtTime(42, BaseTime.AddSeconds(2)).PidHash);

            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out _, out int entries);
            Assert.Equal(0, hits);
            Assert.Equal(2, misses);
            Assert.Equal(0, entries);
        }

        [Fact]
        public void ResolveProcessIdentityAtTime_UnresolvedRequestCountsOneCacheMiss()
        {
            using var connection = CreateProcessDatabase();
            var resolver = new ProcessResolver(connection, 16);

            Assert.Null(resolver.ResolveProcessIdentityAtTime(42, BaseTime));

            resolver.TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out _, out int entries);
            Assert.Equal(0, hits);
            Assert.Equal(1, misses);
            Assert.Equal(0, entries);
        }

        [Fact]
        public void ReconcileStartupOpenRows_PreservesSubsecondExitTime()
        {
            using var connection = CreateProcessDatabase();
            InsertProcess(connection, "stale", 42, "stale-process", BaseTime, null);
            DateTime exitTime = BaseTime.AddSeconds(1).AddMilliseconds(375);

            ProcessResolver.ReconcileStartupOpenRows(connection, Array.Empty<string>(), exitTime);

            using var select = connection.CreateCommand();
            select.CommandText = "SELECT exit_time FROM process WHERE pid_hash = 'stale'";
            Assert.Equal(exitTime, (DateTime)select.ExecuteScalar());
        }

        private static DuckDBConnection CreateProcessDatabase()
        {
            var connection = new DuckDBConnection("Data Source=:memory:");
            connection.Open();
            ProcessResolver.EnsureEventStoreTables(connection);
            return connection;
        }

        private static void InsertProcess(
            DuckDBConnection connection,
            string pidHash,
            int pid,
            string processName,
            DateTime createTime,
            DateTime? exitTime)
        {
            using var insert = connection.CreateCommand();
            insert.CommandText = @"
                INSERT INTO process VALUES (
                    $pid_hash, '', $pid, 1, $process_name, '', '',
                    $create_time, $exit_time, 0, 'real_time', '', '', '')";
            insert.Parameters.Add(new DuckDBParameter("pid_hash", pidHash));
            insert.Parameters.Add(new DuckDBParameter("pid", pid));
            insert.Parameters.Add(new DuckDBParameter("process_name", processName));
            insert.Parameters.Add(new DuckDBParameter("create_time", createTime));
            insert.Parameters.Add(new DuckDBParameter("exit_time", exitTime.HasValue ? exitTime.Value : DBNull.Value));
            insert.ExecuteNonQuery();
        }
    }
}
