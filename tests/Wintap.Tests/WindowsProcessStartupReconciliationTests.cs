using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading.Tasks;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using ProcessHash = gov.llnl.wintap.core.shared.helpers.ProcessHash;
using gov.llnl.wintap.platform.windows.collect.etw;
using gov.llnl.wintap.platform.windows.collect.etw.helpers;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    [Trait("Category", "wpc-10")]
    public partial class WindowsProcessStartupReconciliationTests
    {
        private static readonly DateTime Boot = new(2026, 11, 1, 8, 0, 0, DateTimeKind.Utc);
        private static readonly DateTime Restart = Boot.AddHours(1);
        private static string Hash(int pid, DateTime birth) => new ProcessHash().GenPidHash(pid, birth.ToFileTimeUtc());
        private static string UnknownHash => new ProcessHash().GenPidHash(-1, 0);

        [Fact]
        public void BootstrapRegistersCanonicalSeedsBeforeReplayAndDoesNotEnumerateUntilDelta()
        {
            var fixture = new Fixture();
            Assert.False(fixture.Sensor.InitializeSnapshotDelta());
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.Equal(0, fixture.EnumerationCalls);
            Assert.Equal(1, fixture.ClearCalls);
            Assert.Equal("clear", fixture.Operations[0]);
            Assert.Equal(new[] { 4, 0, -1 }, fixture.Emitted.Select(message => message.PID));
            Assert.Equal(3, fixture.History.Count);
            foreach (var seed in fixture.Emitted)
            {
                Assert.Equal(Hash(seed.PID, Boot), seed.PidHash);
                Assert.Equal(Boot.ToFileTimeUtc(), seed.EventTime);
                Assert.Equal(Hash(4, Boot), seed.Process.ParentPidHash);
                Assert.Equal(WintapMessage.ActivityTypeEnum.Refresh, seed.ActivityType);
            }
            Assert.Null(fixture.Replay(4, 0, Boot, "System"));
            Assert.Null(fixture.Replay(0, 0, Boot, "idle"));
            Assert.Null(fixture.Replay(-1, 0, Boot, "unknown"));
            Assert.Equal(0, fixture.Sensor.BootReplayCount);
            var smss = fixture.Replay(100, 4, Boot.AddSeconds(1), "smss.exe");
            Assert.Equal(Hash(4, Boot), smss.Process.ParentPidHash);
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(1, fixture.EnumerationCalls);
            Assert.Equal(4, fixture.History.Count);
        }

        [Fact]
        public void ReplayThenDeltaPreservesExitedSessionAndServiceAncestorChains()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var smss = fixture.Replay(100, 4, Boot.AddSeconds(1), "smss.exe");
            var session = fixture.Replay(110, 100, Boot.AddSeconds(2), "smss.exe");
            var winlogon = fixture.Replay(120, 110, Boot.AddSeconds(3), "winlogon.exe");
            var userinit = fixture.Replay(130, 120, Boot.AddSeconds(4), "userinit.exe");
            var explorer = fixture.Replay(140, 130, Boot.AddSeconds(5), "explorer.exe");
            var wininit = fixture.Replay(200, 100, Boot.AddSeconds(2), "wininit.exe");
            var services = fixture.Replay(210, 200, Boot.AddSeconds(3), "services.exe");
            var service = fixture.Replay(220, 210, Boot.AddSeconds(4), "service-host.exe");
            fixture.Exit(session, Boot.AddSeconds(10));
            fixture.Exit(userinit, Boot.AddSeconds(10));
            fixture.Exit(wininit, Boot.AddSeconds(10));
            fixture.Exit(service, Boot.AddSeconds(30));
            fixture.Snapshot.AddRange(new[]
            {
                Snapshot(300, 220, Boot.AddSeconds(20), "wintap.exe"),
                Snapshot(140, 130, Boot.AddSeconds(5), "snapshot-explorer.exe"),
                Snapshot(310, 140, Boot.AddSeconds(20), "desktop-child.exe")
            });

            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(1, fixture.Sensor.DedupSuppressedCount);
            Assert.Single(fixture.Emitted, message => message.PID == 140);
            Assert.Equal(service.PidHash, fixture.Record(300).ParentPidHash);
            Assert.Equal(explorer.PidHash, fixture.Record(310).ParentPidHash);
            Assert.Equal(smss.PidHash, fixture.Record(110).ParentPidHash);
            Assert.Equal(session.PidHash, fixture.Record(120).ParentPidHash);
            Assert.Equal(userinit.PidHash, fixture.Record(140).ParentPidHash);
            Assert.Equal(wininit.PidHash, fixture.Record(210).ParentPidHash);
            Assert.Equal(services.PidHash, fixture.Record(220).ParentPidHash);
            Assert.Equal(winlogon.PidHash, fixture.Record(130).ParentPidHash);
            AssertLineage(fixture, 300, 5);
            AssertLineage(fixture, 310, 6);
            Assert.All(fixture.Emitted, message =>
                Assert.Equal(Hash(message.PID, DateTime.FromFileTimeUtc(message.EventTime)), message.PidHash));
            Assert.Equal(1, fixture.ClearCalls);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public void ExactOrUniqueEarlierSkewOverlapUsesHistoricalParentHashWithoutRefreshingMetadata(int skewSeconds)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(1);
            var original = Historical(400, 4, birth, "replay-parent.exe", Hash(4, Boot));
            original.CommandLine = "payload --authoritative";
            original.UserName = "retained-user";
            original.MD5Hash = "retained-md5";
            original.SHA2Hash = "retained-sha2";
            original.Source = ProcessRecord.ProcessSourceEnum.real_time;
            // Database timestamps are UTC despite their Unspecified kind.
            original.CreateTime = DateTime.SpecifyKind(birth, DateTimeKind.Unspecified);
            fixture.History.Add(original);
            fixture.Snapshot.Add(Snapshot(400, 999, birth.AddSeconds(skewSeconds), "poorer-snapshot.exe"));
            fixture.Snapshot.Add(Snapshot(401, 400, birth.AddSeconds(3), "child.exe"));

            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());

            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 400);
            Assert.Same(original, fixture.Record(400));
            Assert.Equal(original.PidHash, fixture.Record(401).ParentPidHash);
            Assert.Contains(original.PidHash, fixture.ReconciledHashes);
            if (skewSeconds != 0) Assert.DoesNotContain(Hash(400, birth.AddSeconds(skewSeconds)), fixture.ReconciledHashes);
            Assert.Equal("replay-parent.exe", original.ProcessName);
            Assert.Equal(@"C:\fixture\replay-parent.exe", original.ProcessPath);
            Assert.Equal("payload --authoritative", original.CommandLine);
            Assert.Equal("retained-user", original.UserName);
            Assert.Equal("retained-md5", original.MD5Hash);
            Assert.Equal("retained-sha2", original.SHA2Hash);
            Assert.Equal(Hash(4, Boot), original.ParentPidHash);
            Assert.Equal(ProcessRecord.ProcessSourceEnum.real_time, original.Source);
            Assert.Equal(1, fixture.Sensor.DedupSuppressedCount);
            Assert.Equal(0, fixture.ClearCalls);
        }

        [Fact]
        public void ExactIdentityAlwaysWinsOverMultipleSkewCandidatesEvenWithRecordedExit()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(2);
            fixture.History.Add(Historical(410, 4, birth.AddSeconds(-2), "old.exe"));
            fixture.History.Add(Historical(410, 4, birth.AddSeconds(-1), "near.exe"));
            var exact = Historical(410, 4, birth, "exact.exe");
            exact.ExitTime = birth.AddTicks(-1);
            fixture.History.Add(exact);
            fixture.Snapshot.Add(Snapshot(410, 4, birth, "snapshot.exe"));
            fixture.Snapshot.Add(Snapshot(411, 410, birth.AddSeconds(1), "child.exe"));

            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 410);
            // Exact snapshot coverage does not make an exited row a compatible
            // parent at a later child birth; the latest covering lifetime wins.
            Assert.Equal(Hash(410, birth.AddSeconds(-1)), fixture.Record(411).ParentPidHash);
            Assert.Contains(exact.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(Hash(410, birth.AddSeconds(-1)), fixture.ReconciledHashes);
            Assert.DoesNotContain(fixture.Logs, text => text.Contains("overlap ambiguous"));
        }

        [Fact]
        public void AmbiguousSkewOverlapEmitsSnapshotIdentityAndUsesItForChildrenAndReconcile()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(3);
            var first = Historical(420, 4, birth.AddSeconds(-2), "first.exe");
            var second = Historical(420, 4, birth.AddSeconds(-1), "second.exe");
            fixture.History.AddRange(new[] { first, second });
            fixture.Snapshot.Add(Snapshot(420, 4, birth, "snapshot.exe"));
            fixture.Snapshot.Add(Snapshot(421, 420, birth.AddSeconds(1), "child.exe"));

            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            var refresh = Assert.Single(fixture.Emitted, message => message.PID == 420);
            Assert.Equal(Hash(420, birth), refresh.PidHash);
            Assert.Equal(refresh.PidHash, fixture.Record(421).ParentPidHash);
            Assert.Contains(refresh.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(first.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(second.PidHash, fixture.ReconciledHashes);
            Assert.Contains(fixture.Logs, text => text.Contains("overlap ambiguous") && text.Contains("pid=420"));
            Assert.Equal(0, fixture.Sensor.DedupSuppressedCount);
        }

        [Theory]
        [InlineData("future")]
        [InlineData("older-than-tolerance")]
        [InlineData("exited-before-snapshot")]
        [InlineData("wrong-pid")]
        [InlineData("missing-hash")]
        public void IncompatibleOverlapEvidenceDoesNotSuppressSnapshot(string scenario)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(4);
            DateTime historyBirth = scenario == "future" ? birth.AddTicks(1) :
                scenario == "older-than-tolerance" ? birth.AddSeconds(-2).AddTicks(-1) : birth.AddSeconds(-1);
            var prior = Historical(scenario == "wrong-pid" ? 999 : 430, 4, historyBirth, "prior.exe");
            if (scenario == "exited-before-snapshot") prior.ExitTime = birth.AddTicks(-1);
            if (scenario == "missing-hash") prior.PidHash = " ";
            fixture.History.Add(prior);
            fixture.Snapshot.Add(Snapshot(430, 4, birth, "new-lifetime.exe"));

            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.Equal(Hash(430, birth), Assert.Single(fixture.Emitted, message => message.PID == 430).PidHash);
            Assert.Contains(Hash(430, birth), fixture.ReconciledHashes);
            Assert.Equal(0, fixture.Sensor.DedupSuppressedCount);
        }

        [Fact]
        public void UniqueSkewCandidateWithExitExactlyAtSnapshotStillCoversIdentity()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(5);
            var prior = Historical(440, 4, birth.AddSeconds(-2), "boundary.exe");
            prior.ExitTime = birth;
            fixture.History.Add(prior);
            fixture.Snapshot.Add(Snapshot(440, 4, birth, "snapshot.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 440);
            Assert.Contains(prior.PidHash, fixture.ReconciledHashes);
        }

        [Theory]
        [InlineData("Registry")]
        [InlineData("Secure System")]
        [InlineData("early-system-child.exe")]
        public void EarlyRootChildrenUseSystemSeedEvenWhenTheirBirthPrecedesAnchor(string image)
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(500, 4, Boot.AddSeconds(-1), image);
            fixture.Snapshot.Add(Snapshot(501, 4, Boot.AddSeconds(-2), image));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(Hash(4, Boot), replay.Process.ParentPidHash);
            Assert.Equal(Hash(4, Boot), fixture.Record(501).ParentPidHash);
            Assert.Equal(Hash(500, Boot.AddSeconds(-1)), replay.PidHash);
            AssertLineage(fixture, 500, 1);
            AssertLineage(fixture, 501, 1);
        }

        [Fact]
        public void NonRootSelfParentsRemainUnknownInReplayAndSnapshot()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            fixture.History.Add(Historical(510, 4, Boot.AddSeconds(1), "older-same-pid.exe"));
            var replay = fixture.Replay(510, 510, Boot.AddSeconds(2), "self.exe");
            fixture.Snapshot.Add(Snapshot(511, 511, Boot.AddSeconds(3), "snapshot-self.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(UnknownHash, replay.Process.ParentPidHash);
            Assert.Equal(UnknownHash, fixture.Record(511).ParentPidHash);
        }

        [Theory]
        [InlineData("future")]
        [InlineData("same-birth")]
        [InlineData("exited")]
        [InlineData("wrong-pid")]
        public void ReplayRejectsResolverParentThatDoesNotCoverChildBirth(string scenario)
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            DateTime childBirth = Boot.AddMinutes(6);
            var parent = Historical(scenario == "wrong-pid" ? 999 : 520, 4,
                scenario == "future" ? childBirth.AddTicks(1) : scenario == "same-birth" ? childBirth : childBirth.AddSeconds(-1), "parent.exe");
            if (scenario == "exited") parent.ExitTime = childBirth.AddTicks(-1);
            fixture.ResolveOverride = (_, _) => parent;
            var replay = fixture.Replay(521, 520, childBirth, "child.exe");
            Assert.Equal(UnknownHash, replay.Process.ParentPidHash);
            Assert.Contains(fixture.Logs, text => text.Contains("missing compatible parent evidence"));
        }

        [Fact]
        public void SnapshotParentSelectionRejectsReusedFuturePidAndExpiredLifetime()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime childBirth = Boot.AddMinutes(7);
            var expired = Historical(530, 4, childBirth.AddSeconds(-2), "expired-parent.exe");
            expired.ExitTime = childBirth.AddTicks(-1);
            fixture.History.Add(expired);
            fixture.History.Add(Historical(530, 4, childBirth.AddTicks(1), "future-parent.exe"));
            fixture.Snapshot.Add(Snapshot(530, 4, childBirth.AddSeconds(1), "current-reused-parent.exe"));
            fixture.Snapshot.Add(Snapshot(531, 530, childBirth, "older-child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.Equal(UnknownHash, fixture.Record(531).ParentPidHash);
        }

        [Fact]
        public void ReplayDeduplicatesExactHistoryIdentityButKeepsDistinctBirthsLessThanTwoSecondsApart()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime firstBirth = Boot.AddMinutes(8);
            var prior = Historical(540, 4, firstBirth, "persisted.exe", Hash(4, Boot));
            prior.ExitTime = firstBirth.AddTicks(1);
            fixture.History.Add(prior);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            int historyCalls = fixture.HistoryCalls;
            fixture.ResolveOverride = (_, _) => throw new InvalidOperationException("must not resolve current child PID");
            Assert.Null(fixture.Replay(540, 4, firstBirth, "duplicate-payload.exe"));
            var second = fixture.Replay(540, 4, firstBirth.AddTicks(2), "second.exe");
            var third = fixture.Replay(540, 4, firstBirth.AddSeconds(1), "third.exe");
            Assert.NotEqual(prior.PidHash, second.PidHash);
            Assert.NotEqual(second.PidHash, third.PidHash);
            Assert.Null(fixture.Replay(540, 4, firstBirth.AddTicks(2), "duplicate-second.exe"));
            Assert.Equal(2, fixture.Sensor.BootReplayCount);
            Assert.Equal(2, fixture.Sensor.DedupSuppressedCount);
            Assert.Equal(historyCalls, fixture.HistoryCalls);
            Assert.Equal(3, fixture.History.Count(record => record.ProcessId == 540));
        }

        [Fact]
        public void ReplayPayloadDoesNotUseCurrentPidTokenPebOrImageEnrichment()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var payload = fixture.Replay(550, 4, Boot.AddMinutes(9), @"\Device\Fixture\MixedCase.exe", "");
            var missing = fixture.Replay(551, 4, Boot.AddMinutes(9).AddTicks(1), null, null);
            Assert.Equal(@"\Device\Fixture\MixedCase.exe", payload.Process.Path);
            Assert.Equal("", payload.Process.CommandLine);
            Assert.Equal("", payload.Process.User);
            Assert.Equal("", missing.Process.Path);
            Assert.Equal("", missing.Process.CommandLine);
            Assert.Equal("", missing.Process.User);
            Assert.Equal(0, fixture.CurrentPidEnrichmentCalls);
            Assert.Equal(2, fixture.Sensor.GetQaCounterSnapshot().CmdlineEmpty);
            Assert.Equal(0, fixture.Sensor.GetQaCounterSnapshot().CmdlinePebRecovered);
        }

        [Fact]
        public void RegistryNameDoesNotOverrideReportedNonSystemParent()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var parent = fixture.Replay(552, 4, Boot.AddSeconds(1), "reported-parent.exe");
            var registry = fixture.Replay(553, 552, Boot.AddSeconds(2), "Registry");
            fixture.Snapshot.Add(Snapshot(554, 552, Boot.AddSeconds(3), "Registry"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(parent.PidHash, registry.Process.ParentPidHash);
            Assert.Equal(parent.PidHash, fixture.Record(554).ParentPidHash);
            Assert.NotEqual(Hash(4, Boot), registry.Process.ParentPidHash);
        }

        [Fact]
        public void ReplayExtractedSidMapsPayloadAccountWithoutCurrentPidLookups()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var message = fixture.Sensor.HandleReplayedStart(555, 4, Boot.AddSeconds(1), "payload.exe", "payload command",
                new SecurityIdentifier("S-1-5-18"), SidParseStatus.Extracted);
            Assert.Equal("payload-account", message.Process.User);
            Assert.Equal(0, fixture.CurrentPidEnrichmentCalls);
            Assert.Equal(1, fixture.Sensor.GetQaCounterSnapshot().SidExtracted);
            Assert.Equal(0, fixture.Sensor.GetQaCounterSnapshot().SidFallback);
        }

        [Fact]
        public void BootReplaySubscriptionUsesActualStartsNeverDcStartBirths()
        {
            string directory = AppContext.BaseDirectory;
            while (directory != null && !File.Exists(Path.Combine(directory, "AGENTS.md")))
                directory = Directory.GetParent(directory)?.FullName;
            Assert.NotNull(directory);
            string source = File.ReadAllText(Path.Combine(directory, "wintap", "platform", "windows", "sensor", "etw", "WindowsProcessSensor.cs"));
            int start = source.IndexOf("internal bool ReplayBootTrace(", StringComparison.Ordinal);
            int end = source.IndexOf("private void HandleReplayedProcessTraceData(", start, StringComparison.Ordinal);
            Assert.True(start >= 0 && end > start);
            string replayMethod = source.Substring(start, end - start);
            Assert.Contains("parser.ProcessStart +=", replayMethod);
            Assert.DoesNotContain("parser.ProcessDCStart +=", replayMethod);
            Assert.DoesNotContain("parser.ProcessDCStop +=", replayMethod);
        }

        [Fact]
        public void SameBootReconciliationRunsAfterDeltaAndRetainsOnlyLiveMatchedHashes()
        {
            var fixture = new Fixture(sameBoot: true);
            var stale = Historical(560, 4, Boot.AddMinutes(1), "stale.exe");
            fixture.History.Add(stale);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(561, 4, Boot.AddMinutes(2), "covered.exe");
            fixture.Snapshot.Add(Snapshot(561, 4, Boot.AddMinutes(2).AddMilliseconds(1), "covered.exe"));
            fixture.Snapshot.Add(Snapshot(562, 561, Boot.AddMinutes(3), "new.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(0, fixture.ClearCalls);
            Assert.Equal(1, fixture.ReconcileCalls);
            Assert.Equal(Restart, stale.ExitTime);
            Assert.Null(fixture.History.Single(record => record.PidHash == replay.PidHash).ExitTime);
            Assert.Equal(new[] { Hash(-1, Boot), Hash(0, Boot), Hash(4, Boot), replay.PidHash, Hash(562, Boot.AddMinutes(3)) }.OrderBy(hash => hash),
                fixture.ReconciledHashes.OrderBy(hash => hash));
            Assert.Equal((Boot.AddMinutes(50), Restart, "prior-session", "restart_same_boot"), Assert.Single(fixture.Gaps));
            Assert.True(fixture.Operations.IndexOf("emit:562") < fixture.Operations.IndexOf("reconcile"));
        }

        [Theory]
        [InlineData("enumeration")]
        [InlineData("history")]
        [InlineData("emission")]
        public void FailedDeltaRetainsPartialReplayAndDoesNotClearReconcileOrRetry(string failure)
        {
            var fixture = new Fixture(sameBoot: true);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var partial = fixture.Replay(570, 4, Boot.AddMinutes(10), "partial-replay.exe");
            fixture.Snapshot.Add(Snapshot(571, 570, Boot.AddMinutes(11), "first-delta.exe"));
            fixture.Snapshot.Add(Snapshot(572, 570, Boot.AddMinutes(12), "second-delta.exe"));
            fixture.FailEnumeration = failure == "enumeration";
            fixture.FailHistory = failure == "history";
            fixture.FailEmit = message => failure == "emission" && message.PID == 572;
            Assert.False(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(0, fixture.ClearCalls);
            Assert.Equal(0, fixture.ReconcileCalls);
            Assert.Empty(fixture.Gaps);
            Assert.Contains(fixture.History, record => record.PidHash == partial.PidHash);
            var continued = fixture.Replay(573, 570, Boot.AddMinutes(13), "continued-replay.exe");
            Assert.Equal(partial.PidHash, continued.Process.ParentPidHash);
            Assert.Null(fixture.Replay(570, 4, Boot.AddMinutes(10), "duplicate.exe"));
            if (failure == "emission") Assert.Single(fixture.Emitted, message => message.PID == 571);
            fixture.FailEnumeration = fixture.FailHistory = false;
            fixture.FailEmit = null;
            int enumerationCalls = fixture.EnumerationCalls;
            int historyCalls = fixture.HistoryCalls;
            int emittedCount = fixture.Emitted.Count;
            Assert.False(fixture.Sensor.InitializeSnapshotDelta());
            Assert.False(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.Equal(enumerationCalls, fixture.EnumerationCalls);
            Assert.Equal(historyCalls, fixture.HistoryCalls);
            Assert.Equal(emittedCount, fixture.Emitted.Count);
            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 572);
            Assert.Equal(0, fixture.ClearCalls);
            Assert.Equal(0, fixture.ReconcileCalls);
            Assert.Empty(fixture.Gaps);
            Assert.Contains(fixture.Logs, text => text.Contains("bootstrap/replay history retained"));
        }

        [Theory]
        [InlineData("clear")]
        [InlineData("seed")]
        [InlineData("history")]
        [InlineData("boot-anchor")]
        public void BootstrapFailureReturnsFalseAndWrapperNeverRunsDelta(string failure)
        {
            var fixture = new Fixture(probeAvailable: failure != "boot-anchor");
            fixture.FailClear = failure == "clear";
            fixture.FailEmit = message => failure == "seed" && message.PID == 0;
            fixture.FailHistory = failure == "history";
            fixture.FailBootAnchor = failure == "boot-anchor";
            Assert.False(fixture.Sensor.InitializeStartupBootstrap());
            Assert.False(fixture.Sensor.InitializeStartupBootstrap());
            Assert.False(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.False(fixture.Sensor.InitializeSnapshotDelta());
            Assert.False(fixture.Sensor.ReplayBootTrace("fixture-not-an-etl.etl"));
            Assert.Equal(0, fixture.EnumerationCalls);
            Assert.Equal(0, fixture.ReconcileCalls);
            Assert.Empty(fixture.Gaps);
            Assert.Equal(1, fixture.ClearCalls);
            Assert.Contains(fixture.Logs, text => text.Contains("startup bootstrap failed; replay skipped"));
            if (failure == "seed") Assert.Single(fixture.History);
        }

        [Fact]
        public void MissingSystemProbeDegradesToBootAnchorWithoutAbortingBootstrap()
        {
            var fixture = new Fixture(probeAvailable: false);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.Equal(3, fixture.History.Count);
            Assert.Equal(Hash(4, Boot), fixture.Record(4).PidHash);
            Assert.Contains(fixture.Logs, text => text.Contains("System seed falling back to WMI boot time"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(1, fixture.ClearCalls);
            Assert.Equal(0, fixture.ReconcileCalls);
        }

        [Fact]
        public void InterruptedReplayKeepsRegisteredStartsAndSnapshotDeltaCompletesMissingRows()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var parent = fixture.Replay(580, 4, Boot.AddMinutes(14), "registered-parent.exe");
            fixture.FailEmit = message => message.PID == 581;
            Assert.Throws<InvalidOperationException>(() => fixture.Replay(581, 580, Boot.AddMinutes(15), "interrupted-child.exe"));
            Assert.Equal(1, fixture.Sensor.BootReplayCount);
            Assert.DoesNotContain(fixture.History, record => record.ProcessId == 581);
            fixture.FailEmit = null;
            fixture.Snapshot.Add(Snapshot(580, 4, Boot.AddMinutes(14), "covered-parent.exe"));
            fixture.Snapshot.Add(Snapshot(581, 580, Boot.AddMinutes(15), "snapshot-child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(parent.PidHash, fixture.Record(581).ParentPidHash);
            Assert.Single(fixture.Emitted, message => message.PID == 580);
            Assert.Single(fixture.Emitted, message => message.PID == 581);
            Assert.Equal(1, fixture.ClearCalls);
            Assert.Equal(0, fixture.ReconcileCalls);
        }

        [Fact]
        public async Task NormalProcessSerializerToTemporaryParquetPreservesReplayBirthsAndDeltaLineage()
        {
            var fixture = new Fixture();
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var smss = fixture.Replay(600, 4, Boot.AddSeconds(1), "smss.exe", "smss payload");
            var parent = fixture.Replay(610, 600, Boot.AddSeconds(2), "parent.exe", "parent payload --exact");
            var reused = fixture.Replay(610, 600, Boot.AddSeconds(3), "reused.exe", "second birth");
            Assert.Null(fixture.Replay(610, 600, Boot.AddSeconds(3), "duplicate.exe"));
            fixture.Snapshot.Add(Snapshot(610, 999, Boot.AddSeconds(3), "poorer-snapshot.exe"));
            fixture.Snapshot.Add(Snapshot(620, 610, Boot.AddSeconds(4), "child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());

            // Bypass production constructor startup (Esper, host inventory and timers),
            // but invoke the actual process serializer handler and Save queue.
            var serializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var queue = new ConcurrentQueue<ExpandoObject>();
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(typeof(ProcessSerializer), serializer, "host", new HostId { Hostname = "fixture-host" });
            var handler = typeof(ProcessSerializer).GetMethod("handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(handler);
            var messages = fixture.Emitted.ToArray();
            foreach (var message in messages)
            {
                message.AgentId = "fixture-agent";
                // Synthetic seed SYSTEM accounts are irrelevant to lineage and
                // must not cause the serializer to consult host account inventory.
                message.Process.User = "";
                handler.Invoke(serializer, new object[] { message });
            }
            Assert.Equal(7, queue.Count);
            var rows = queue.Select(row => (IDictionary<string, object>)row).ToList();
            var schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(schemaMethod);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { rows[0] });
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp", "opencode");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "wpc-10-" + Guid.NewGuid().ToString("N") + ".parquet");
            try
            {
                using (var output = File.Create(path))
                    await ParquetSerializer.SerializeUntypedAsync(rows, schema, output);
                using var input = File.OpenRead(path);
                var recovered = await ParquetSerializer.DeserializeUntypedAsync(input);
                Assert.Equal(7, recovered.Data.Count);
                for (int i = 0; i < messages.Length; i++)
                {
                    var row = recovered.Data[i];
                    var message = messages[i];
                    Assert.Equal(message.PidHash, row["PidHash"]);
                    Assert.Equal(message.Process.ParentPidHash, row["ParentPidHash"]);
                    Assert.Equal(message.EventTime, Convert.ToInt64(row["StartTime"]));
                    Assert.Equal(message.EventTime, Convert.ToInt64(row["EventTime"]));
                    Assert.Equal(message.Process.Path, row["ProcessPath"]);
                    Assert.Equal(message.Process.CommandLine, row["CommandLine"]);
                    Assert.Equal(message.ActivityType.ToString(), row["ActivityType"]);
                    Assert.Equal("fixture-agent", row["AgentId"]);
                    Assert.Equal("FIXTURE-HOST", row["Hostname"]);
                }
                Assert.All(recovered.Data.GroupBy(row => (string)row["PidHash"]), group => Assert.Single(group));
                var byHash = recovered.Data.ToDictionary(row => (string)row["PidHash"]);
                var root = byHash[Hash(4, Boot)];
                Assert.Equal(4, Convert.ToInt32(root["PID"]));
                Assert.Equal("ntoskrnl.exe", root["ProcessName"]);
                foreach (var row in recovered.Data.Where(row => Convert.ToInt32(row["PID"]) > 4))
                {
                    var visited = new HashSet<string>();
                    var current = row;
                    while (Convert.ToInt32(current["PID"]) != 4)
                    {
                        Assert.True(visited.Add((string)current["PidHash"]), "Recovered lineage must not cycle");
                        Assert.True(byHash.TryGetValue((string)current["ParentPidHash"], out current), "Recovered parent row missing");
                    }
                    Assert.Same(root, current);
                }
                Assert.Equal(smss.PidHash, byHash[parent.PidHash]["ParentPidHash"]);
                Assert.Equal(reused.PidHash, byHash[Hash(620, Boot.AddSeconds(4))]["ParentPidHash"]);
                Assert.NotEqual(parent.PidHash, reused.PidHash);
                Assert.Equal("Refresh", byHash[Hash(620, Boot.AddSeconds(4))]["ActivityType"]);
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }

        private static void SetField(Type type, object target, string name, object value)
        {
            var field = type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(field);
            field.SetValue(target, value);
        }

        private static void AssertLineage(Fixture fixture, int pid, int expectedHops)
        {
            Assert.True(WindowsProcessSensor.ValidateProcessLineage(fixture.History, fixture.Record(pid).PidHash,
                new ProcessHash().GenPidHash, out int hops, out string reason), reason);
            Assert.Equal(expectedHops, hops);
        }

        private static SnapshotProcessInfo Snapshot(int pid, int parent, DateTime birth, string name) => new()
        {
            Pid = pid, ParentPid = parent, CreateTimeUtc = birth, Name = name,
            Path = @"C:\fixture\" + name, CommandLine = name + " --snapshot", User = ""
        };

        private static ProcessRecord Historical(int pid, int parent, DateTime birth, string name, string parentHash = null) => new()
        {
            ProcessId = pid, ParentProcessId = parent, CreateTime = birth, PidHash = Hash(pid, birth),
            ParentPidHash = parentHash ?? UnknownHash, ProcessName = name, ProcessPath = @"C:\fixture\" + name,
            CommandLine = name, UserName = "", Source = ProcessRecord.ProcessSourceEnum.real_time
        };

        private sealed class Fixture
        {
            internal readonly List<ProcessRecord> History = new();
            internal readonly List<WintapMessage> Emitted = new();
            internal readonly List<SnapshotProcessInfo> Snapshot = new();
            internal readonly List<string> Operations = new(), Logs = new();
            internal readonly List<(DateTime Start, DateTime End, string Session, string Reason)> Gaps = new();
            internal readonly WindowsProcessSensor Sensor;
            internal IReadOnlyCollection<string> ReconciledHashes = Array.Empty<string>();
            internal int ClearCalls, EnumerationCalls, HistoryCalls, ReconcileCalls, CurrentPidEnrichmentCalls;
            internal bool FailClear, FailHistory, FailEnumeration, FailBootAnchor;
            internal Func<WintapMessage, bool> FailEmit;
            internal Func<int, DateTime, ProcessRecord> ResolveOverride;

            internal Fixture(bool sameBoot = false, bool probeAvailable = true)
            {
                Sensor = new WindowsProcessSensor(
                    resolveProcessAtTime: Resolve,
                    emit: Register,
                    utcNow: () => Restart,
                    enumerateSnapshot: () =>
                    {
                        EnumerationCalls++;
                        Operations.Add("snapshot");
                        if (FailEnumeration) throw new InvalidOperationException("fixture enumeration failure");
                        return Snapshot.ToArray();
                    },
                    clearProcessDb: () =>
                    {
                        ClearCalls++;
                        Operations.Add("clear");
                        if (FailClear) throw new InvalidOperationException("fixture clear failure");
                        History.Clear();
                    },
                    machineBootTimeUtc: () => FailBootAnchor ? throw new InvalidOperationException("fixture anchor failure") : Boot,
                    probeSystemStartFileTimeUtc: () => probeAvailable ? Boot.ToFileTimeUtc() : null,
                    isProcessRowOpen: hash => sameBoot && hash == Hash(4, Boot),
                    bootSessionRecoveryEnabled: true,
                    readHeartbeat: (out DateTime time, out string session) =>
                    { time = Boot.AddMinutes(50); session = "prior-session"; return true; },
                    reconcileStartupOpenRows: (hashes, time) =>
                    {
                        ReconcileCalls++;
                        Operations.Add("reconcile");
                        ReconciledHashes = hashes.ToArray();
                        var stale = History.Where(record => !record.ExitTime.HasValue && !hashes.Contains(record.PidHash)).ToArray();
                        foreach (var record in stale) record.ExitTime = time;
                        return stale.Length;
                    },
                    writeCollectionGap: (start, end, session, reason) => Gaps.Add((start, end, session, reason)),
                    updateHeartbeat: () => { },
                    log: (text, _) => Logs.Add(text),
                    lookupAccountSid: _ => "payload-account",
                    lookupTokenUserByPid: _ => CurrentPidLookup(),
                    lookupPebCommandLineByPid: _ => CurrentPidLookup(),
                    lookupFullProcessImagePathByPid: _ => CurrentPidLookup(),
                    translateDevicePath: path => path,
                    getProcessHistory: () =>
                    {
                        HistoryCalls++;
                        if (FailHistory) throw new InvalidOperationException("fixture history failure");
                        return History.ToArray();
                    },
                    repairParentLinkage: (_, _, _) => throw new InvalidOperationException("unexpected parent repair"),
                    enableQaCounterTimer: false);
            }

            private string CurrentPidLookup()
            {
                CurrentPidEnrichmentCalls++;
                throw new InvalidOperationException("replay must not enrich from current PID");
            }

            private ProcessRecord Resolve(int pid, DateTime time)
            {
                if (ResolveOverride != null) return ResolveOverride(pid, time);
                return History.Where(record => record.ProcessId == pid && record.CreateTime <= time &&
                    (!record.ExitTime.HasValue || record.ExitTime >= time)).OrderByDescending(record => record.CreateTime).FirstOrDefault();
            }

            private void Register(WintapMessage message)
            {
                if (FailEmit?.Invoke(message) == true) throw new InvalidOperationException("fixture emit failure");
                Operations.Add("emit:" + message.PID);
                Emitted.Add(message);
                if (History.Any(record => record.PidHash == message.PidHash)) return;
                History.Add(new ProcessRecord
                {
                    ProcessId = message.PID, ParentProcessId = message.Process.ParentPID,
                    PidHash = message.PidHash, ParentPidHash = message.Process.ParentPidHash,
                    ProcessName = message.Process.Name, ProcessPath = message.Process.Path,
                    CommandLine = message.Process.CommandLine, UserName = message.Process.User,
                    CreateTime = DateTime.FromFileTimeUtc(message.EventTime),
                    Source = message.ActivityType == WintapMessage.ActivityTypeEnum.Start
                        ? ProcessRecord.ProcessSourceEnum.real_time : ProcessRecord.ProcessSourceEnum.refresh,
                    MD5Hash = message.Process.MD5, SHA2Hash = message.Process.SHA2
                });
            }

            internal WintapMessage Replay(int pid, int parent, DateTime birth, string image, string commandLine = "") =>
                Sensor.HandleReplayedStart(pid, parent, birth, image, commandLine);

            internal ProcessRecord Record(int pid) => History.Where(record => record.ProcessId == pid).OrderByDescending(record => record.CreateTime).First();
            internal void Exit(WintapMessage message, DateTime time) => History.Single(record => record.PidHash == message.PidHash).ExitTime = time;
        }
    }
}
