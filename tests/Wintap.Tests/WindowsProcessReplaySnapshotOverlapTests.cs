using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.platform.windows.collect.etw;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    public partial class WindowsProcessStartupReconciliationTests
    {
        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(-50001L, false)]
        [InlineData(-50000L, true)]
        [InlineData(-49999L, true)]
        [InlineData(-1L, true)]
        [InlineData(1L, true)]
        [InlineData(49999L, true)]
        [InlineData(50000L, true)]
        [InlineData(50001L, false)]
        [InlineData(846L, true)]
        [InlineData(934L, true)]
        [InlineData(31314L, true)]
        public void ActualReplayOverlapUsesInclusiveSymmetricFiveMillisecondTickBoundary(long replaySkewTicks, bool matches)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime snapshotBirth = Boot.AddMinutes(20).AddTicks(1234);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(700, 4, snapshotBirth.AddTicks(replaySkewTicks), @"C:\boot\SmSs.ExE", "authoritative payload");
            var original = fixture.Record(700);
            fixture.Snapshot.Add(Snapshot(700, 4, snapshotBirth, "smss.exe"));
            fixture.Snapshot.Add(Snapshot(701, 700, snapshotBirth.AddSeconds(1), "child.exe"));

            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            string chosenHash = matches ? replay.PidHash : Hash(700, snapshotBirth);
            Assert.Equal(chosenHash, fixture.Record(701).ParentPidHash);
            Assert.Contains(chosenHash, fixture.ReconciledHashes);
            Assert.Equal(matches ? 1 : 2, fixture.Emitted.Count(message => message.PID == 700));
            Assert.Equal(matches ? 1 : 0, fixture.Sensor.DedupSuppressedCount);
            Assert.Equal(1, fixture.Sensor.BootReplayCount);
            Assert.Equal(snapshotBirth.AddTicks(replaySkewTicks).ToFileTimeUtc(), replay.EventTime);
            Assert.Equal(Hash(700, snapshotBirth.AddTicks(replaySkewTicks)), replay.PidHash);
            Assert.Equal("authoritative payload", original.CommandLine);
            Assert.Equal(@"C:\boot\SmSs.ExE", original.ProcessPath);
            Assert.Equal(snapshotBirth.AddTicks(replaySkewTicks), original.CreateTime);
            if (matches)
            {
                Assert.Same(original, fixture.Record(700));
                Assert.DoesNotContain(Hash(700, snapshotBirth), fixture.ReconciledHashes);
                Assert.DoesNotContain(fixture.Emitted, message => message.PID == 700 && message.ActivityType == WintapMessage.ActivityTypeEnum.Refresh);
            }
            Assert.All(new[] { -1, 0, 4 }, pid => Assert.Single(fixture.Emitted, message => message.PID == pid));
            Assert.Equal(0, fixture.ClearCalls);
            AssertLineage(fixture, 701, 2);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData("different-name")]
        [InlineData("replay-null-name")]
        [InlineData("snapshot-null-name")]
        [InlineData("replay-blank-name")]
        [InlineData("snapshot-blank-name")]
        [InlineData("both-unknown")]
        [InlineData("both-parenthesized-unknown")]
        [InlineData("both-angle-unknown")]
        [InlineData("replay-unknown")]
        [InlineData("snapshot-unknown")]
        [InlineData("replay-parent-missing")]
        [InlineData("snapshot-parent-missing")]
        [InlineData("both-parent-missing")]
        [InlineData("replay-parent-negative")]
        [InlineData("snapshot-parent-negative")]
        [InlineData("different-parent")]
        [InlineData("wrong-pid")]
        [InlineData("missing-hash")]
        public void NarrowReplayOverlapRejectsUnknownOrDisagreeingCompatibilityEvidence(string scenario)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(21);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(710, 4, birth.AddTicks(-846), "known.exe");
            var record = fixture.Record(710);
            string snapshotName = "KNOWN.EXE";
            int snapshotParent = 4;
            // Mutate the history view to exercise missing persisted fields as well
            // as payload placeholders. Names here are already normalized basenames.
            switch (scenario)
            {
                case "different-name": snapshotName = "other.exe"; break;
                case "replay-null-name": record.ProcessName = null; break;
                case "snapshot-null-name": snapshotName = null; break;
                case "replay-blank-name": record.ProcessName = " \t"; break;
                case "snapshot-blank-name": snapshotName = " \t"; break;
                case "both-unknown": record.ProcessName = "unknown"; snapshotName = "UNKNOWN"; break;
                case "both-parenthesized-unknown": record.ProcessName = "(unknown)"; snapshotName = "(UNKNOWN)"; break;
                case "both-angle-unknown": record.ProcessName = "<unknown>"; snapshotName = "<UNKNOWN>"; break;
                case "replay-unknown": record.ProcessName = "unknown"; break;
                case "snapshot-unknown": snapshotName = "unknown"; break;
                case "replay-parent-missing": record.ParentProcessId = 0; break;
                case "snapshot-parent-missing": snapshotParent = 0; break;
                case "both-parent-missing": record.ParentProcessId = snapshotParent = 0; break;
                case "replay-parent-negative": record.ParentProcessId = -1; break;
                case "snapshot-parent-negative": snapshotParent = -1; break;
                case "different-parent": snapshotParent = 999; break;
                case "wrong-pid": record.ProcessId = 999; break;
                case "missing-hash": record.PidHash = " "; break;
            }
            fixture.Snapshot.Add(Snapshot(710, snapshotParent, birth, snapshotName));

            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            var refresh = Assert.Single(fixture.Emitted, message => message.PID == 710 && message.ActivityType == WintapMessage.ActivityTypeEnum.Refresh);
            Assert.Equal(Hash(710, birth), refresh.PidHash);
            Assert.NotEqual(replay.PidHash, refresh.PidHash);
            Assert.Contains(refresh.PidHash, fixture.ReconciledHashes);
            Assert.Equal(0, fixture.Sensor.DedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void ActualUnknownReplayPayloadCannotMatchUnknownSnapshotPlaceholder()
        {
            var fixture = new Fixture();
            DateTime birth = Boot.AddMinutes(22);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(720, 4, birth.AddTicks(-934), null);
            // Model the existing unknown-name placeholder in the resolver view.
            // The delegate fixture stores the producer value, so model that view.
            fixture.Record(720).ProcessName = "unknown";
            fixture.Snapshot.Add(Snapshot(720, 4, birth, "unknown"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal("", replay.Process.Path);
            Assert.Equal(2, fixture.Emitted.Count(message => message.PID == 720));
            Assert.Equal(0, fixture.Sensor.DedupSuppressedCount);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(-1L, false)]
        [InlineData(0L, true)]
        [InlineData(1L, true)]
        public void NarrowReplayKnownExitRejectsOnlyExitEarlierThanSnapshotBirth(long exitSkewTicks, bool matches)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(23);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(730, 4, birth.AddTicks(-846), "lifetime.exe");
            fixture.Exit(replay, birth.AddTicks(exitSkewTicks));
            fixture.Snapshot.Add(Snapshot(730, 4, birth, "LIFETIME.EXE"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(matches ? 1 : 2, fixture.Emitted.Count(message => message.PID == 730));
            Assert.Contains(matches ? replay.PidHash : Hash(730, birth), fixture.ReconciledHashes);
            Assert.Equal(birth.AddTicks(exitSkewTicks), fixture.History.Single(record => record.PidHash == replay.PidHash).ExitTime);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(false)]
        [InlineData(true)]
        public void ExactSnapshotHashWinsRegardlessOfReplayProvenanceAndIncompatibleFields(bool observedInReplay)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(24);
            var exact = Historical(740, 0, birth, "(unknown)", "authoritative-parent-hash");
            exact.CommandLine = "original --do-not-replace";
            exact.ExitTime = birth.AddTicks(-1);
            fixture.History.Add(exact);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            if (observedInReplay) Assert.Null(fixture.Replay(740, 999, birth, "different-payload.exe"));
            fixture.Replay(740, 4, birth.AddTicks(-934), "known.exe");
            fixture.Replay(740, 4, birth.AddTicks(846), "known.exe");
            fixture.Snapshot.Add(Snapshot(740, 4, birth, "known.exe"));

            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 740 && message.ActivityType == WintapMessage.ActivityTypeEnum.Refresh);
            Assert.Contains(exact.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(Hash(740, birth.AddTicks(-934)), fixture.ReconciledHashes);
            Assert.DoesNotContain(Hash(740, birth.AddTicks(846)), fixture.ReconciledHashes);
            Assert.Equal("(unknown)", exact.ProcessName);
            Assert.Equal("original --do-not-replace", exact.CommandLine);
            Assert.Equal("authoritative-parent-hash", exact.ParentPidHash);
            Assert.Equal(birth.AddTicks(-1), exact.ExitTime);
            Assert.DoesNotContain(fixture.Logs, text => text.Contains("overlap ambiguous"));
            Assert.Equal(2, fixture.Sensor.BootReplayCount);
            Assert.Equal(observedInReplay ? 2 : 1, fixture.Sensor.DedupSuppressedCount);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void TwoActualStartsWithinFiveMillisecondsRemainDistinctAndSnapshotIsAmbiguous()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(25);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var first = fixture.Replay(750, 4, birth.AddTicks(-846), "same.exe");
            var second = fixture.Replay(750, 4, birth.AddTicks(934), "SAME.EXE");
            Assert.Null(fixture.Replay(750, 4, birth.AddTicks(-846), "duplicate.exe"));
            fixture.Snapshot.Add(Snapshot(750, 4, birth, "same.exe"));
            fixture.Snapshot.Add(Snapshot(751, 750, birth.AddSeconds(1), "child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            var refresh = Assert.Single(fixture.Emitted, message => message.PID == 750 && message.ActivityType == WintapMessage.ActivityTypeEnum.Refresh);
            Assert.NotEqual(first.PidHash, second.PidHash);
            Assert.Equal(3, fixture.History.Count(record => record.ProcessId == 750));
            Assert.Equal(2, fixture.Sensor.BootReplayCount);
            Assert.Equal(1, fixture.Sensor.DedupSuppressedCount);
            Assert.Equal(Hash(750, birth), refresh.PidHash);
            Assert.Equal(refresh.PidHash, fixture.Record(751).ParentPidHash);
            Assert.Contains(refresh.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(first.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(second.PidHash, fixture.ReconciledHashes);
            Assert.Contains(fixture.Logs, text => text.Contains("overlap ambiguous") && text.Contains("pid=750"));
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void DuplicateHistoryRowsWithSameReplayHashAreOneCandidateAndParentHashNeedNotAgree()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(26);
            var prior = Historical(760, 4, birth.AddTicks(846), "same.exe", Hash(4, Boot));
            fixture.History.Add(prior);
            fixture.History.Add(Historical(760, 4, prior.CreateTime, "SAME.EXE", "different-parent-hash"));
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.Null(fixture.Replay(760, 4, prior.CreateTime, "same.exe"));
            fixture.Snapshot.Add(Snapshot(760, 4, birth, "same.exe"));
            fixture.Snapshot.Add(Snapshot(761, 760, birth.AddSeconds(1), "child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 760);
            Assert.Equal(prior.PidHash, fixture.Record(761).ParentPidHash);
            Assert.Contains(prior.PidHash, fixture.ReconciledHashes);
            Assert.Equal(2, fixture.Sensor.DedupSuppressedCount);
            Assert.Equal(0, fixture.Sensor.BootReplayCount);
            Assert.DoesNotContain(fixture.Logs, text => text.Contains("overlap ambiguous"));
            Assert.Equal(Hash(4, Boot), prior.ParentPidHash);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(846L, true, true)]
        [InlineData(-846L, true, true)]
        [InlineData(-50001L, true, false)]
        [InlineData(50001L, true, false)]
        [InlineData(-10000000L, true, false)]
        [InlineData(10000000L, true, false)]
        [InlineData(-10000000L, false, false)]
        [InlineData(10000000L, false, false)]
        [InlineData(-846L, false, false)]
        public void RetainedExactReplayObservationUsesNarrowRuleAndNeverFallsBack(long skewTicks, bool compatible, bool matches)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(27);
            var prior = Historical(770, 4, birth.AddTicks(skewTicks), "original.exe", Hash(4, Boot));
            prior.CommandLine = "retained command";
            fixture.History.Add(prior);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.Null(fixture.Replay(770, 4, prior.CreateTime, "original.exe"));
            fixture.Snapshot.Add(Snapshot(770, compatible ? 4 : 999, birth, compatible ? "ORIGINAL.EXE" : "different.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(matches ? 0 : 1, fixture.Emitted.Count(message => message.PID == 770));
            Assert.Contains(matches ? prior.PidHash : Hash(770, birth), fixture.ReconciledHashes);
            Assert.Equal(matches ? 2 : 1, fixture.Sensor.DedupSuppressedCount);
            Assert.Equal(0, fixture.Sensor.BootReplayCount);
            Assert.Equal("retained command", prior.CommandLine);
            Assert.Equal(birth.AddTicks(skewTicks), prior.CreateTime);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void EligibleRetainedAndActualReplayCandidatesTogetherRemainAmbiguous()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(28);
            var retained = Historical(780, 999, birth.AddSeconds(-1), "retained-other-name.exe");
            fixture.History.Add(retained);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var replay = fixture.Replay(780, 4, birth.AddTicks(934), "same.exe");
            fixture.Snapshot.Add(Snapshot(780, 4, birth, "same.exe"));
            fixture.Snapshot.Add(Snapshot(781, 780, birth.AddSeconds(1), "child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            var refresh = Assert.Single(fixture.Emitted, message => message.PID == 780 && message.ActivityType == WintapMessage.ActivityTypeEnum.Refresh);
            Assert.Equal(Hash(780, birth), refresh.PidHash);
            Assert.Equal(refresh.PidHash, fixture.Record(781).ParentPidHash);
            Assert.Contains(refresh.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(retained.PidHash, fixture.ReconciledHashes);
            Assert.DoesNotContain(replay.PidHash, fixture.ReconciledHashes);
            Assert.Contains(fixture.Logs, text => text.Contains("overlap ambiguous") && text.Contains("pid=780"));
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(-20000001L, false)]
        [InlineData(-20000000L, true)]
        [InlineData(-10000000L, true)]
        [InlineData(1L, false)]
        public void RetainedOnlyHistoryWithoutReplayPreservesOneSidedTwoSecondPolicy(long skewTicks, bool matches)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(29);
            var prior = Historical(790, 0, birth.AddTicks(skewTicks), "(unknown)");
            fixture.History.Add(prior);
            fixture.Snapshot.Add(Snapshot(790, 4, birth, "different.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.Equal(matches ? 0 : 1, fixture.Emitted.Count(message => message.PID == 790));
            Assert.Contains(matches ? prior.PidHash : Hash(790, birth), fixture.ReconciledHashes);
            Assert.Equal(0, fixture.Sensor.BootReplayCount);
            Assert.Equal(0, fixture.ClearCalls);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(-10000000L, true)]
        [InlineData(846L, false)]
        public void OrdinaryLiveStartIsNotActualBootReplayEvidence(long skewTicks, bool matches)
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(30);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var live = fixture.Sensor.HandleLiveStart(800, 4, birth.AddTicks(skewTicks), "live.exe", "live command");
            Assert.NotNull(live);
            // Older live evidence keeps the retained-only policy even if the
            // snapshot name/parent disagree; a future live birth is not symmetric.
            fixture.Snapshot.Add(Snapshot(800, matches ? 999 : 4, birth, matches ? "other.exe" : "live.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(matches ? 1 : 2, fixture.Emitted.Count(message => message.PID == 800));
            Assert.Contains(matches ? live.PidHash : Hash(800, birth), fixture.ReconciledHashes);
            Assert.Equal(0, fixture.Sensor.BootReplayCount);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void BootstrapClearsPreBootstrapObservationButRepeatedBootstrapKeepsCurrentPassEvidenceAndSeeds()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(31);
            // Exercise the existing internal seam before bootstrap: this must not
            // leak replay provenance into the actual startup pass.
            var beforeBootstrap = fixture.Replay(810, 4, birth.AddSeconds(-1), "before.exe");
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var currentPass = fixture.Replay(811, 4, birth.AddTicks(846), "current.exe");
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            fixture.Snapshot.Add(Snapshot(810, 999, birth, "different.exe"));
            fixture.Snapshot.Add(Snapshot(811, 4, birth, "CURRENT.EXE"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Single(fixture.Emitted, message => message.PID == 810);
            Assert.Single(fixture.Emitted, message => message.PID == 811);
            Assert.Contains(beforeBootstrap.PidHash, fixture.ReconciledHashes);
            Assert.Contains(currentPass.PidHash, fixture.ReconciledHashes);
            Assert.All(new[] { -1, 0, 4 }, pid => Assert.Single(fixture.Emitted, message => message.PID == pid));
            Assert.Equal(1, fixture.EnumerationCalls);
            Assert.Equal(1, fixture.ReconcileCalls);
            Assert.Equal(0, fixture.ClearCalls);
        }

        [Theory]
        [Trait("Category", "wpc-11")]
        [InlineData(false)]
        [InlineData(true)]
        public void MissingReplayStillPublishesSnapshotOnceWithoutDuplicateSeeds(bool sameBoot)
        {
            var fixture = new Fixture(sameBoot: sameBoot);
            DateTime birth = Boot.AddMinutes(32);
            fixture.Snapshot.Add(Snapshot(820, 4, birth, "snapshot-only.exe"));
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            Assert.False(fixture.Sensor.ReplayBootTrace(Path.Combine(AppContext.BaseDirectory, "missing-wpc-11-" + Guid.NewGuid().ToString("N") + ".etl")));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.True(fixture.Sensor.InitializeSnapshotRefresh());
            Assert.Equal(4, fixture.Emitted.Count);
            Assert.Equal(0, fixture.Sensor.BootReplayCount);
            Assert.All(new[] { -1, 0, 4, 820 }, pid => Assert.Single(fixture.Emitted, message => message.PID == pid));
            Assert.Equal(Hash(4, Boot), fixture.Record(820).ParentPidHash);
            Assert.Equal(sameBoot ? 0 : 1, fixture.ClearCalls);
            Assert.Equal(sameBoot ? 1 : 0, fixture.ReconcileCalls);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public void PartialReplayUsesOnlyProcessedObservationsAndRetainsCanonicalLiveSetAfterFailedEmission()
        {
            var fixture = new Fixture(sameBoot: true);
            DateTime birth = Boot.AddMinutes(33);
            var notObserved = Historical(832, 999, birth.AddSeconds(-1), "retained.exe", Hash(4, Boot));
            fixture.History.Add(notObserved);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            var parent = fixture.Replay(830, 4, birth.AddTicks(934), "parent.exe");
            fixture.FailEmit = message => message.PID == 831;
            Assert.Throws<InvalidOperationException>(() => fixture.Replay(831, 830, birth.AddSeconds(1).AddTicks(846), "child.exe"));
            Assert.DoesNotContain(fixture.History, record => record.ProcessId == 831);
            Assert.Equal(1, fixture.Sensor.BootReplayCount);
            fixture.FailEmit = null;
            fixture.Snapshot.AddRange(new[]
            {
                Snapshot(830, 4, birth, "PARENT.EXE"),
                Snapshot(831, 830, birth.AddSeconds(1), "child.exe"),
                Snapshot(832, 4, birth, "different.exe")
            });
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Single(fixture.Emitted, message => message.PID == 830);
            var child = Assert.Single(fixture.Emitted, message => message.PID == 831);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Refresh, child.ActivityType);
            Assert.Equal(Hash(831, birth.AddSeconds(1)), child.PidHash);
            Assert.Equal(parent.PidHash, child.Process.ParentPidHash);
            Assert.DoesNotContain(fixture.Emitted, message => message.PID == 832);
            Assert.Equal(new[] { Hash(-1, Boot), Hash(0, Boot), Hash(4, Boot), parent.PidHash, child.PidHash, notObserved.PidHash }.OrderBy(hash => hash),
                fixture.ReconciledHashes.OrderBy(hash => hash));
            Assert.Null(fixture.History.Single(record => record.PidHash == parent.PidHash).ExitTime);
            Assert.Null(notObserved.ExitTime);
            Assert.Equal(0, fixture.ClearCalls);
            Assert.Equal(1, fixture.ReconcileCalls);
            Assert.Equal(2, fixture.Sensor.DedupSuppressedCount);
            Assert.All(new[] { -1, 0, 4 }, pid => Assert.Single(fixture.Emitted, message => message.PID == pid));
            AssertLineage(fixture, 831, 2);
        }

        [Fact]
        [Trait("Category", "wpc-11")]
        public async Task RealStartAndStopSerializersToTemporaryParquetKeepOneSkewedParentIdentityAndRawLifecycleRows()
        {
            var fixture = new Fixture(sameBoot: true);
            Assert.True(fixture.Sensor.InitializeStartupBootstrap());
            DateTime smssSnapshotBirth = Boot.AddSeconds(1).AddTicks(1234);
            DateTime parentSnapshotBirth = Boot.AddSeconds(2).AddTicks(4321);
            var smss = fixture.Replay(840, 4, smssSnapshotBirth.AddTicks(846), @"C:\Windows\System32\smss.exe", "smss original");
            var parent = fixture.Replay(841, 840, parentSnapshotBirth.AddTicks(934), @"C:\Windows\System32\wininit.exe", "wininit --original payload");
            parent.Process.MD5 = "original-md5";
            parent.Process.SHA2 = "original-sha2";
            Assert.Null(fixture.Replay(841, 840, parentSnapshotBirth.AddTicks(934), "duplicate-payload.exe"));
            fixture.Snapshot.Add(Snapshot(840, 4, smssSnapshotBirth, "SMSS.EXE"));
            fixture.Snapshot.Add(Snapshot(841, 840, parentSnapshotBirth, "WININIT.EXE"));
            fixture.Snapshot.Add(Snapshot(842, 841, Boot.AddSeconds(3).AddTicks(789), "uncovered-child.exe"));
            Assert.True(fixture.Sensor.InitializeSnapshotDelta());
            Assert.Equal(6, fixture.Emitted.Count); // Three seeds, two Starts, one delta Refresh.
            Assert.Equal(2, fixture.Sensor.BootReplayCount);
            Assert.Equal(3, fixture.Sensor.DedupSuppressedCount); // Exact replay duplicate and two covered snapshots.
            Assert.Equal(4, fixture.Sensor.GetQaCounterSnapshot().SnapshotCount);
            Assert.Equal(parent.PidHash, fixture.Record(842).ParentPidHash);
            Assert.DoesNotContain(Hash(840, smssSnapshotBirth), fixture.ReconciledHashes);
            Assert.DoesNotContain(Hash(841, parentSnapshotBirth), fixture.ReconciledHashes);

            // Capture Stop separately: Fixture.Register intentionally models only
            // birth registration, and must not add a stop-time process identity.
            var stops = new List<WintapMessage>();
            var stopSensor = new WindowsProcessSensor(
                resolveProcessAtTime: (pid, time) => fixture.History.Where(record => record.ProcessId == pid && record.CreateTime <= time)
                    .OrderByDescending(record => record.CreateTime).FirstOrDefault(),
                emit: stops.Add, log: (_, _) => { }, enableQaCounterTimer: false);
            DateTime stopTime = Boot.AddSeconds(10).AddTicks(9876);
            var stop = stopSensor.EmitStop(841, stopTime, "ignored-stop-payload.exe", 7);
            stop.AgentId = "fixture-agent";
            Assert.Same(stop, Assert.Single(stops));
            Assert.Equal(parent.PidHash, stop.PidHash);
            Assert.Equal(smss.PidHash, stop.Process.ParentPidHash);
            Assert.Equal(0, stopSensor.StopWithoutStartCount);
            Assert.Equal(6, fixture.History.Count);

            var startQueue = new ConcurrentQueue<ExpandoObject>();
            var stopQueue = new ConcurrentQueue<ExpandoObject>();
            var startSerializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var stopSerializer = (ProcessStopSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessStopSerializer));
            InitializeOverlapSerializer(startSerializer, typeof(ProcessSerializer), startQueue);
            InitializeOverlapSerializer(stopSerializer, typeof(ProcessStopSerializer), stopQueue);
            var startHandler = typeof(ProcessSerializer).GetMethod("handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            var stopHandler = typeof(ProcessStopSerializer).GetMethod("handleStopEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(startHandler);
            Assert.NotNull(stopHandler);
            var messages = fixture.Emitted.ToArray();
            foreach (var message in messages)
            {
                message.AgentId = "fixture-agent";
                message.Process.User = ""; // Do not consult live host account inventory for synthetic seeds.
                // Use non-null defaults so the Parquet round-trip retains hash
                // metadata columns even for synthetic seeds without file hashes.
                message.Process.MD5 ??= "";
                message.Process.SHA2 ??= "";
                startHandler.Invoke(startSerializer, new object[] { message });
            }
            stopHandler.Invoke(stopSerializer, new object[] { stop });
            Assert.Equal(6, startQueue.Count);
            Assert.Single(stopQueue);
            var starts = await RoundTripOverlapParquet(startQueue, "process");
            var terminations = await RoundTripOverlapParquet(stopQueue, "processstop");
            Assert.Equal(6, starts.Count);
            var stopRow = Assert.Single(terminations);

            // Inspect raw row cardinality before building any ancestry lookup.
            Assert.All(starts.GroupBy(row => (string)row["PidHash"]), group => Assert.Single(group));
            Assert.Single(starts, row => Convert.ToInt32(row["PID"]) == 840);
            Assert.Single(starts, row => Convert.ToInt32(row["PID"]) == 841);
            Assert.DoesNotContain(starts, row => (string)row["PidHash"] == Hash(840, smssSnapshotBirth) || (string)row["PidHash"] == Hash(841, parentSnapshotBirth));
            for (int i = 0; i < messages.Length; i++)
            {
                var row = starts[i];
                var message = messages[i];
                Assert.Equal(message.PidHash, row["PidHash"]);
                Assert.Equal(Hash(message.PID, DateTime.FromFileTimeUtc(message.EventTime)), row["PidHash"]);
                Assert.Equal(message.Process.ParentPidHash, row["ParentPidHash"]);
                Assert.Equal(message.EventTime, Convert.ToInt64(row["EventTime"]));
                Assert.Equal(message.EventTime, Convert.ToInt64(row["StartTime"]));
                Assert.Equal(message.Process.Path, row["ProcessPath"]);
                Assert.Equal(message.Process.CommandLine, row["CommandLine"]);
                Assert.Equal(message.Process.MD5, row["FileMd5"]);
                Assert.Equal(message.Process.SHA2, row["FileSha2"]);
                Assert.Equal(message.ActivityType.ToString(), row["ActivityType"]);
                Assert.Equal("fixture-agent", row["AgentId"]);
                Assert.Equal("FIXTURE-HOST", row["Hostname"]);
            }
            var byHash = starts.ToDictionary(row => (string)row["PidHash"]);
            var root = byHash[Hash(4, Boot)];
            Assert.Equal("ntoskrnl.exe", root["ProcessName"]);
            Assert.Equal(smssSnapshotBirth.AddTicks(846).ToFileTimeUtc(), Convert.ToInt64(byHash[smss.PidHash]["StartTime"]));
            var parentRow = byHash[parent.PidHash];
            Assert.Equal(parentSnapshotBirth.AddTicks(934).ToFileTimeUtc(), Convert.ToInt64(parentRow["StartTime"]));
            Assert.Equal("wininit --original payload", parentRow["CommandLine"]);
            Assert.Equal("original-md5", parentRow["FileMd5"]);
            Assert.Equal("original-sha2", parentRow["FileSha2"]);
            Assert.Equal("Start", parentRow["ActivityType"]);
            Assert.Equal(parent.PidHash, byHash[Hash(842, Boot.AddSeconds(3).AddTicks(789))]["ParentPidHash"]);
            int realIdentitiesReachingRoot = 0;
            foreach (var row in starts.Where(row => Convert.ToInt32(row["PID"]) > 4))
            {
                var visited = new HashSet<string>();
                var current = row;
                while (Convert.ToInt32(current["PID"]) != 4)
                {
                    Assert.True(visited.Add((string)current["PidHash"]), "Raw fixture ancestry must not cycle");
                    Assert.True(byHash.TryGetValue((string)current["ParentPidHash"], out current), "Raw parent identity must exist");
                }
                Assert.Same(root, current);
                realIdentitiesReachingRoot++;
            }
            Assert.Equal(3, realIdentitiesReachingRoot);
            Assert.Equal("Stop", stopRow["ActivityType"]);
            Assert.Equal(parent.PidHash, stopRow["PidHash"]);
            Assert.Equal(smss.PidHash, stopRow["ParentPidHash"]);
            Assert.Equal(stopTime.ToFileTimeUtc(), Convert.ToInt64(stopRow["EventTime"]));
            Assert.Equal(7, Convert.ToInt64(stopRow["ExitCode"]));
            Assert.Equal("fixture-agent", stopRow["AgentId"]);
            Assert.Equal("FIXTURE-HOST", stopRow["Hostname"]);
            Assert.Equal(2, starts.Concat(terminations).Count(row => (string)row["PidHash"] == parent.PidHash));
            Assert.All(new[] { -1, 0, 4 }, pid => Assert.Single(starts, row => Convert.ToInt32(row["PID"]) == pid));
        }

        private static void InitializeOverlapSerializer(Serializer serializer, Type concreteType, ConcurrentQueue<ExpandoObject> queue)
        {
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(concreteType, serializer, "host", new HostId { Hostname = "fixture-host" });
        }

        private static async Task<List<IDictionary<string, object>>> RoundTripOverlapParquet(ConcurrentQueue<ExpandoObject> queue, string kind)
        {
            var rows = queue.Select(row => (IDictionary<string, object>)row).ToList();
            var schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(schemaMethod);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { rows[0] });
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp", "opencode");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "wpc-11-" + kind + "-" + Guid.NewGuid().ToString("N") + ".parquet");
            try
            {
                using (var output = File.Create(path))
                    await ParquetSerializer.SerializeUntypedAsync(rows, schema, output);
                using var input = File.OpenRead(path);
                var recovered = await ParquetSerializer.DeserializeUntypedAsync(input);
                return recovered.Data.Select(row => (IDictionary<string, object>)row).ToList();
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }
    }
}
