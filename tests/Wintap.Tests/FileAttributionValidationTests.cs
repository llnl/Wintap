using gov.llnl.wintap.collect.models;
using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using V = gov.llnl.wintap.platform.windows.infrastructure.FileAttributionValidation;
using Activity = gov.llnl.wintap.collect.models.WintapMessage.ActivityTypeEnum;

namespace Wintap.Tests
{
    [Trait("Category", "pai-05")]
    [Trait("Category", "pai-06")]
    public class FileAttributionValidationTests
    {
        private const string Id = "0123456789abcdef0123456789abcdef";
        private const string DirectoryName = @"C:\isolated\validation\held";
        private const int Pid = 123, Parent = 45;
        private const long Start = 100, Os = 99;
        private static string Hash(int pid, long time) => pid + ":" + time;
        private static string Marker => V.Marker(Id, "held");

        private static WintapMessage Process(long time = Start, string hash = null, int pid = Pid,
            int parent = Parent, string name = "cmd.exe", string command = null) =>
            new WintapMessage(DateTime.UtcNow, pid, WintapMessage.MessageTypeEnum.Process)
            {
                EventTime = time, ActivityType = Activity.Start, ProcessName = name,
                PidHash = hash ?? Hash(pid, time),
                Process = new WintapMessage.ProcessObject { ParentPID = parent, CommandLine = command ?? "cmd /d /q /k \"set WINTAP_VALIDATION=" + Marker + "\"" }
            };

        private static WintapMessage File(int path = 0, Activity activity = Activity.Write,
            int pid = Pid, string name = "cmd.exe", string hash = null) =>
            new WintapMessage(DateTime.UtcNow, pid, WintapMessage.MessageTypeEnum.File)
            {
                ActivityType = activity, ProcessName = name, PidHash = hash ?? Hash(Pid, Start),
                File = new WintapMessage.FileActivityObject { Path = Path.Combine(DirectoryName, V.FileNames[path]) }
            };

        private static V.Evidence Evidence(bool start = true)
        {
            var evidence = new V.Evidence(DirectoryName, Marker, Parent);
            evidence.SetChild(Pid, Os);
            if (start) evidence.Capture(Process(), TimeSpan.Zero);
            evidence.Complete(TimeSpan.FromSeconds(1), DateTime.UtcNow);
            return evidence;
        }

        private static void GoodWrite(V.Evidence evidence)
        {
            evidence.Capture(File(), TimeSpan.FromSeconds(2));
        }

        private static V.Result Judge(V.Evidence evidence, bool interrupted = false, bool completed = true,
            bool filesCorrect = true, bool exit = true)
        {
            evidence.Seal(TimeSpan.FromSeconds(31));
            return evidence.Judge(Hash, "sentinel", completed, filesCorrect, exit, interrupted);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("0", false)]
        [InlineData("false", false)]
        [InlineData("yes", false)]
        [InlineData(" true ", false)]
        [InlineData("1", true)]
        [InlineData("TRUE", true)]
        public void FlagIsExplicitOptIn(string value, bool enabled) => Assert.Equal(enabled, V.Enabled(value));

        [Theory]
        [InlineData(false, true, true)]
        [InlineData(true, false, true)]
        [InlineData(true, true, false)]
        public void UnsupportedStartupDoesNotAuthorizeWork(bool windows, bool resolver, bool collectors) =>
            Assert.NotNull(V.Unavailable(windows, resolver, collectors, _ => null));

        [Theory]
        [InlineData("WINTAP_DISABLE_SENSORS")]
        [InlineData("WINTAP_SKIP_PROCESS_RESOLVE")]
        [InlineData("WINTAP_SKIP_PARENT_PROCESS_RESOLVE")]
        [InlineData("WINTAP_SKIP_PROCESS_REGISTER")]
        [InlineData("WINTAP_SKIP_ESPER_SEND")]
        [InlineData("WINTAP_ENABLE_DIRECT_PARQUET")]
        public void BypassedCollectionCannotValidate(string flag)
        {
            Assert.Equal(flag, V.Unavailable(true, true, true, key => key == flag ? "1" : null));
            Assert.Null(V.Unavailable(true, true, true, _ => null));
        }

        [Theory]
        [InlineData("held", "/k")]
        [InlineData("exit", "/k")]
        public void CommandUsesFixedWorkloadAndWorkingDirectory(string name, string switchValue)
        {
            string directory = @"C:\data with spaces & metacharacters\case";
            var info = V.Command(directory, Id, name);
            Assert.Equal(Path.Combine(Environment.SystemDirectory, "cmd.exe"), info.FileName);
            Assert.Equal(directory, info.WorkingDirectory);
            Assert.StartsWith("/d /q " + switchValue, info.Arguments);
            Assert.DoesNotContain(directory, info.Arguments);
            Assert.Contains("set WINTAP_VALIDATION=" + V.Marker(Id, name), info.Arguments);
            Assert.False(info.UseShellExecute);
            Assert.True(info.CreateNoWindow);
            Assert.True(info.RedirectStandardInput && info.RedirectStandardOutput && info.RedirectStandardError);
            Assert.Contains(">probe.txt echo " + Marker, V.Workload(Marker));
            Assert.DoesNotContain("powershell", V.Workload(Marker));
            Assert.Throws<ArgumentException>(() => V.Command(directory, Id, "held & injected"));
            Assert.Throws<ArgumentException>(() => V.Command(directory, "untrusted", name));
        }

        [Theory]
        [InlineData("set WINTAP_VALIDATION={0}", true)]
        [InlineData("set WINTAP_VALIDATION={0} & echo done", true)]
        [InlineData("\"{0}\"", true)]
        [InlineData("set WINTAP_VALIDATION={0}_suffix", false)]
        [InlineData("set WINTAP_VALIDATION=prefix{0}", false)]
        [InlineData("no marker", false)]
        public void MarkerRequiresWholeToken(string command, bool matches) =>
            Assert.Equal(matches, V.Evidence.HasMarker(string.Format(command, Marker.ToUpperInvariant()), Marker));

        [Fact]
        public void CompleteEvidencePassesWithIndependentStartHash()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            var result = Judge(evidence);
            Assert.Equal("PASS", result.Verdict);
            Assert.Equal(Hash(Pid, Start), result.ExpectedHash);
            Assert.Equal(1, result.Count);
        }

        [Fact]
        public void UsesFullCaseInsensitivePathsAndCopiesScalars()
        {
            var evidence = Evidence();
            var message = File();
            message.File.Path = message.File.Path.ToUpperInvariant();
            evidence.Capture(message, TimeSpan.FromSeconds(2));
            message.PID = 999;
            message.PidHash = "changed";
            message.File.Path = "changed";
            var outside = File(hash: "wrong");
            outside.File.Path += ".other";
            evidence.Capture(outside, TimeSpan.FromSeconds(2));
            outside.File.Path = @"C:\prefix" + Path.Combine(DirectoryName, "probe.txt");
            evidence.Capture(outside, TimeSpan.FromSeconds(2));
            Assert.Equal("PASS", Judge(evidence).Verdict);
        }

        [Fact]
        public void WrongThenCorrectNeverErasesFailure()
        {
            var evidence = Evidence();
            evidence.Capture(File(hash: "wrong"), TimeSpan.FromSeconds(2));
            GoodWrite(evidence);
            Assert.Equal(1, Judge(evidence).Misattributed);
            Assert.Equal("FAIL", Judge(evidence).Verdict);
        }

        [Fact]
        public void ReadsAreOutsideFixture()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(activity: Activity.Read, pid: 777), TimeSpan.FromSeconds(2));
            Assert.Equal("PASS", Judge(evidence).Verdict);
        }

        [Fact]
        public void MissingChildWriteRequiresCompletedWorkloadAndFullWindow()
        {
            var evidence = Evidence();
            evidence.Capture(File(pid: 4), TimeSpan.FromSeconds(2));
            var result = Judge(evidence);
            Assert.Equal("FAIL", result.Verdict);
            Assert.Equal(1, result.Missing);
            Assert.Equal("INCONCLUSIVE", Judge(Evidence(), completed: false).Verdict);
        }

        [Theory]
        [InlineData("Unknown", "123:100", 123)]
        [InlineData("", "123:100", 123)]
        [InlineData(" ", "123:100", 123)]
        [InlineData("cmd.exe", "", 123)]
        [InlineData("cmd.exe", "sentinel", 123)]
        [InlineData("cmd.exe", "Unknown", 123)]
        public void UnresolvedFieldsFail(string name, string hash, int pid)
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(pid: pid, name: name, hash: hash), TimeSpan.FromSeconds(2));
            var result = Judge(evidence);
            Assert.Equal("FAIL", result.Verdict);
            Assert.Equal(1, result.Unresolved);
        }

        [Fact]
        public void NullOwnerFieldsFail()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            var message = File();
            message.PidHash = null;
            message.ProcessName = null;
            evidence.Capture(message, TimeSpan.FromSeconds(2));
            Assert.Equal(1, Judge(evidence).Unresolved);
        }

        [Theory]
        [InlineData(123, "cmd.exe", "INCONCLUSIVE", 1)]
        [InlineData(777, "cmd.exe", "PASS", 0)]
        [InlineData(123, "wrong.exe", "FAIL", 0)]
        public void OsHashVariantRequiresCorrectPidAndName(int pid, string name, string verdict, int variants)
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(pid: pid, name: name, hash: Hash(Pid, Os)), TimeSpan.FromSeconds(2));
            var result = Judge(evidence);
            Assert.Equal(verdict, result.Verdict);
            Assert.Equal(variants, result.HashVariant);
        }

        [Fact]
        public void ArbitraryHashDifferenceFails()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(hash: "arbitrary"), TimeSpan.FromSeconds(2));
            Assert.Equal(1, Judge(evidence).Misattributed);
        }

        [Theory]
        [InlineData("missing")]
        [InlineData("ambiguous")]
        [InlineData("invalidHash")]
        [InlineData("invalidTime")]
        [InlineData("wrongPid")]
        [InlineData("wrongParent")]
        [InlineData("wrongName")]
        [InlineData("wrongMarker")]
        public void InvalidStartEvidenceCannotPass(string kind)
        {
            var evidence = Evidence(false);
            if (kind == "ambiguous")
            {
                evidence.Capture(Process(), TimeSpan.Zero);
                evidence.Capture(Process(Start + 1), TimeSpan.Zero);
            }
            else if (kind != "missing")
                evidence.Capture(Process(time: kind == "invalidTime" ? 0 : Start,
                    hash: kind == "invalidHash" ? "incorrect" : null,
                    pid: kind == "wrongPid" ? 555 : Pid,
                    parent: kind == "wrongParent" ? 555 : Parent,
                    name: kind == "wrongName" ? "other.exe" : "cmd.exe",
                    command: kind == "wrongMarker" ? "rem " + Marker + "_other" : null), TimeSpan.Zero);
            GoodWrite(evidence);
            Assert.Equal("INCONCLUSIVE", Judge(evidence).Verdict);
        }

        [Fact]
        public void IdenticalDuplicateStartsRemainOneIdentity()
        {
            var evidence = Evidence();
            evidence.Capture(Process(), TimeSpan.Zero);
            GoodWrite(evidence);
            Assert.Equal("PASS", Judge(evidence).Verdict);
        }

        [Fact]
        public void StartMayArriveBeforeHandleIdentityIsPublished()
        {
            var evidence = new V.Evidence(DirectoryName, Marker, Parent);
            evidence.Capture(Process(), TimeSpan.Zero);
            Assert.False(evidence.HasStart);
            evidence.SetChild(Pid, Os);
            Assert.True(evidence.HasStart);
        }

        [Fact]
        public void FullWindowDoesNotEndWhenChildWriteArrives()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(hash: "wrong"), TimeSpan.FromSeconds(30.999));
            Assert.Equal("FAIL", Judge(evidence).Verdict);
        }

        [Fact]
        public void DeadlineAndSealExcludeLaterDelivery()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(hash: "wrong"), TimeSpan.FromSeconds(31));
            var first = Judge(evidence);
            evidence.Capture(File(hash: "wrong"), TimeSpan.FromSeconds(2));
            Assert.Equal("PASS", first.Verdict);
            Assert.Equal(first.Details, Judge(evidence).Details);
        }

        [Fact]
        public void PrematureSealAndCancellationCannotPass()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Seal(TimeSpan.FromSeconds(30));
            Assert.Equal("INCONCLUSIVE", Judge(evidence).Verdict);
            var cancelled = Evidence();
            GoodWrite(cancelled);
            Assert.Equal("INCONCLUSIVE", Judge(cancelled, interrupted: true).Verdict);
        }

        [Fact]
        public async Task ConcurrentCallbacksCannotMutateSealedResult()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Seal(TimeSpan.FromSeconds(31));
            await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(() =>
                evidence.Capture(File(hash: "wrong"), TimeSpan.FromSeconds(30)))));
            Assert.Equal("PASS", Judge(evidence).Verdict);
        }

        [Fact]
        public void EvidenceMustBeSealedBeforeJudgement() =>
            Assert.Throws<InvalidOperationException>(() => Evidence().Judge(Hash, "sentinel", true, true, true, false));

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void EvidenceCapsAreInconclusive(bool process)
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            for (int i = 0; i < (process ? 8 : 256); i++)
                evidence.Capture(process ? Process() : File(), TimeSpan.FromSeconds(2));
            var result = Judge(evidence);
            Assert.Equal("INCONCLUSIVE", result.Verdict);
            Assert.True(result.Count <= 256);
        }

        [Fact]
        public void OversizedScalarsAndCallbackErrorsCannotPass()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.MarkUnsupported();
            Assert.Equal("INCONCLUSIVE", Judge(evidence).Verdict);
            var oversized = Evidence();
            GoodWrite(oversized);
            oversized.Capture(Process(name: new string('x', 1000)), TimeSpan.FromSeconds(2));
            Assert.Equal("INCONCLUSIVE", Judge(oversized).Verdict);
        }

        [Fact]
        public void OutputIsBoundedAndOnlyExactCompletionLinesCount()
        {
            int completions = 0;
            var output = new V.BoundedOutput("done", () => completions++);
            output.Append("notdone\r\ndone_suffix\r\ndo".AsSpan());
            Assert.Equal(0, completions);
            output.Append("ne\r\ndone\r\n".AsSpan());
            Assert.Equal(1, completions);
            output.Append(new string('x', 9000).AsSpan());
            Assert.True(output.Overflow);
            Assert.Equal(8192, output.Bytes);
        }

        [Fact]
        public void FailedExecutionAndExitCannotPass()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            Assert.Equal("INCONCLUSIVE", Judge(evidence, filesCorrect: false).Verdict);
            Assert.Equal("INCONCLUSIVE", Judge(evidence, exit: false).Verdict);
        }

        [Fact]
        public void ShutdownPreventsAnyLaterLaunch()
        {
            var ownership = new V.ChildOwnership();
            ownership.Shutdown();
            int launches = 0;
            Assert.Throws<OperationCanceledException>(() => ownership.Launch(() => { launches++; return new object(); }, _ => { }));
            Assert.Equal(0, launches);
        }

        [Fact]
        public async Task ShutdownCannotMissChildBeingCreated()
        {
            var ownership = new V.ChildOwnership();
            using var entered = new ManualResetEventSlim();
            using var proceed = new ManualResetEventSlim();
            object handle = new object(), killed = null;
            Task launch = Task.Run(() => ownership.Launch(() =>
            {
                entered.Set();
                Assert.True(proceed.Wait(TimeSpan.FromSeconds(3)));
                return handle;
            }, child => killed = child));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(3)));
            Task stop = Task.Run(() => ownership.Shutdown());
            proceed.Set();
            await Task.WhenAll(launch, stop);
            Assert.Same(handle, killed);
            Assert.Throws<OperationCanceledException>(() => ownership.Launch(() => new object(), _ => { }));
        }

        [Fact]
        public void ReleaseCannotTerminateUnownedHandle()
        {
            var ownership = new V.ChildOwnership();
            int kills = 0;
            object handle = ownership.Launch(() => new object(), _ => kills++);
            ownership.Release(new object(), _ => kills++);
            Assert.Equal(0, kills);
            ownership.Release(handle, _ => kills++);
            ownership.Shutdown();
            Assert.Equal(1, kills);
        }

        [Theory]
        [InlineData(@"C:\run\held\probe.txt", true, true)]
        [InlineData(@"C:\run-other\held\probe.txt", true, false)]
        [InlineData(@"C:\run\..\unrelated.txt", true, false)]
        [InlineData(@"C:\run\held\probe.txt", false, false)]
        public void CleanupRequiresOwnershipAndContainment(string path, bool owned, bool allowed) =>
            Assert.Equal(allowed, V.OwnedPaths.CanDelete(@"C:\run", path, owned));

        [Fact]
        public async Task BlockedCleanupJoinReturnsWithoutReleasingItsContinuation()
        {
            var pending = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Assert.False(await V.JoinWithinAsync(pending.Task, TimeSpan.FromMilliseconds(1)));
            Assert.False(pending.Task.IsCompleted);
            pending.SetResult();
            Assert.True(await V.JoinWithinAsync(pending.Task, TimeSpan.FromSeconds(1)));
        }

        [Fact]
        public void FailedTerminationRetainsOwnershipForRetry()
        {
            var ownership = new V.ChildOwnership();
            object handle = ownership.Launch(() => new object(), _ => { });
            Assert.Throws<IOException>(() => ownership.Release(handle, _ => throw new IOException()));
            Assert.True(ownership.HasChild);
            ownership.Release(handle, _ => { });
            Assert.False(ownership.HasChild);
        }

        [Fact]
        public async Task ChildTerminationPrecedesBlockedCleanup()
        {
            var ownership = new V.ChildOwnership();
            bool killed = false;
            ownership.Launch(() => new object(), _ => killed = true);
            var cleanup = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            ownership.Shutdown();
            Assert.True(killed);
            Assert.False(await V.JoinWithinAsync(cleanup.Task, TimeSpan.FromMilliseconds(1)));
            Assert.Throws<OperationCanceledException>(() => ownership.Launch(() => new object(), _ => { }));
            cleanup.SetResult();
        }

        [Fact]
        public void OtherProcessesDoNotEraseChildCoverageOrImplyMisattribution()
        {
            var evidence = Evidence();
            GoodWrite(evidence);
            evidence.Capture(File(pid: 4, name: "System", hash: "system"), TimeSpan.FromSeconds(2));
            var result = Judge(evidence);
            Assert.Equal("PASS", result.Verdict);
            Assert.Equal(1, result.ChildWrites);
            Assert.Equal(1, result.OtherProcessWrites);
            Assert.Equal(0, result.Misattributed);
        }

        [Fact]
        public void AmbiguousIdentityAbortsBeforeWriteAuthorization()
        {
            var evidence = Evidence();
            Assert.True(evidence.ValidStart(Hash));
            evidence.Capture(Process(Start + 1), TimeSpan.Zero);
            Assert.False(evidence.ValidStart(Hash));
        }

        [Theory, Trait("Category", "pai-06-command")]
        [InlineData("held")]
        [InlineData("exit")]
        public async Task ActualCmdWritesAndExits(string mode)
        {
            string id = Guid.NewGuid().ToString("N");
            string directory = Path.Combine(Path.GetTempPath(), "pai-06-" + id);
            System.IO.Directory.CreateDirectory(directory);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var child = new System.Diagnostics.Process { StartInfo = V.Command(directory, id, mode) };
            Task stdout = Task.CompletedTask, stderr = Task.CompletedTask;
            try
            {
                Assert.True(child.Start());
                var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var output = new V.BoundedOutput(id + "_done", () => done.TrySetResult());
                stdout = output.PumpAsync(child.StandardOutput, deadline.Token);
                stderr = new V.BoundedOutput(null, null).PumpAsync(child.StandardError, deadline.Token);
                await child.StandardInput.WriteLineAsync(V.Workload(id));
                await child.StandardInput.FlushAsync(deadline.Token);
                await done.Task.WaitAsync(deadline.Token);
                Assert.Equal(id + "\r\n", System.IO.File.ReadAllText(Path.Combine(directory, "probe.txt")));
                if (mode == "held") Assert.False(child.HasExited);
                await child.StandardInput.WriteLineAsync("exit 0");
                await child.StandardInput.FlushAsync(deadline.Token);
                await child.WaitForExitAsync(deadline.Token).WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal(0, child.ExitCode);
                await Task.WhenAll(stdout, stderr).WaitAsync(deadline.Token);
                Assert.False(output.Overflow);
            }
            finally
            {
                if (child.Id > 0 && !child.HasExited) child.Kill();
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                deadline.Cancel();
                try { await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(1)); } catch { }
                string path = Path.Combine(directory, "probe.txt");
                Assert.True(V.OwnedPaths.CanDelete(directory, path, true));
                System.IO.File.Delete(path);
                System.IO.Directory.Delete(directory, false);
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(3)]
        [InlineData(20)]
        [InlineData(50)]
        public void ReservoirWindowsAreSparseBoundedAndIndependent(int count)
        {
            var reservoir = new V.Reservoir(n => n - 1);
            DateTime start = new DateTime(2026, 10, 7, 0, 0, 0, DateTimeKind.Utc);
            reservoir.Reset(start);
            for (int n = 0; n < count; n++) reservoir.Capture(File(pid: n, name: "Unknown"));
            var window = reservoir.Detach(start.AddMinutes(8));
            Assert.Equal(count, window.Eligible);
            Assert.Equal(Math.Min(count, 20), window.Samples.Length);
            Assert.Equal(start, window.Start);
            Assert.Equal(start.AddMinutes(8), window.End);
            var empty = reservoir.Detach(start.AddMinutes(9));
            Assert.Empty(empty.Samples);
            Assert.Equal(0, empty.Eligible);
            Assert.Equal(window.End, empty.Start);
            Assert.Equal(Math.Min(count, 20), window.Samples.Length);
        }

        [Fact]
        public void ReservoirRetainsReplacesDiscardsAndCopiesOnlyWrites()
        {
            var draws = new System.Collections.Generic.Queue<long>(new long[] { 0, 19, 22 });
            var reservoir = new V.Reservoir(n => draws.Dequeue());
            for (int n = 0; n < 23; n++)
            {
                var message = File(pid: n);
                reservoir.Capture(message);
                message.PID = 999;
                message.File.Path = "changed";
            }
            reservoir.Capture(File(activity: Activity.Read));
            reservoir.Capture(Process());
            var window = reservoir.Detach(DateTime.UtcNow);
            Assert.Equal(23, window.Eligible);
            Assert.Equal(20, window.Samples[0].Pid);
            Assert.Equal(21, window.Samples[19].Pid);
            Assert.DoesNotContain(window.Samples, v => v.Pid == 999 || v.Path == "changed");
        }

        [Fact]
        public void FlushEscapesBoundsPreservesOwnershipAndLooksUpOnlyDetachedSamples()
        {
            int lookups = 0;
            var reservoir = new V.Reservoir(n => 0);
            var message = File(name: "Unknown");
            message.File.Path = DirectoryName + "\\quote\"\r\n" + new string('x', 5000);
            for (int n = 0; n < 40; n++) reservoir.Capture(message);
            Assert.Equal(0, lookups);
            var logs = new System.Collections.Generic.List<string>();
            V.Flush(reservoir.Detach(DateTime.UtcNow), (hash, pid) =>
            {
                lookups++;
                return new gov.llnl.wintap.core.infrastructure.ProcessResolver.AttributedProcessPath(@"C:\stored.exe", "stored_identity");
            }, logs.Add, diagnosticRoot: DirectoryName);
            Assert.Equal(20, lookups);
            Assert.Equal(21, logs.Count);
            foreach (string line in logs)
            {
                Assert.DoesNotContain("\n", line);
                using var json = System.Text.Json.JsonDocument.Parse(line.Substring(line.IndexOf(' ') + 1));
                if (!json.RootElement.TryGetProperty("filePath", out var path)) continue;
                Assert.Equal(4096, path.GetString().Length);
                Assert.True(json.RootElement.GetProperty("truncated").GetBoolean());
                Assert.True(json.RootElement.GetProperty("diagnosticOwned").GetBoolean());
                Assert.Equal("Unknown", json.RootElement.GetProperty("attributedProcessName").GetString());
            }
        }

        [Fact]
        public void UnavailableAndEmptyFlushDoNotInventMetadata()
        {
            var reservoir = new V.Reservoir();
            var logs = new System.Collections.Generic.List<string>();
            V.Flush(reservoir.Detach(DateTime.UtcNow), null, logs.Add, diagnosticRoot: DirectoryName);
            Assert.Single(logs);
            reservoir.Capture(File());
            logs.Clear();
            V.Flush(reservoir.Detach(DateTime.UtcNow), null, logs.Add, diagnosticRoot: DirectoryName);
            Assert.Contains("\"pathStatus\":\"resolver_unavailable\"", logs[1]);
            Assert.Contains("\"executablePath\":null", logs[1]);
        }

        [Fact]
        public async Task IndependentDeadlineStopsStalledEnrichmentWithoutReplacement()
        {
            var reservoir = new V.Reservoir();
            reservoir.Capture(File());
            reservoir.Capture(File());
            using var entered = new ManualResetEventSlim();
            using var release = new ManualResetEventSlim();
            using var cancellation = new CancellationTokenSource();
            int calls = 0, timeouts = 0;
            var logs = new System.Collections.Generic.List<string>();
            Task batch = Task.Run(() => V.Flush(reservoir.Detach(DateTime.UtcNow), (_, _) =>
            {
                calls++;
                entered.Set();
                if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException();
                return new gov.llnl.wintap.core.infrastructure.ProcessResolver.AttributedProcessPath(null, "path_missing");
            }, logs.Add, cancellation.Token, DirectoryName));
            try
            {
                Assert.True(entered.Wait(TimeSpan.FromSeconds(2)));
                await V.SuperviseAsync(batch, TimeSpan.FromMilliseconds(10), () =>
                { timeouts++; cancellation.Cancel(); });
                Assert.Equal(1, timeouts);
                Assert.False(batch.IsCompleted);
            }
            finally { release.Set(); }
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => batch);
            Assert.Equal(1, calls);
            Assert.Single(logs);
        }

        [Fact]
        public async Task CompletedOperationsCancelTheirDeadline()
        {
            int expired = 0;
            await V.SuperviseAsync(Task.CompletedTask, TimeSpan.FromMilliseconds(1), () => expired++);
            Assert.Equal(0, expired);
        }

        [Fact]
        public void CadenceAlternatesAndSchedulesFromActualBoundaryWithoutCatchup()
        {
            var cadence = new V.Cadence();
            Assert.Equal("held", cadence.Begin(TimeSpan.Zero));
            Assert.Equal(TimeSpan.FromMinutes(5), cadence.Next);
            Assert.Equal("exit", cadence.Begin(TimeSpan.FromMinutes(19)));
            Assert.Equal(TimeSpan.FromMinutes(24), cadence.Next);
            Assert.Equal("held", cadence.Begin(TimeSpan.FromMinutes(24)));
        }


        [Fact]
        public async Task SequentialCyclesDoNotOverlapAndCancelBeforeAnotherLaunch()
        {
            using var cancellation = new CancellationTokenSource();
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var modes = new System.Collections.Generic.List<string>();
            var deadlines = new System.Collections.Generic.List<TimeSpan>();
            TimeSpan now = TimeSpan.Zero;
            int flushes = 0;
            Task loop = V.RunCyclesAsync(async mode =>
            {
                modes.Add(mode);
                if (modes.Count == 1) await release.Task;
                if (modes.Count == 3) cancellation.Cancel();
            }, () => { flushes++; return Task.CompletedTask; },
            deadline =>
            {
                deadlines.Add(deadline);
                now = deadlines.Count == 1 ? TimeSpan.FromMinutes(19) : deadline;
                return Task.CompletedTask;
            }, () => now, cancellation.Token);
            Assert.Single(modes);
            Assert.Empty(deadlines);
            Assert.Equal(0, flushes);
            release.SetResult();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop);
            Assert.Equal(new[] { "held", "exit", "held" }, modes);
            Assert.Equal(new[] { TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(24) }, deadlines);
            Assert.Equal(2, flushes);
        }

        [Fact]
        public async Task AlreadyCancelledSessionPerformsNoCycleOperations()
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            int operations = 0;
            await V.RunCyclesAsync(_ => { operations++; return Task.CompletedTask; },
                () => { operations++; return Task.CompletedTask; },
                _ => { operations++; return Task.CompletedTask; }, () => TimeSpan.Zero, cancellation.Token);
            Assert.Equal(0, operations);
        }

        [Fact]
        public async Task ShutdownReturnsDuringCreationAndLatePublicationTerminatesChild()
        {
            var ownership = new V.ChildOwnership();
            using var entered = new ManualResetEventSlim();
            using var release = new ManualResetEventSlim();
            bool killed = false;
            var launch = Task.Run(() => ownership.Launch(() =>
            {
                entered.Set();
                Assert.True(release.Wait(TimeSpan.FromSeconds(5)));
                return new object();
            }, _ => killed = true));
            try
            {
                Assert.True(entered.Wait(TimeSpan.FromSeconds(2)));
                await Task.Run(ownership.Shutdown).WaitAsync(TimeSpan.FromSeconds(1));
                Assert.False(launch.IsCompleted);
            }
            finally { release.Set(); }
            var handle = await launch;
            Assert.True(killed);
            ownership.Release(handle, _ => { });
            Assert.False(ownership.HasChild);
        }

        [Fact]
        public void FreshProbeDoesNotInheritPreviousEvidenceAndFailureSurvivesOverflow()
        {
            var first = Evidence();
            first.Capture(File(hash: "wrong"), TimeSpan.FromSeconds(2));
            for (int n = 0; n < 260; n++) first.Capture(File(), TimeSpan.FromSeconds(2));
            Assert.Equal("FAIL", Judge(first).Verdict);
            var fresh = Evidence();
            Assert.Equal("FAIL", Judge(fresh).Verdict);
            Assert.Equal(0, Judge(fresh).Count);
        }

        [Fact]
        public void TrustedRootPolicyAllowsOnlyIdentitySystemAndAdministrators()
        {
            Assert.True(V.TrustedSid("service", "service"));
            Assert.True(V.TrustedSid("S-1-5-18", "service"));
            Assert.True(V.TrustedSid("S-1-5-32-544", "service"));
            Assert.False(V.TrustedSid("S-1-1-0", "service"));
            Assert.False(V.Writes(FileSystemRights.ReadAndExecute));
            Assert.True(V.Writes(FileSystemRights.Write));
            Assert.True(V.Writes(FileSystemRights.DeleteSubdirectoriesAndFiles));
            Assert.True(V.Writes(FileSystemRights.ChangePermissions));
        }
    }
}
