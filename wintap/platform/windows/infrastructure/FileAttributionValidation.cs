/*
 * Copyright (c) 2026, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory. All rights reserved.
 */
using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.platform.windows.infrastructure
{
    // Opt-in periodic diagnostics with stored metadata enrichment.
    internal sealed class FileAttributionValidation
    {
        internal const string Flag = "WINTAP_VALIDATE_FILE_ATTRIBUTION";
        internal static readonly TimeSpan RunLimit = TimeSpan.FromSeconds(90);
        internal static readonly TimeSpan StartLimit = TimeSpan.FromSeconds(30);
        internal static readonly TimeSpan Observation = TimeSpan.FromSeconds(30);
        internal static readonly TimeSpan CleanupLimit = TimeSpan.FromSeconds(5);
        internal static readonly string[] FileNames = { "probe.txt" };
        private readonly string runId = Guid.NewGuid().ToString("N");
        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private readonly ChildOwnership ownership = new ChildOwnership();
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private Task worker;
        private Evidence active;
        private readonly Func<string, int, ProcessResolver.AttributedProcessPath> readPath;
        private readonly Reservoir samples = new Reservoir();
        internal static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

        internal FileAttributionValidation(Func<string, int, ProcessResolver.AttributedProcessPath> readPath = null)
        { this.readPath = readPath; }

        internal static bool Enabled(string value) =>
            string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

        internal static string Unavailable(bool windows, bool resolver, bool collectors, Func<string, string> read)
        {
            if (!windows) return "Windows required";
            if (!resolver) return "resolver unavailable";
            if (!collectors) return "Process/File collectors not started";
            foreach (string key in new[] { "WINTAP_DISABLE_SENSORS", "WINTAP_SKIP_PROCESS_RESOLVE",
                "WINTAP_SKIP_PARENT_PROCESS_RESOLVE", "WINTAP_SKIP_PROCESS_REGISTER",
                "WINTAP_SKIP_ESPER_SEND", "WINTAP_ENABLE_DIRECT_PARQUET" })
                if (Enabled(read(key))) return key;
            return null;
        }

        internal void Start(string unavailable)
        {
            if (unavailable != null) { Log("session", "", "NOT_RUN", unavailable); return; }
            worker = Task.Run(RunAsync);
        }

        internal void Cancel()
        {
            cancellation.Cancel();
            ownership.Shutdown();
        }

        internal async Task JoinAsync()
        {
            if (worker != null && !await JoinWithinAsync(worker, CleanupLimit))
                Log("session", "", "INCONCLUSIVE", "shutdown;cleanupPending=true");
        }

        internal static async Task<bool> JoinWithinAsync(Task task, TimeSpan limit)
        {
            using var timer = new CancellationTokenSource();
            Task deadline = Task.Delay(limit, timer.Token);
            bool done = await Task.WhenAny(task, deadline) == task;
            timer.Cancel();
            return done;
        }

        internal static async Task SuperviseAsync(Task operation, TimeSpan limit, Action expired,
            CancellationToken token = default)
        {
            using var timer = CancellationTokenSource.CreateLinkedTokenSource(token);
            Task deadline = Task.Delay(limit, timer.Token);
            if (await Task.WhenAny(operation, deadline) != operation && !token.IsCancellationRequested)
                expired();
            timer.Cancel();
        }

        // The independent timer can stop the session while its single worker is in native code.
        private async Task SupervisedAsync(Func<Task> action, TimeSpan limit, string operation)
        {
            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task supervisor = SuperviseAsync(done.Task, limit, () =>
            {
                Volatile.Read(ref active)?.Seal(clock.Elapsed);
                Log("session", "", "INCONCLUSIVE", operation + " timeout;cleanupPending=true");
                Cancel();
            }, cancellation.Token);
            try { await action(); }
            finally { done.TrySetResult(); await supervisor; }
        }

        private async Task RunAsync()
        {
            EPDeployment deployment = null;
            try
            {
                await SupervisedAsync(() =>
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    deployment = EventChannel.CompileDeploy(
                        "select * from WintapMessage where MessageType = 'Process' or MessageType = 'File'",
                        "FileAttributionValidation_" + runId);
                    cancellation.Token.ThrowIfCancellationRequested();
                    foreach (var statement in deployment.Statements) statement.Events += Observe;
                    return Task.CompletedTask;
                }, CleanupLimit, "subscription setup");
                cancellation.Token.ThrowIfCancellationRequested();
                samples.Reset(DateTime.UtcNow);
                await RunCyclesAsync(
                    mode => SupervisedAsync(() => RunCaseAsync(mode), RunLimit, "probe"),
                    () =>
                    {
                        Window window = samples.Detach(DateTime.UtcNow);
                        return SupervisedAsync(() =>
                        {
                            Flush(window, readPath, Emit, cancellation.Token);
                            return Task.CompletedTask;
                        }, CleanupLimit, "sample enrichment batch incomplete");
                    },
                    deadline => WaitUntilAsync(() => false, deadline),
                    () => clock.Elapsed, cancellation.Token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { LogCleanup(ex); }
            finally
            {
                ownership.Shutdown();
                Volatile.Read(ref active)?.Seal(clock.Elapsed);
                Window partial = samples.Detach(DateTime.UtcNow);
                Emit("FileAttributionSampleWindow " + JsonSerializer.Serialize(new {
                    partial.Start, partial.End, partial.Eligible, status = "partial/discarded" }));
                var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                Task supervisor = SuperviseAsync(done.Task, CleanupLimit,
                    () => Log("session", "", "INCONCLUSIVE", "subscription teardown timeout;cleanupPending=true"));
                try
                {
                    if (deployment != null)
                    {
                        foreach (var statement in deployment.Statements) statement.Events -= Observe;
                        EventChannel.EsperRuntime.DeploymentService.Undeploy(deployment.DeploymentId);
                    }
                }
                catch (Exception ex) { LogCleanup(ex); }
                finally { done.TrySetResult(); await supervisor; }
            }
        }

        // One sequential loop; injected time and operations allow cadence/cancellation tests.
        internal static async Task RunCyclesAsync(Func<string, Task> probe, Func<Task> flush,
            Func<TimeSpan, Task> wait, Func<TimeSpan> now, CancellationToken token)
        {
            var cadence = new Cadence();
            while (!token.IsCancellationRequested)
            {
                string mode = cadence.Begin(now());
                if (cadence.Cycles > 1) await flush();
                token.ThrowIfCancellationRequested();
                await probe(mode);
                token.ThrowIfCancellationRequested();
                await wait(cadence.Next);
            }
        }

        internal sealed class Cadence
        {
            private bool exit;
            internal TimeSpan Next { get; private set; }
            internal int Cycles { get; private set; }
            internal string Begin(TimeSpan actualBoundary)
            {
                Cycles++;
                Next = actualBoundary + Interval;
                string mode = exit ? "exit" : "held";
                exit = !exit;
                return mode;
            }
        }

        private void Observe(object sender, UpdateEventArgs args)
        {
            if (args.NewEvents == null || cancellation.IsCancellationRequested) return;
            foreach (var item in args.NewEvents)
            {
                if (item.Underlying is not WintapMessage message) continue;
                samples.Capture(message);
                Evidence evidence = Volatile.Read(ref active);
                try { evidence?.Capture(message, clock.Elapsed); }
                catch { evidence?.MarkUnsupported(); }
            }
        }

        private async Task RunCaseAsync(string name)
        {
            string probeId = Guid.NewGuid().ToString("N");
            string marker = Marker(probeId, name);
            var paths = new OwnedPaths(Env.FileDataRoot, probeId);
            var evidence = new Evidence(paths.CasePath(name), marker, Environment.ProcessId);
            Volatile.Write(ref active, evidence);
            Process child = null;
            Task output = Task.CompletedTask, error = Task.CompletedTask;
            using var streamCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            bool completed = false, filesCorrect = false, exitCorrect = false;
            string problem = null;
            DateTime? launchUtc = null, exitUtc = null;
            TimeSpan launchElapsed = clock.Elapsed;
            var stdout = new BoundedOutput(marker + "_done", () => evidence.Complete(clock.Elapsed, DateTime.UtcNow));
            var stderr = new BoundedOutput(null, null);
            Log("start", name, "PENDING", "probeId=" + probeId + " utc=" + DateTime.UtcNow.ToString("O"));
            try
            {
                paths.Prepare();
                child = ownership.Launch(() =>
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    var process = new Process { StartInfo = Command(paths.CasePath(name), probeId, name) };
                    try
                    {
                        if (!process.Start()) throw new InvalidOperationException("child did not start");
                        // Retain the handle and its OS creation time for this child.

                        launchUtc = DateTime.UtcNow;
                        launchElapsed = clock.Elapsed;
                        return process;
                    }
                    catch { process.Dispose(); throw; }
                }, Kill);
                evidence.SetChild(child.Id, child.StartTime.ToUniversalTime().ToFileTimeUtc());
                output = stdout.PumpAsync(child.StandardOutput, streamCancellation.Token);
                error = stderr.PumpAsync(child.StandardError, streamCancellation.Token);
                TimeSpan startDeadline = launchElapsed + StartLimit;
                await WaitUntilAsync(() => evidence.HasStart, startDeadline);
                if (!evidence.ValidStart(new ProcessHash().GenPidHash)) throw new InvalidOperationException("Process Start identity absent/conflicting");
                {
                    await child.StandardInput.WriteLineAsync(Workload(marker));
                    await child.StandardInput.FlushAsync(cancellation.Token);
                }
                // Workload execution is also bounded; the observation deadline begins at its marker.
                await WaitUntilAsync(() => evidence.Completion.HasValue, clock.Elapsed + StartLimit);
                if (!evidence.Completion.HasValue) throw new TimeoutException("workload completion marker missing");
                completed = true;
                TimeSpan deadline = evidence.Completion.Value + Observation;
                if (name == "exit")
                {
                    await child.StandardInput.WriteLineAsync("exit 0");
                    await child.StandardInput.FlushAsync(cancellation.Token);
                    await WaitUntilAsync(() => child.HasExited, clock.Elapsed + CleanupLimit);
                    if (!child.HasExited) throw new TimeoutException("child exit timeout");
                }
                await WaitUntilAsync(() => false, deadline); // always observe the entire window
                evidence.Seal(clock.Elapsed);
                filesCorrect = paths.Verify(name, marker);
                if (name == "held")
                {
                    if (child.HasExited) problem = "held child exited before release";
                    else
                    {
                        await child.StandardInput.WriteLineAsync("exit 0");
                        await child.StandardInput.FlushAsync(cancellation.Token);
                    }
                }
                await WaitUntilAsync(() => child.HasExited, clock.Elapsed + CleanupLimit);
                if (!child.HasExited) throw new TimeoutException("child exit timeout");
                exitUtc = child.ExitTime.ToUniversalTime();
                exitCorrect = child.ExitCode == 0;
                await Task.WhenAll(output, error).WaitAsync(CleanupLimit, cancellation.Token);
            }
            catch (Exception ex) { problem = ex is OperationCanceledException ? "cancelled/deadline" : ex.GetType().Name + ":" + ex.Message; }
            finally
            {
                evidence.Seal(clock.Elapsed);
                if (child != null)
                {
                    try
                    {
                        // Confirm termination before releasing the retained handle or deleting files.
                        Kill(child);
                        await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(1));
                        exitUtc = child.ExitTime.ToUniversalTime();
                        ownership.Release(child, Kill);
                        child.Dispose();
                    }
                    catch (Exception ex)
                    {
                        problem = "child cleanup failed:" + ex.GetType().Name;
                        Cancel(); // retain ownership for the outer finally; never launch another child
                    }
                }
                streamCancellation.Cancel();
                try { await Task.WhenAll(output, error).WaitAsync(TimeSpan.FromSeconds(1)); }
                catch { problem = problem ?? "output capture interrupted"; }
                Volatile.Write(ref active, null);
                try
                {
                    if (ownership.HasChild) throw new IOException("child exit unconfirmed; retaining owned paths");
                    paths.Cleanup();
                }
                catch (Exception ex) { problem = "cleanupPending=true:" + ex.GetType().Name; Cancel(); }
                var hash = new ProcessHash();
                Result result = evidence.Judge(hash.GenPidHash, hash.GenPidHash(-1, 0),
                    completed, filesCorrect, exitCorrect,
                    problem != null || stdout.Overflow || stderr.Overflow || cancellation.IsCancellationRequested);
                Log("result", name, result.Verdict,
                    result.Details + " probeId=" + probeId + " launchUtc=" + launchUtc?.ToString("O") + " exitUtc=" + exitUtc?.ToString("O") +
                    " marker=" + marker + " stdoutBytes=" + stdout.Bytes + " stderrBytes=" + stderr.Bytes +
                    " reason=" + (problem ?? "complete"));
            }
        }

        private async Task WaitUntilAsync(Func<bool> condition, TimeSpan deadline)
        {
            while (clock.Elapsed < deadline && !condition())
            {
                cancellation.Token.ThrowIfCancellationRequested();

                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(50, (deadline - clock.Elapsed).TotalMilliseconds > 0
                    ? (deadline - clock.Elapsed).TotalMilliseconds : 1)), cancellation.Token);
            }
            cancellation.Token.ThrowIfCancellationRequested();
        }

        private static void Kill(Process process)
        {
            try { if (!process.HasExited) process.Kill(); }
            catch (InvalidOperationException) { }
        }

        private void LogCleanup(Exception ex) =>
            Log("cleanup", "", "INCONCLUSIVE", ex.GetType().Name + ":" + ex.Message);

        private static void Emit(string text)
        {
            try { WintapLogger.Log.Append(text, LogLevel.Info); }
            catch { }
        }

        private void Log(string stage, string name, string verdict, string details) =>
            Emit("FileAttributionValidation " + JsonSerializer.Serialize(new {
                session = runId, mode = name, stage, verdict, reason = details }));

        internal static string Marker(string id, string name)
        {
            if (!Guid.TryParseExact(id, "N", out _) || (name != "held" && name != "exit"))
                throw new ArgumentException("Only generated run IDs and fixed cases are supported");
            return id;
        }

        internal static string Workload(string marker) =>
            ">probe.txt echo " + marker + "\r\necho.\r\necho " + marker + "_done";

        internal static ProcessStartInfo Command(string directory, string id, string name)
        {
            string marker = Marker(id, name);
            var info = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                WorkingDirectory = directory,
                Arguments = "/d /q /k \"set WINTAP_VALIDATION=" + marker + "\"",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            // cmd emits a prompt before each stdin line even with /q. A newline-only
            // prompt keeps the completion marker on an exact, independently parsed line.
            info.Environment["PROMPT"] = "$_";
            return info;
        }

        // The lock covers creation AND publication. Shutdown either wins before launch,
        // or receives the exact retained handle. No PID-based kill or process-tree traversal.
        internal sealed class ChildOwnership
        {
            private readonly object sync = new object();
            private volatile bool stopped;
            private object child;
            private Action<object> terminate;
            internal bool HasChild { get { lock (sync) return child != null; } }
            internal T Launch<T>(Func<T> create, Action<T> kill) where T : class
            {
                lock (sync)
                {
                    if (stopped) throw new OperationCanceledException();
                    if (child != null) throw new InvalidOperationException("child already owned");
                    T value = create();
                    child = value;
                    terminate = item => kill((T)item);
                    if (stopped) { try { terminate(child); } catch { } }
                    return value;
                }
            }
            internal void Shutdown()
            {
                stopped = true;
                // A stuck creation cannot block service stop. Late publication sees stopped
                // while still holding sync and terminates the retained handle itself.
                if (!Monitor.TryEnter(sync)) return;
                try
                {
                    if (child != null)
                    {
                        try { terminate(child); }
                        catch { }
                    }
                }
                finally { Monitor.Exit(sync); }
            }
            internal void Release<T>(T value, Action<T> kill) where T : class
            {
                lock (sync)
                {
                    if (!ReferenceEquals(child, value)) return;
                    kill(value);
                    child = null;
                    terminate = null;
                }
            }
        }

        internal sealed class BoundedOutput
        {
            private readonly string marker;
            private readonly Action completed;
            private readonly StringBuilder line = new StringBuilder();
            private bool found;
            internal int Bytes { get; private set; }
            internal bool Overflow { get; private set; }
            internal BoundedOutput(string marker, Action completed) { this.marker = marker; this.completed = completed; }
            internal void Append(ReadOnlySpan<char> text)
            {
                foreach (char c in text)
                {
                    if (Bytes >= 8192) { Overflow = true; continue; }
                    Bytes += Encoding.UTF8.GetByteCount(new[] { c });
                    if (Bytes > 8192) { Bytes = 8192; Overflow = true; line.Clear(); continue; }
                    if (c == '\n')
                    {
                        if (!found && marker != null && line.ToString().TrimEnd('\r') == marker)
                        { found = true; completed(); }
                        line.Clear();
                    }
                    else line.Append(c);
                }
            }
            internal async Task PumpAsync(StreamReader reader, CancellationToken token)
            {
                char[] buffer = new char[512];
                int count;
                while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
                    Append(buffer.AsSpan(0, count));
            }
        }

        internal sealed record StartRecord(int Pid, int Parent, string Name, long Time, string Hash);
        internal sealed record FileRecord(int PathIndex, WintapMessage.ActivityTypeEnum Activity, int Pid, string Name, string Hash, long Time);
        internal sealed class Result
        {
            internal string Verdict, Details, ExpectedHash, IdentityDetails;
            internal int Missing, Unresolved, Misattributed, HashVariant, Count, ChildWrites, OtherProcessWrites;
        }

        internal sealed class Evidence
        {
            private readonly object sync = new object();
            private readonly string[] paths;
            private readonly string marker;
            private readonly int parent;
            private readonly List<StartRecord> starts = new List<StartRecord>();
            private readonly List<FileRecord> files = new List<FileRecord>();
            private int pid;
            private long osTime;
            private bool sealedEvidence, fullWindow, overflow, unsupported;
            private TimeSpan? completion;
            private DateTime? completionUtc;
            internal Evidence(string directory, string marker, int parent)
            { paths = FileNames.Select(n => Path.Combine(directory, n)).ToArray(); this.marker = marker; this.parent = parent; }
            internal TimeSpan? Completion { get { lock (sync) return completion; } }
            internal bool HasStart { get { lock (sync) return starts.Where(s => s.Pid == pid && s.Parent == parent && IsCmd(s.Name)).Distinct().Count() == 1; } }
            internal bool ValidStart(Func<int, long, string> hash)
            {
                lock (sync)
                {
                    var candidates = starts.Distinct().ToArray();
                    return !overflow && !unsupported && candidates.Length == 1 &&
                        candidates[0].Pid == pid && candidates[0].Parent == parent &&
                        IsCmd(candidates[0].Name) && candidates[0].Time > 0 &&
                        candidates[0].Hash == hash(pid, candidates[0].Time);
                }
            }
            internal void SetChild(int value, long time) { lock (sync) { pid = value; osTime = time; } }
            internal void Complete(TimeSpan now, DateTime utc)
            { lock (sync) { if (!sealedEvidence && !completion.HasValue) { completion = now; completionUtc = utc; } } }
            internal void MarkUnsupported() { lock (sync) unsupported = true; }
            internal static bool IsCmd(string value) => string.Equals(value, "cmd.exe", StringComparison.OrdinalIgnoreCase);
            internal static bool HasMarker(string command, string marker)
            {
                if (command == null) return false;
                int index = command.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                while (index >= 0)
                {
                    int end = index + marker.Length;
                    if ((index == 0 || !TokenChar(command[index - 1])) &&
                        (end == command.Length || !TokenChar(command[end]))) return true;
                    index = command.IndexOf(marker, index + 1, StringComparison.OrdinalIgnoreCase);
                }
                return false;
            }
            private static bool TokenChar(char c) => char.IsLetterOrDigit(c) || c == '_';
            internal void Capture(WintapMessage message, TimeSpan now)
            {
                lock (sync)
                {
                    if (sealedEvidence || (completion.HasValue && now >= completion.Value + Observation)) return;
                    if (message.MessageType == WintapMessage.MessageTypeEnum.Process &&
                        message.ActivityType == WintapMessage.ActivityTypeEnum.Start &&
                        HasMarker(message.Process?.CommandLine, marker))
                    {
                        if (starts.Count == 8) { overflow = true; return; }
                        starts.Add(new StartRecord(message.PID, message.Process.ParentPID,
                            Scalar(message.ProcessName), message.EventTime, Scalar(message.PidHash)));
                    }
                    if (message.MessageType != WintapMessage.MessageTypeEnum.File ||
                        message.ActivityType != WintapMessage.ActivityTypeEnum.Write) return;
                    int index = Array.FindIndex(paths, p => string.Equals(p, message.File?.Path, StringComparison.OrdinalIgnoreCase));
                    if (index < 0) return;
                    if (files.Count == 256) { overflow = true; return; }
                    files.Add(new FileRecord(index, message.ActivityType, message.PID,
                        Scalar(message.ProcessName), Scalar(message.PidHash), message.EventTime));
                }
            }
            private string Scalar(string value)
            {
                if (value?.Length > 512) { unsupported = true; return value.Substring(0, 512); }
                return value;
            }
            internal void Seal(TimeSpan now)
            {
                lock (sync)
                {
                    if (sealedEvidence) return;
                    fullWindow = completion.HasValue && now >= completion.Value + Observation;
                    sealedEvidence = true;
                }
            }
            internal Result Judge(Func<int, long, string> hash, string sentinel, bool completed,
                bool filesCorrect, bool exitCorrect, bool interrupted)
            {
                lock (sync)
                {
                    if (!sealedEvidence) throw new InvalidOperationException("Seal evidence before judging");
                    StartRecord[] candidates = starts.Where(s => s.Pid == pid && s.Parent == parent && IsCmd(s.Name)).Distinct().ToArray();
                    StartRecord start = candidates.Length == 1 ? candidates[0] : null;
                    bool identity = starts.Distinct().Count() == 1 && start != null && start.Time > 0 && !Blank(start.Hash, sentinel) &&
                        string.Equals(start.Hash, hash(pid, start.Time), StringComparison.Ordinal);
                    string expected = identity ? start.Hash : null;
                    string alternate = osTime > 0 ? hash(pid, osTime) : null;
                    var result = new Result { Count = files.Count, ExpectedHash = expected };
                    var otherExamples = new List<FileRecord>();
                    var examples = new List<string>();
                    foreach (var file in files)
                    {
                        if (file.Pid != pid)
                        {
                            result.OtherProcessWrites++;
                            if (otherExamples.Count < 3) otherExamples.Add(file);
                            continue;
                        }
                        result.ChildWrites++;
                        string classification = null;
                        if (file.Pid <= 0 || Blank(file.Name, sentinel) || Blank(file.Hash, sentinel))
                        { result.Unresolved++; classification = "unresolved"; }
                        else if (file.Pid != pid || !IsCmd(file.Name))
                        { result.Misattributed++; classification = "misattributed"; }
                        else if (identity && !string.Equals(file.Hash, expected, StringComparison.Ordinal))
                        {
                            if (alternate != expected && file.Hash == alternate)
                            { result.HashVariant++; classification = "hashVariant"; }
                            else { result.Misattributed++; classification = "misattributed"; }
                        }
                        if (classification != null && examples.Count < 3)
                            examples.Add(classification + ":" + FileNames[file.PathIndex] + ":" + file.Activity +
                                ":pid=" + file.Pid + ":name=" + file.Name + ":hash=" + file.Hash + ":time=" + file.Time);
                    }
                    // Missing is definite only after a confirmed workload and complete window.
                    result.Missing = completed && fullWindow && result.ChildWrites == 0 ? 1 : 0;
                    bool failure = result.Missing + result.Unresolved + result.Misattributed > 0;
                    result.Verdict = failure ? "FAIL" :
                        !identity || !completed || !filesCorrect || !exitCorrect || !fullWindow ||
                        overflow || unsupported || interrupted || result.HashVariant > 0 ? "INCONCLUSIVE" : "PASS";
                    result.IdentityDetails = "pid=" + pid + " osStart=" + osTime + " etwStart=" + start?.Time +
                        " startDeltaTicks=" + (start == null ? "" : (osTime - start.Time).ToString()) +
                        " expectedHash=" + (expected ?? "<unverified>");
                    result.Details = result.IdentityDetails + " starts=" + starts.Count +
                        " childWrites=" + result.ChildWrites + " otherProcessWrites=" + result.OtherProcessWrites +
                        " otherExamples=" + JsonSerializer.Serialize(otherExamples) +
                        " missingChildWrite=" + result.Missing + " unresolved=" + result.Unresolved +
                        " identityMismatch=" + result.Misattributed + " hashVariant=" + result.HashVariant +
                        " overflow=" + overflow + " unsupported=" + unsupported + " fullWindow=" + fullWindow +
                        " completionUtc=" + completionUtc?.ToString("O") + " filesCorrect=" + filesCorrect +
                        " exitZero=" + exitCorrect + " examples=[" + string.Join(";", examples) + "]";
                    return result;
                }
            }
            private static bool Blank(string value, string sentinel) => string.IsNullOrWhiteSpace(value) ||
                string.Equals(value, "Unknown", StringComparison.OrdinalIgnoreCase) || value == sentinel;
        }


        internal sealed record Sample(string Path, int Pid, string PidHash, string ProcessName,
            long EventTime, long ReceiveTime, bool Truncated);
        internal sealed record Window(string Id, DateTime Start, DateTime End, long Eligible, Sample[] Samples);

        internal sealed class Reservoir
        {
            private readonly object sync = new object();
            private readonly Func<long, long> draw;
            private readonly List<Sample> values = new List<Sample>(20);
            private long count;
            private DateTime start = DateTime.UtcNow;
            internal Reservoir(Func<long, long> draw = null)
            { this.draw = draw ?? (n => Random.Shared.NextInt64(n)); }

            internal void Capture(WintapMessage message)
            {
                if (message.MessageType != WintapMessage.MessageTypeEnum.File ||
                    message.ActivityType != WintapMessage.ActivityTypeEnum.Write) return;
                lock (sync)
                {
                    long n = checked(++count);
                    long slot = n <= 20 ? n - 1 : draw(n);
                    if (slot >= 20) return;
                    bool truncated = false;
                    var value = new Sample(Bound(message.File?.Path, ref truncated), message.PID,
                        Bound(message.PidHash, ref truncated), Bound(message.ProcessName, ref truncated),
                        message.EventTime, message.ReceiveTime, truncated);
                    if (values.Count < 20) values.Add(value);
                    else values[(int)slot] = value;
                }
            }
            internal void Reset(DateTime utc) { lock (sync) { start = utc; count = 0; values.Clear(); } }
            internal Window Detach(DateTime utc)
            {
                lock (sync)
                {
                    var window = new Window(Guid.NewGuid().ToString("N"), start, utc, count, values.ToArray());
                    start = utc; count = 0; values.Clear();
                    return window;
                }
            }
        }

        internal static string Bound(string value, ref bool truncated)
        {
            if (value?.Length <= 4096 || value == null) return value;
            truncated = true;
            return value.Substring(0, 4096);
        }

        internal static void Flush(Window window,
            Func<string, int, ProcessResolver.AttributedProcessPath> lookup, Action<string> log,
            CancellationToken token = default, string diagnosticRoot = null)
        {
            diagnosticRoot ??= Path.Combine(Env.FileDataRoot, "validation", "file-attribution");
            string prefix = diagnosticRoot.TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            log("FileAttributionSampleWindow " + JsonSerializer.Serialize(new {
                windowId = window.Id, startUtc = window.Start, endUtc = window.End,
                eligibleCount = window.Eligible, sampleCount = window.Samples.Length }));
            foreach (Sample sample in window.Samples.Take(20))
            {
                token.ThrowIfCancellationRequested();
                ProcessResolver.AttributedProcessPath result;
                try { result = lookup?.Invoke(sample.PidHash, sample.Pid) ??
                    new ProcessResolver.AttributedProcessPath(null, "resolver_unavailable"); }
                catch { result = new ProcessResolver.AttributedProcessPath(null, "lookup_failed"); }
                token.ThrowIfCancellationRequested();
                bool truncated = sample.Truncated;
                string executable = Bound(result.Path, ref truncated);
                log("FileAttributionSample " + JsonSerializer.Serialize(new {
                    windowId = window.Id, filePath = sample.Path, attributedPid = sample.Pid,
                    attributedPidHash = sample.PidHash, attributedProcessName = sample.ProcessName,
                    executablePath = executable, pathStatus = result.Status,
                    eventTime = sample.EventTime, receiveTime = sample.ReceiveTime,
                    diagnosticOwned = sample.Path?.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true,
                    truncated }));
            }
        }

        internal static void ValidateTrustedDirectory(string path)
        {
            string full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal) || new DriveInfo(Path.GetPathRoot(full)).DriveType != DriveType.Fixed)
                throw new IOException("trusted local fixed-drive root required");
            CheckNoLinks(full);
            var security = new DirectoryInfo(full).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            string current = WindowsIdentity.GetCurrent().User.Value;
            if (!TrustedSid(security.GetOwner(typeof(SecurityIdentifier)).Value, current))
                throw new IOException("untrusted directory owner");
            var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
            if (descriptor.DiscretionaryAcl == null) throw new IOException("unrestricted directory DACL");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && Writes(rule.FileSystemRights) &&
                    !TrustedSid(rule.IdentityReference.Value, current))
                    throw new IOException("directory grants write access to " + rule.IdentityReference.Value);
        }

        internal static bool TrustedSid(string sid, string current) =>
            sid == current || sid == "S-1-5-18" || sid == "S-1-5-32-544";
        internal static bool Writes(FileSystemRights rights) =>
            (rights & (FileSystemRights.Write | FileSystemRights.Delete |
                FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions |
                FileSystemRights.TakeOwnership | (FileSystemRights)0x40000000 | (FileSystemRights)0x10000000)) != 0;

        internal static void CheckNoLinks(string path)
        {
            for (var item = new DirectoryInfo(Path.GetFullPath(path)); item != null; item = item.Parent)
                if ((File.GetAttributes(item.FullName) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("reparse point rejected");
        }

        // Explicit ownership list, with non-recursive deletion. Never follows links or enumerates children.
        internal sealed class OwnedPaths
        {
            private readonly string root, run;
            private readonly List<string> directories = new List<string>();
            private readonly HashSet<string> files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            internal OwnedPaths(string root, string id)
            { Marker(id, "held"); this.root = Path.GetFullPath(root); run = Path.Combine(this.root, "validation", "file-attribution", id); }
            internal string CasePath(string name)
            {
                if (name != "held" && name != "exit") throw new ArgumentException(nameof(name));
                return run;
            }
            private void DirectoryPath(string path, bool mustBeNew)
            {
                if (Path.Exists(path))
                {
                    if (mustBeNew) throw new IOException("unexpected existing run path");
                }
                else { Directory.CreateDirectory(path); if (mustBeNew) directories.Add(path); }
                ValidateTrustedDirectory(path);
            }
            internal void Prepare()
            {
                ValidateTrustedDirectory(root);
                DirectoryPath(Path.Combine(root, "validation"), false);
                DirectoryPath(Path.Combine(root, "validation", "file-attribution"), false);
                DirectoryPath(run, true);
                string path = Path.Combine(run, "probe.txt");
                if (Path.Exists(path)) throw new IOException("unexpected existing workload path");
                files.Add(path);
            }
            internal bool Verify(string name, string marker)
            {
                CheckNoLinks(run);
                string path = Path.Combine(run, "probe.txt");
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("workload file became reparse point");
                return File.ReadAllText(path) == marker + "\r\n";
            }
            internal static bool CanDelete(string run, string path, bool owned) =>
                owned && Path.GetFullPath(path).StartsWith(Path.GetFullPath(run) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
            internal void Cleanup()
            {
                var errors = new List<Exception>();
                foreach (string file in files)
                {
                    try
                    {
                        if (!CanDelete(run, file, files.Contains(file))) throw new IOException("cleanup ownership failure");
                        CheckNoLinks(Path.GetDirectoryName(file));
                        if (Path.Exists(file))
                        {
                            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("cleanup link rejected");
                            File.Delete(file);
                        }
                    }
                    catch (Exception ex) { errors.Add(ex); }
                }
                foreach (string directory in directories.AsEnumerable().Reverse())
                {
                    try { CheckNoLinks(directory); Directory.Delete(directory, false); }
                    catch (Exception ex) { errors.Add(ex); }
                }
                if (errors.Count != 0) throw new AggregateException("owned-path cleanup failed", errors);
            }
        }
    }
}
