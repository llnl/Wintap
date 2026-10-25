using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace gov.llnl.wintap.platform.linux.collect
{
    // Experimental annotations are separate from raw process identity and never
    // suppress telemetry. No alternate process hash definition lives here.
    internal static class LinuxLifecycleEvidence
    {
        internal const int LegacyExitSize = 48;
        internal const int ExtendedExitSize = 64;
        internal const int LegacyCloneSize = 48;
        internal const int ExtendedCloneSize = 56;

        internal static ulong ReadCloneStart(IntPtr data, ulong size)
        {
            if (size != LegacyCloneSize && size != ExtendedCloneSize)
                throw new ArgumentException("Unsupported Linux clone event ABI size: " + size);
            return size == LegacyCloneSize ? 0 : unchecked((ulong)Marshal.ReadInt64(data, 48));
        }

        internal static DateTime? SelectBirthStart(DateTime? kernelStartUtc, DateTime procStartUtc)
        {
            // Kernel task birth wins over callback-time /proc, which can refer
            // to a reused PID. Neither fork occurrence nor callback time is birth.
            return kernelStartUtc ?? (procStartUtc == default ? null : procStartUtc.ToUniversalTime());
        }

        internal static (ulong BootNs, ulong MonotonicNs) ReadStartTimes(IntPtr data, ulong size)
        {
            if (size != LegacyExitSize && size != ExtendedExitSize)
                throw new ArgumentException("Unsupported Linux exit event ABI size: " + size);
            return size == LegacyExitSize ? (0, 0) :
                (unchecked((ulong)Marshal.ReadInt64(data, 48)), unchecked((ulong)Marshal.ReadInt64(data, 56)));
        }

        internal static string SelectExitHash(string historyHash, string liveHash,
            DateTime? canonicalStartUtc, Func<long, string> hashStart, string unknownHash)
        {
            if (!string.IsNullOrWhiteSpace(historyHash)) return historyHash;
            if (!string.IsNullOrWhiteSpace(liveHash)) return liveHash;
            return canonicalStartUtc.HasValue ? hashStart(canonicalStartUtc.Value.ToFileTimeUtc()) : unknownHash;
        }

        internal static LifetimeObservation Classify(int pid, string pidHash, string identitySource,
            string processName, uint uid, ulong exitNs, ulong startNs, ulong startBootNs)
        {
            ulong? duration = startNs > 0 && exitNs >= startNs ? exitNs - startNs : null;
            string bin = !duration.HasValue ? "unknown" : duration.Value < 100_000_000 ? "lt100ms" :
                duration.Value <= 1_000_000_000 ? "100ms-1s" : duration.Value <= 10_000_000_000 ? "1s-10s" : "gt10s";
            // Names are weak role evidence, not a benign/security verdict.
            string name = Path.GetFileName(processName ?? "").ToLowerInvariant();
            string role = name is "sh" or "bash" or "dash" or "grep" or "sed" or "cat" ? "shell-utility" :
                name is "mandb" or "dpkg" or "apt" or "apt-get" ? "package-helper" :
                name.StartsWith("python", StringComparison.Ordinal) ? "interpreter" : "unknown";
            return new LifetimeObservation(pid, pidHash, identitySource, processName, uid,
                exitNs, startNs, startBootNs, duration, bin,
                !duration.HasValue ? "unknown" : duration.Value <= 1_000_000_000 ? "short-lived" : "longer-lived",
                "leader-exit", role, role == "unknown" ? "none" : "low", "lifetime-shadow-v1");
        }
    }

    internal sealed record LifetimeObservation(int Pid, string PidHash, string IdentitySource,
        string ProcessName, uint Uid, ulong ExitMonotonicNs, ulong StartMonotonicNs,
        ulong StartBootNs, ulong? DurationNs, string LifetimeBin, string LifetimeClass,
        string ExitSemantics, string RoleClass, string RoleConfidence, string RuleVersion)
    {
        public bool ExitEvidenceRetained { get; init; }
        public string LifecycleCoverage { get; init; } = "not-assessed";
    }

    internal sealed class LifecycleShadowWriter : IDisposable
    {
        private readonly Channel<LifetimeObservation> queue;
        private readonly Task worker;
        private long accepted, refused;

        internal LifecycleShadowWriter(string path, int capacity = 1024)
        {
            // Refuse overwriting prior evidence. Startup errors are visible.
            var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read));
            queue = Channel.CreateBounded<LifetimeObservation>(new BoundedChannelOptions(capacity)
            { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
            worker = Task.Run(async () =>
            {
                using (output)
                {
                    await foreach (var observation in queue.Reader.ReadAllAsync())
                        await output.WriteLineAsync(JsonSerializer.Serialize(observation));
                    await output.WriteLineAsync(JsonSerializer.Serialize(new
                    { Kind = "summary", Accepted = accepted, Refused = refused, RuleVersion = "lifetime-shadow-v1" }));
                }
            });
        }

        internal bool TryWrite(LifetimeObservation observation)
        {
            if (worker.IsFaulted || !queue.Writer.TryWrite(observation))
            { Interlocked.Increment(ref refused); return false; }
            Interlocked.Increment(ref accepted);
            return true;
        }

        public void Dispose()
        {
            queue.Writer.TryComplete();
            worker.GetAwaiter().GetResult();
        }
    }
}
