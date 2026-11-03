using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.shared;

namespace gov.llnl.wintap.core.infrastructure
{
    /// <summary>Applies canonical identity with optional provider lifetime evidence.</summary>
    internal static class ProcessAttribution
    {
        // Lifetime evidence stays with the in-memory observation and is never serialized.
        private sealed class LifetimeEvidence
        {
            internal long? ProcessStart;
        }
        private static readonly ConditionalWeakTable<WintapMessage, LifetimeEvidence> lifetimes = new();

        internal static void RecordExpectedProcessStart(WintapMessage message, long? processStart)
            => lifetimes.GetOrCreateValue(message).ProcessStart = processStart;

        internal static bool TryApply(WintapMessage message, ProcessRecord owner,
            Func<int, long, bool> verifyLive = null, bool requireProcessStart = false)
        {
            if (message == null || owner == null || owner.ProcessId != message.PID ||
                string.IsNullOrWhiteSpace(owner.PidHash)) return false;

            if (!lifetimes.TryGetValue(message, out var evidence) || !evidence.ProcessStart.HasValue)
            {
                if (requireProcessStart) return false;
                message.PidHash = owner.PidHash;
                message.ProcessName = owner.ProcessName;
                return true;
            }
            if (owner.CreateTime == default) return false;

            long sourceStart = evidence.ProcessStart.Value;
            long canonicalStart = owner.CreateTime.ToUniversalTime().ToFileTimeUtc();
            if (message.EventTime < Math.Max(sourceStart, canonicalStart) ||
                (owner.ExitTime.HasValue && message.EventTime > owner.ExitTime.Value.ToUniversalTime().ToFileTimeUtc()))
                return false;

            if (sourceStart != canonicalStart)
            {
                // The source hash tolerates database timestamp rounding.
                string sourceHash = ProcessIdentity.Compute(Environment.MachineName, message.PID, sourceStart);
                if (string.Equals(owner.PidHash, sourceHash, StringComparison.OrdinalIgnoreCase))
                    canonicalStart = sourceStart;
                else
                {
                    // ETW start times can differ; confirm the live lifetime.
                    if (Math.Abs(sourceStart - canonicalStart) > ProcessResolver.LiveStartTimeMatchTolerance.Ticks ||
                        !string.Equals(owner.PidHash, ProcessIdentity.Compute(Environment.MachineName, message.PID, canonicalStart), StringComparison.OrdinalIgnoreCase) ||
                        !(verifyLive ?? VerifyLive)(message.PID, sourceStart))
                        return false;
                }
            }

            message.PidHash = owner.PidHash;
            message.ProcessName = owner.ProcessName;
            return true;
        }

        private static bool VerifyLive(int pid, long start)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                return !process.HasExited && process.StartTime.ToUniversalTime().ToFileTimeUtc() == start;
            }
            catch { return false; }
        }
    }
}
