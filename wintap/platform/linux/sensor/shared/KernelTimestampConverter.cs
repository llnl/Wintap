using System;
using System.Runtime.InteropServices;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Converts bpf_ktime_get_ns() timestamps to UTC without replacing event
    /// time with delayed userspace callback time.
    /// </summary>
    internal static class KernelTimestampConverter
    {
        private const int ClockRealtime = 0;
        private const int ClockMonotonic = 1;

        internal static long ComputeMonotonicToRealtimeOffsetNanoseconds()
        {
            if (clock_gettime(ClockRealtime, out Timespec realtime) != 0 ||
                clock_gettime(ClockMonotonic, out Timespec monotonic) != 0)
            {
                return 0;
            }

            return realtime.ToNanoseconds() - monotonic.ToNanoseconds();
        }

        internal static DateTime ToUtcDateTime(ulong timestampNs, long monotonicToRealtimeOffsetNs)
        {
            try
            {
                long realtimeNs = checked((long)timestampNs + monotonicToRealtimeOffsetNs);
                if (realtimeNs > 0)
                {
                    return DateTime.UnixEpoch.AddTicks(realtimeNs / 100).ToUniversalTime();
                }
            }
            catch
            {
            }

            return DateTime.UtcNow;
        }

        internal static bool TryToUtcFileTimeUtc(
            ulong timestampNs,
            long monotonicToRealtimeOffsetNs,
            out long fileTimeUtc)
        {
            fileTimeUtc = 0;
            if (timestampNs == 0 || monotonicToRealtimeOffsetNs == 0)
            {
                return false;
            }

            try
            {
                long realtimeNs = checked((long)timestampNs + monotonicToRealtimeOffsetNs);
                if (realtimeNs <= 0)
                {
                    return false;
                }

                fileTimeUtc = DateTime.UnixEpoch.AddTicks(realtimeNs / 100).ToFileTimeUtc();
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static void ApplyKernelProcessObservation(
            WintapMessage message,
            ulong timestampNs,
            long monotonicToRealtimeOffsetNs)
        {
            if (message?.Process == null || timestampNs == 0 || timestampNs > long.MaxValue)
            {
                return;
            }

            message.Process.ObservationTimeMonotonicNanoseconds = (long)timestampNs;
            message.Process.ObservationClockDomain = "linux-bpf-ktime-monotonic";
            message.Process.ObservationRunId = RuntimeCapabilities.GetCaptureRunId();
            if (TryToUtcFileTimeUtc(timestampNs, monotonicToRealtimeOffsetNs, out long fileTimeUtc))
            {
                message.Process.ObservationTimeFileTimeUtc = fileTimeUtc;
            }
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int clock_gettime(int clkId, out Timespec tp);

        [StructLayout(LayoutKind.Sequential)]
        private struct Timespec
        {
            public long TvSec;
            public long TvNsec;

            public long ToNanoseconds()
            {
                return checked(TvSec * 1_000_000_000L + TvNsec);
            }
        }
    }
}
