using System;
using System.Runtime.InteropServices;

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
