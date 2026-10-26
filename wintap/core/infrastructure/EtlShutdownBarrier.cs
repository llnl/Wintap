using System;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.infrastructure
{
    internal static class EtlShutdownBarrier
    {
        internal static bool Enabled(bool linux, string value) => linux &&
            (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1");

        // Terminal runtime-clock operation, not an event timestamp or OS clock
        // correction. Current bundled aggregation EPL has a 10,000ms horizon.
        // Freeze the timer first, then execute pending boundaries synchronously.
        // Timeout is a failed barrier, NEVER permission to drain live callbacks.
        internal static async Task FinishWindowsAsync(Action freeze, Func<long> currentTime,
            Action<long> advanceTimeSpan, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            await Task.Run(() =>
            {
                freeze();
                long start = currentTime();
                advanceTimeSpan(checked(start + 10000));
            }).WaitAsync(timeout, cancellationToken);
        }
    }
}
