using System;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.infrastructure
{
    internal static class EtlStartupReadiness
    {
        // Experimental Linux control, not a change to Windows startup policy.
        internal static bool Enabled(bool isLinux, string value) => isLinux &&
            (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1");

        internal static async Task RequireAsync(Task<bool> ready, TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            if (ready == null) throw new InvalidOperationException("ETL readiness task unavailable");
            if (!await ready.WaitAsync(timeout, cancellationToken))
                throw new InvalidOperationException("ETL query/callback initialization failed; producers must not start");
        }
    }
}
