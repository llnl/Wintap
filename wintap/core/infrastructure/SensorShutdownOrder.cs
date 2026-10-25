using System;
using System.Collections.Generic;
using System.Linq;

namespace gov.llnl.wintap.core.infrastructure
{
    // A dependent producer may still emit while Stop joins its sender/poller.
    // Keep identity producers alive until dependent producers have finished.
    internal static class SensorShutdownOrder
    {
        internal static IEnumerable<T> DependentsBeforeIdentity<T>(
            IEnumerable<T> collectors, Func<T, bool> isIdentityProducer)
        {
            // OrderBy is stable: preserve original order within each phase,
            // without mutating the startup list or stopping anything twice.
            return collectors.OrderBy(collector => isIdentityProducer(collector) ? 1 : 0);
        }
    }
}
