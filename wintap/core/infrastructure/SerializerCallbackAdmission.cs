using System;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.infrastructure
{
    // Terminal experimental cutoff: no payload storage, no waiting while holding
    // the counter lock, and in-flight callbacks keep their original output path.
    internal sealed class SerializerCallbackAdmission
    {
        private readonly object gate = new();
        private readonly TaskCompletionSource<bool> drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int active;
        private bool closed;

        internal bool TryEnter()
        {
            lock (gate)
            {
                if (closed) return false;
                active++;
                return true;
            }
        }

        internal void Exit()
        {
            lock (gate)
            {
                if (active == 0) throw new InvalidOperationException("Unbalanced serializer callback exit");
                active--;
                if (closed && active == 0) drained.TrySetResult(true);
            }
        }

        internal Task Close()
        {
            lock (gate)
            {
                closed = true;
                if (active == 0) drained.TrySetResult(true);
                return drained.Task;
            }
        }
    }
}
