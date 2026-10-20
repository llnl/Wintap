using System;
using System.Threading;

namespace gov.llnl.wintap.core.etl.extract
{
    // One process-lifetime drain thread: shared thread-pool congestion must not
    // delay both the high-water request and its fallback timer.
    internal sealed class SerializerFlushWorker : IDisposable
    {
        private readonly AutoResetEvent signal = new(false);
        private readonly Func<bool> needsFlush;
        private readonly Action<string> flush;
        private readonly Action<Exception> onError;
        private readonly TimeSpan interval;
        private readonly Thread thread;
        private int requested;
        private int stopped;

        internal SerializerFlushWorker(TimeSpan interval, Func<bool> needsFlush, Action<string> flush, Action<Exception> onError, string serializerName = "serializer")
        {
            if (interval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(interval));
            this.interval = interval;
            this.needsFlush = needsFlush;
            this.flush = flush;
            this.onError = onError;
            thread = new Thread(Run) { IsBackground = true, Name = $"Wintap {serializerName} flush" };
            thread.Start();
        }

        internal void Request()
        {
            if (Volatile.Read(ref stopped) == 0 && Interlocked.CompareExchange(ref requested, 1, 0) == 0)
                signal.Set();
        }

        private void Run()
        {
            while (Volatile.Read(ref stopped) == 0)
            {
                bool highWater = signal.WaitOne(interval);
                if (Volatile.Read(ref stopped) != 0) break;
                try
                {
                    // A pending signal may be stale after a preceding drain.
                    if (!highWater || needsFlush()) flush(highWater ? "high_water" : "timer");
                    while (Volatile.Read(ref stopped) == 0 && needsFlush()) flush("high_water");
                }
                catch (Exception ex)
                {
                    onError(ex);
                    // A persistent fault must not turn into a hot retry/log loop.
                    Thread.Sleep((int)Math.Min(1000, Math.Max(1, interval.TotalMilliseconds)));
                }
                finally
                {
                    Interlocked.Exchange(ref requested, 0);
                }
                // Cover arrivals racing the final depth check/reset, without
                // queuing one task per event or losing the next wake-up.
                if (needsFlush()) Request();
            }
        }

        // Call after producers stop, just as for the serializer's other workers.
        public void Dispose()
        {
            if (Interlocked.Exchange(ref stopped, 1) != 0) return;
            signal.Set();
            thread.Join();
            signal.Dispose();
        }
    }
}
