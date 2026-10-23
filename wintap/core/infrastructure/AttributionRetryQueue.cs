using System;
using System.Collections.Generic;
using System.Threading;
using gov.llnl.wintap.collect.models;

namespace gov.llnl.wintap.core.infrastructure
{
    // Retry selected streams whose process identity may arrive later. Preserve
    // original event/receive timestamps and emit only after resolution or exhaustion.
    internal sealed class AttributionRetryQueue
    {
        // Short-lived Linux children can emit file activity before their Clone /
        // Execve lifecycle records clear the independent ring-buffer pollers.
        // At the default one-second interval, three attempts exhausted under a
        // measured rapid-fork workload; retain events for ten seconds, bounded
        // by the queue capacity, before emitting an Unknown identity.
        internal const int MaxAttempts = 10;
        private readonly object gate = new object(), pumpGate = new object();
        private readonly Queue<(WintapMessage Message, int Attempt, long Due)> pending = new();
        private readonly Action<WintapMessage, int> retry;
        private readonly Action<Exception> onError;
        private readonly Func<long> clock;
        private readonly int capacity;
        private readonly HashSet<WintapMessage.MessageTypeEnum> streams;
        private readonly Timer timer;
        private bool stopped;

        internal AttributionRetryQueue(Action<WintapMessage, int> retry,
            int capacity = 1024, Func<long> clock = null, bool startTimer = true,
            Action<Exception> onError = null, string enabledStreams = null)
        {
            streams = ParseStreams(enabledStreams);
            this.retry = retry ?? throw new ArgumentNullException(nameof(retry));
            this.capacity = Math.Max(0, capacity);
            this.clock = clock ?? (() => Environment.TickCount64);
            this.onError = onError;
            if (startTimer) timer = new Timer(_ => Pump(), null, 100, 100);
        }

        internal static HashSet<WintapMessage.MessageTypeEnum> ParseStreams(string configured)
        {
            var result = new HashSet<WintapMessage.MessageTypeEnum>();
            // File and network callbacks can race Linux lifecycle callbacks on
            // independent ring-buffer pollers. Retry those bounded streams by
            // default so a just-arrived Clone/Execve record can establish the
            // owner before an Unknown identity is emitted.
            foreach (string token in (configured ?? "Registry,File,TcpConnection,UdpPacket").Split(','))
            {
                string name = token.Trim();
                if (name.Length == 0 || name.Equals("none", StringComparison.OrdinalIgnoreCase)) continue;
                if (!Enum.TryParse(name, true, out WintapMessage.MessageTypeEnum stream) ||
                    !Enum.IsDefined(typeof(WintapMessage.MessageTypeEnum), stream) ||
                    !name.Equals(stream.ToString(), StringComparison.OrdinalIgnoreCase) ||
                    stream == WintapMessage.MessageTypeEnum.Process ||
                    stream == WintapMessage.MessageTypeEnum.ProcessPartial)
                    throw new ArgumentException("Invalid attribution retry stream: " + name, nameof(configured));
                result.Add(stream);
            }
            return result;
        }

        internal bool TrySchedule(WintapMessage message, int completedAttempts)
        {
            if (message == null || !streams.Contains(message.MessageType) ||
                completedAttempts >= MaxAttempts) return false;
            lock (gate)
            {
                if (stopped || pending.Count >= capacity) return false;
                pending.Enqueue((message, completedAttempts + 1, clock() + 1000));
                return true;
            }
        }

        internal void Pump()
        {
            // Never accumulate overlapping timer callbacks behind a slow downstream send.
            if (!Monitor.TryEnter(pumpGate)) return;
            try
            {
                int remaining;
                lock (gate) remaining = pending.Count;
                while (remaining-- > 0)
                {
                    (WintapMessage Message, int Attempt, long Due) item;
                    lock (gate)
                    {
                        if (stopped || pending.Count == 0 || pending.Peek().Due > clock()) break;
                        item = pending.Dequeue();
                    }
                    Invoke(item.Message, item.Attempt);
                }
            }
            finally { Monitor.Exit(pumpGate); }
        }

        internal void Shutdown()
        {
            timer?.Dispose();
            lock (pumpGate)
            {
                List<WintapMessage> drain = new();
                lock (gate)
                {
                    stopped = true;
                    while (pending.Count > 0) drain.Add(pending.Dequeue().Message);
                }
                // One final attempt with the best available identity; no requeue on shutdown.
                foreach (var message in drain) Invoke(message, MaxAttempts);
            }
        }

        private void Invoke(WintapMessage message, int attempt)
        {
            try { retry(message, attempt); }
            catch (Exception ex) { try { onError?.Invoke(ex); } catch { } }
        }
    }
}
