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
        internal const int DefaultCapacity = 1024;

        internal static int ExperimentalCapacity(string configured, bool isLinux)
        {
            // Diagnostic sensitivity control, never a package default change.
            if (!isLinux || string.IsNullOrEmpty(configured)) return DefaultCapacity;
            return configured switch
            {
                "1024" => DefaultCapacity,
                "2048" => 2048,
                "4096" => 4096,
                _ => throw new ArgumentException("Experimental attribution retry capacity must be 1024, 2048 or 4096")
            };
        }
        private readonly object gate = new object(), pumpGate = new object();
        private readonly Queue<(WintapMessage Message, int Attempt, long Due)> pending = new();
        private readonly Action<WintapMessage, int> retry;
        private readonly Action<Exception> onError;
        private readonly Action<WintapMessage, string, int, int> observer;
        private readonly Func<long> clock;
        private readonly int capacity;
        private readonly HashSet<WintapMessage.MessageTypeEnum> streams;
        private readonly Timer timer;
        private bool stopped;
        private readonly Dictionary<WintapMessage.MessageTypeEnum, Counts> counts = new();

        // Cumulative, bounded by configured enum streams; no PID/path payloads.
        internal sealed record Diagnostics(WintapMessage.MessageTypeEnum Stream,
            long Scheduled, long CapacityRefused, long StoppedRefused, long Exhausted,
            long Invoked, long CallbackErrors, long ShutdownInvoked, int Pending, int HighWater);
        private sealed class Counts
        {
            internal long Scheduled, CapacityRefused, StoppedRefused, Exhausted,
                Invoked, CallbackErrors, ShutdownInvoked;
            internal int Pending, HighWater;
        }

        internal Diagnostics[] SnapshotDiagnostics()
        {
            lock (gate)
            {
                var result = new List<Diagnostics>();
                foreach (var pair in counts)
                {
                    var c = pair.Value;
                    result.Add(new Diagnostics(pair.Key, c.Scheduled, c.CapacityRefused,
                        c.StoppedRefused, c.Exhausted, c.Invoked, c.CallbackErrors,
                        c.ShutdownInvoked, c.Pending, c.HighWater));
                }
                return result.ToArray();
            }
        }

        internal AttributionRetryQueue(Action<WintapMessage, int> retry,
            int capacity = DefaultCapacity, Func<long> clock = null, bool startTimer = true,
            Action<Exception> onError = null, string enabledStreams = null,
            Action<WintapMessage, string, int, int> observer = null)
        {
            streams = ParseStreams(enabledStreams);
            foreach (var stream in streams) counts.Add(stream, new Counts());
            this.retry = retry ?? throw new ArgumentNullException(nameof(retry));
            this.capacity = Math.Max(0, capacity);
            this.clock = clock ?? (() => Environment.TickCount64);
            this.onError = onError;
            this.observer = observer;
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
            if (message == null || !streams.Contains(message.MessageType)) return false;
            lock (gate)
            {
                var c = counts[message.MessageType];
                if (stopped) { c.StoppedRefused++; Observe(message, "retry-stopped-refused", completedAttempts); return false; }
                if (completedAttempts >= MaxAttempts) { c.Exhausted++; Observe(message, "retry-exhausted", completedAttempts); return false; }
                if (pending.Count >= capacity) { c.CapacityRefused++; Observe(message, "retry-capacity-refused", completedAttempts); return false; }
                pending.Enqueue((message, completedAttempts + 1, clock() + 1000));
                c.Scheduled++;
                c.Pending++;
                c.HighWater = Math.Max(c.HighWater, c.Pending);
                Observe(message, "retry-admitted", completedAttempts);
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
                        counts[item.Message.MessageType].Pending--;
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
                    while (pending.Count > 0)
                    {
                        var message = pending.Dequeue().Message;
                        counts[message.MessageType].Pending--;
                        drain.Add(message);
                    }
                }
                // One final attempt with the best available identity; no requeue on shutdown.
                foreach (var message in drain) Invoke(message, MaxAttempts, shutdown: true);
            }
        }

        private void Invoke(WintapMessage message, int attempt, bool shutdown = false)
        {
            lock (gate)
            {
                counts[message.MessageType].Invoked++;
                if (shutdown) counts[message.MessageType].ShutdownInvoked++;
                Observe(message, shutdown ? "retry-shutdown-invoked" : "retry-invoked", attempt);
            }
            try { retry(message, attempt); }
            catch (Exception ex)
            {
                lock (gate) counts[message.MessageType].CallbackErrors++;
                lock (gate) Observe(message, "retry-callback-error", attempt);
                try { onError?.Invoke(ex); } catch { }
            }
        }

        // Diagnostic observer cannot change admission or callback behavior. Called under gate.
        private void Observe(WintapMessage message, string stage, int attempt)
        {
            if (observer == null) return;
            try { observer(message, stage, attempt, pending.Count); } catch { }
        }
    }
}
