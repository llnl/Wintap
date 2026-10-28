using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.platform.windows.collect.etw
{
    /// <summary>Native 4104 fragments routed through the standard event-time owner pipeline.</summary>
    internal sealed class PowerShellSensor : BaseWindowsSensor
    {
        internal static readonly Guid WindowsProvider = new("a0c1853b-5c40-4b15-8766-3cf1c58f985a");
        internal static readonly Guid CoreProvider = new("f90714a8-5509-434a-bf6d-b1624c8a19a2");
        internal const int ScriptBlockEventId = 4104;
        internal const int MaximumTextLength = 65536;
        private readonly object lifecycle = new(), sessionGate = new();
        private readonly Action<WintapMessage> emit;
        private readonly Func<bool> enabled;
        private TraceEventSession session;
        private Task consumer;
        private Timer reportTimer;
        private bool sessionReleased;
        private int stopRequested;
        private long providerEvents, selectedEvents, submitted, decodeErrors, unsupportedVersions, unhandledEvents;
        private long? eventsLost;

        public PowerShellSensor() : this(null, null) { }

        internal PowerShellSensor(Action<WintapMessage> emit, Func<bool> enabled = null)
        {
            SensorName = "PowerShell";
            CollectorType = CollectorTypeEnum.General;
            this.emit = emit ?? EventChannel.Send;
            this.enabled = enabled ?? (() => Properties.Settings.Default.PowerShellSensor);
        }

        internal static bool IsProvider(Guid provider) => provider == WindowsProvider || provider == CoreProvider;

        public override bool Start()
        {
            lock (lifecycle)
            {
                if (consumer != null)
                {
                    if (!consumer.IsCompleted) return Volatile.Read(ref stopRequested) == 0;
                    lock (sessionGate)
                    {
                        reportTimer?.Dispose(); reportTimer = null;
                        session?.Dispose(); session = null; consumer = null;
                    }
                }
                if (!enabled()) return true;
                try
                {
                    // Unique name: never attach to or stop an operator's session.
                    session = new TraceEventSession("Wintap-PowerShell-" + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"))
                    { StopOnDispose = true };
                    var owned = session;
                    var source = owned.Source;
                    sessionReleased = false;
                    Volatile.Write(ref stopRequested, 0);
                    source.Dynamic.All += ProcessEvent;
                    source.UnhandledEvents += data =>
                    {
                        if (!IsProvider(data.ProviderGuid)) return;
                        Interlocked.Increment(ref providerEvents);
                        Interlocked.Increment(ref unhandledEvents);
                    };
                    int providersEnabled = 0;
                    foreach (Guid provider in new[] { WindowsProvider, CoreProvider })
                    {
                        try
                        {
                            // Match the POC's native subscription. 4104 selection is
                            // downstream filtering, not a promise of reduced ETW traffic.
                            owned.EnableProvider(provider, (TraceEventLevel)255, ulong.MaxValue);
                            providersEnabled++;
                        }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append("PowerShell ETW enable failed for " + provider + ": " + ex.GetType().Name, LogLevel.Warn);
                        }
                    }
                    if (providersEnabled == 0) throw new InvalidOperationException("No PowerShell providers enabled");
                    consumer = Task.Run(() =>
                    {
                        try { source.Process(); }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append("PowerShell ETW reader ended: " + ex.GetType().Name, LogLevel.Warn);
                        }
                        finally
                        {
                            if (Volatile.Read(ref stopRequested) == 0)
                            {
                                lock (sessionGate)
                                {
                                    reportTimer?.Dispose(); reportTimer = null;
                                    CaptureLoss(owned);
                                    try { owned.Stop(); } catch { }
                                    try { owned.Dispose(); } catch { }
                                    sessionReleased = true;
                                    WintapLogger.Log.Append("PowerShell ETW reader completed unexpectedly; owned session released", LogLevel.Warn);
                                    LogCounts();
                                }
                            }
                        }
                    });
                    lock (sessionGate)
                    {
                        if (!sessionReleased)
                            reportTimer = new Timer(_ => Report(owned), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
                    }
                    WintapLogger.Log.Append("PowerShell ETW providers enabled=" + providersEnabled + "; enablement is not emission proof", LogLevel.Info);
                    return true;
                }
                catch (Exception ex)
                {
                    reportTimer?.Dispose(); reportTimer = null;
                    try { session?.Dispose(); } catch { }
                    session = null;
                    WintapLogger.Log.Append("PowerShell ETW startup failed: " + ex.GetType().Name, LogLevel.Warn);
                    return false;
                }
            }
        }

        private void ProcessEvent(TraceEvent data)
        {
            if (!IsProvider(data.ProviderGuid)) return;
            // Filter before materializing text or looking up payload fields.
            if ((int)data.ID != ScriptBlockEventId)
            {
                Interlocked.Increment(ref providerEvents);
                return;
            }
            if (data.Version != 1)
            {
                HandleEvent(data.ProviderGuid, (int)data.ID, data.Version, data.TimeStamp.ToUniversalTime(),
                    data.ProcessID, data.ThreadID, data.ActivityID, data.RelatedActivityID, null);
                return;
            }
            try
            {
                if (data.PayloadNames.Length > 64 || data.EventDataLength > 256 * 1024)
                    throw new InvalidOperationException("Oversized ETW payload");
                var fields = new Dictionary<string, object>(StringComparer.Ordinal);
                foreach (string name in data.PayloadNames)
                    if (name == "MessageNumber" || name == "MessageTotal" || name == "ScriptBlockText" || name == "ScriptBlockId" || name == "Path")
                        fields[name] = data.PayloadByName(name);
                HandleEvent(data.ProviderGuid, (int)data.ID, data.Version, data.TimeStamp.ToUniversalTime(),
                    data.ProcessID, data.ThreadID, data.ActivityID, data.RelatedActivityID, fields);
            }
            catch
            {
                // Never log exception payloads or script text.
                Interlocked.Increment(ref providerEvents);
                Interlocked.Increment(ref selectedEvents);
                Interlocked.Increment(ref decodeErrors);
            }
        }

        internal bool HandleEvent(Guid provider, int eventId, int version, DateTime timestamp,
            int pid, int tid, Guid activityId, Guid relatedActivityId, IReadOnlyDictionary<string, object> fields)
        {
            if (!IsProvider(provider)) return false;
            Interlocked.Increment(ref providerEvents);
            if (eventId != ScriptBlockEventId) return false;
            Interlocked.Increment(ref selectedEvents);
            if (version != 1) { Interlocked.Increment(ref unsupportedVersions); return false; }
            if (!TryCreateMessage(provider, eventId, version, timestamp, pid, tid, activityId, relatedActivityId, fields, out var message))
            {
                Interlocked.Increment(ref decodeErrors);
                return false;
            }
            try { emit(message); }
            catch { Interlocked.Increment(ref decodeErrors); return false; }
            Interlocked.Increment(ref submitted);
            Counter++;
            return true;
        }

        internal static bool TryCreateMessage(Guid provider, int eventId, int version, DateTime timestamp,
            int pid, int tid, Guid activityId, Guid relatedActivityId, IReadOnlyDictionary<string, object> fields,
            out WintapMessage message)
        {
            message = null;
            if (!IsProvider(provider) || eventId != ScriptBlockEventId || version != 1 || pid <= 0 || tid < 0 ||
                timestamp == default || fields == null || fields.Count > 64) return false;
            if (!fields.TryGetValue("MessageNumber", out var rawNumber) || rawNumber is not int number ||
                !fields.TryGetValue("MessageTotal", out var rawTotal) || rawTotal is not int total ||
                number < 1 || total < number ||
                !fields.TryGetValue("ScriptBlockText", out var rawText) || rawText is not string text || text.Length > MaximumTextLength ||
                !fields.TryGetValue("ScriptBlockId", out var rawId) || rawId is not string id || id.Length == 0 || id.Length > 128 ||
                !fields.TryGetValue("Path", out var rawPath) || rawPath is not string path || path.Length > 32768) return false;
            try
            {
                message = new WintapMessage(timestamp.ToUniversalTime(), pid, WintapMessage.MessageTypeEnum.PowerShell)
                {
                    ActivityType = WintapMessage.ActivityTypeEnum.EventWritten,
                    ActivityId = activityId == Guid.Empty ? "" : activityId.ToString("D"),
                    CorrelationId = relatedActivityId == Guid.Empty ? "" : relatedActivityId.ToString("D"),
                    PowerShell = new WintapMessage.PowerShellData
                    {
                        ProviderGuid = provider.ToString("D"), EventId = eventId, Version = version, ThreadId = tid,
                        MessageNumber = number, MessageTotal = total, ScriptBlockText = text, ScriptBlockId = id, Path = path
                    }
                };
                // No producer-created PidHash, live-process lookup or executable-name
                // filter: event-time attribution also works for exited/embedded hosts.
                return true;
            }
            catch (ArgumentOutOfRangeException) { message = null; return false; }
        }

        private void CaptureLoss(TraceEventSession owned)
        {
            try { eventsLost = owned.EventsLost; } catch { eventsLost = null; }
        }

        private void Report(TraceEventSession owned)
        {
            lock (sessionGate)
            {
                if (!ReferenceEquals(session, owned) || sessionReleased) return;
                CaptureLoss(owned);
                LogCounts();
            }
        }

        private void LogCounts() => WintapLogger.Log.Append("PowerShell providerEvents=" + Interlocked.Read(ref providerEvents) +
            ",selected4104=" + Interlocked.Read(ref selectedEvents) + ",submitted=" + Interlocked.Read(ref submitted) +
            ",decodeErrors=" + Interlocked.Read(ref decodeErrors) + ",unsupportedVersions=" + Interlocked.Read(ref unsupportedVersions) +
            ",unhandledEvents=" + Interlocked.Read(ref unhandledEvents) + ",etwEventsLost=" + (eventsLost?.ToString() ?? "unknown"), LogLevel.Info);

        public override void Stop()
        {
            lock (lifecycle)
            {
                if (session == null) return;
                Volatile.Write(ref stopRequested, 1);
                lock (sessionGate)
                {
                    reportTimer?.Dispose(); reportTimer = null;
                    if (!sessionReleased)
                    {
                        CaptureLoss(session);
                        try { session.Stop(); }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append("PowerShell ETW stop failed: " + ex.GetType().Name, LogLevel.Warn);
                            try { session.Dispose(); } catch { }
                        }
                    }
                }
                if (consumer != null && !consumer.Wait(TimeSpan.FromSeconds(5)))
                {
                    WintapLogger.Log.Append("PowerShell ETW consumer did not stop within 5 seconds; ownership retained", LogLevel.Warn);
                    return;
                }
                lock (sessionGate)
                {
                    try { session.Dispose(); }
                    catch (Exception ex) { WintapLogger.Log.Append("PowerShell ETW disposal failed: " + ex.GetType().Name, LogLevel.Warn); }
                    session = null; consumer = null;
                    LogCounts();
                }
            }
        }
    }
}
