using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.platform.windows.collect.etw
{
    internal sealed class WindowsShellClientIdentity
    {
        internal WindowsShellClientIdentity(bool verified, int sessionId, string name, long startTime)
        {
            Verified = verified; SessionId = sessionId; Name = name; StartTime = startTime;
        }
        internal bool Verified { get; }
        internal int SessionId { get; }
        internal string Name { get; }
        internal long StartTime { get; }
    }

    /// <summary>Subscribes to console input ETW and emits verified cmd.exe submitted input.</summary>
    internal sealed class WindowsShellSensor : BaseWindowsSensor
    {
        private readonly object lifecycle = new object();
        private readonly object sessionGate = new object();
        private readonly Action<WintapMessage> emit;
        private readonly Func<int, long, WindowsShellClientIdentity> inspect;
        private TraceEventSession session;
        private Task consumer;
        private System.Threading.Timer reportTimer;
        private long providerEvents, inputEvents, submitted, filtered, decodeErrors;
        private int stopRequested;
        private bool sessionReleased;
        private long? lost;

        public WindowsShellSensor() : this(null, null) { }

        internal WindowsShellSensor(Action<WintapMessage> emit, Func<int, long, WindowsShellClientIdentity> inspect)
        {
            SensorName = "WindowsShell";
            CollectorType = CollectorTypeEnum.General; // Own provider subscription; not a shared kernel sensor.
            this.emit = emit ?? EventChannel.Send;
            this.inspect = inspect ?? InspectClient;
        }

        public override bool Start()
        {
            lock (lifecycle)
            {
                if (consumer != null)
                {
                    if (!consumer.IsCompleted) return true;
                    lock (sessionGate)
                    {
                        reportTimer?.Dispose(); reportTimer = null;
                        try { session?.Dispose(); } catch { }
                        session = null;
                        consumer = null;
                    }
                }
                if (!Properties.Settings.Default.WindowsShellSensor) return true;
                try
                {
                    // Never attach to or stop an operator-owned/pre-existing ETW session.
                    string name = "Wintap-WindowsShell-" + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N");
                    session = new TraceEventSession(name) { StopOnDispose = true };
                    sessionReleased = false;
                    var owned = session;
                    var source = owned.Source;
                    Volatile.Write(ref stopRequested, 0);
                    source.Dynamic.All += data =>
                    {
                        if (data.ProviderGuid != Provider) return;
                        Interlocked.Increment(ref providerEvents);
                        if (!IsSubmittedInputEvent(data.EventName, data.TaskName)) return;
                        Interlocked.Increment(ref inputEvents);
                        try
                        {
                            if (data.PayloadNames.Length > MaximumPayloadFields || data.EventDataLength > 256 * 1024)
                            {
                                Interlocked.Increment(ref decodeErrors);
                                return;
                            }
                            var fields = new Dictionary<string, object>(StringComparer.Ordinal);
                            foreach (string field in data.PayloadNames)
                            {
                                if (field == "ReadBuffer" || field == "AttachedProcessId" || field == "ReadBufferLength" || field == "AttachedProcessCreationTime")
                                    fields[field] = data.PayloadByName(field);
                            }
                            HandleDecoded(data.TimeStamp.ToUniversalTime(), fields);
                        }
                        catch { Interlocked.Increment(ref decodeErrors); }
                    };
                    source.UnhandledEvents += data =>
                    {
                        if (data.ProviderGuid == Provider) Interlocked.Increment(ref providerEvents);
                    };
                    // Microsoft.Windows.Console.Host (fe1ff234-1f09-50a8-d38d-c44fab43e818).
                    owned.EnableProvider(Provider, TraceEventLevel.Verbose, Keywords);
                    reportTimer = new System.Threading.Timer(_ => Report(owned), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
                    consumer = Task.Run(() =>
                    {
                        try { source.Process(); }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append("WindowsShell ETW reader ended: " + ex.GetType().Name, LogLevel.Warn);
                        }
                        finally
                        {
                            if (Volatile.Read(ref stopRequested) == 0)
                            {
                                // An unexpected reader exit must not leave its provider
                                // enabled with nobody draining the realtime buffers.
                                lock (sessionGate)
                                {
                                    reportTimer?.Dispose(); reportTimer = null;
                                    try { lost = owned.EventsLost; } catch { lost = null; }
                                    try { owned.Stop(); } catch { }
                                    try { owned.Dispose(); } catch { }
                                    sessionReleased = true;
                                    WintapLogger.Log.Append("WindowsShell ETW reader completed unexpectedly; owned session released", LogLevel.Warn);
                                    LogCounts();
                                }
                            }
                        }
                    });
                    WintapLogger.Log.Append("WindowsShell console input provider enabled; enablement is not emission proof", LogLevel.Info);
                    return true;
                }
                catch (Exception ex)
                {
                    try { session?.Dispose(); } catch { }
                    session = null;
                    WintapLogger.Log.Append("WindowsShell ETW startup failed: " + ex.GetType().Name, LogLevel.Warn);
                    return false;
                }
            }
        }

        /// <summary>Provider/event-filter seam for tests; header process IDs are never used.</summary>
        internal bool HandleInputEvent(Guid provider, string eventName, string taskName, DateTime timestamp,
            IReadOnlyDictionary<string, object> fields)
        {
            if (provider != Provider) return false;
            Interlocked.Increment(ref providerEvents);
            if (!IsSubmittedInputEvent(eventName, taskName)) return false;
            Interlocked.Increment(ref inputEvents);
            return HandleDecoded(timestamp, fields);
        }

        private bool HandleDecoded(DateTime timestamp, IReadOnlyDictionary<string, object> fields)
        {
            if (!TryCreateMessage(fields, timestamp, inspect, out WintapMessage message, out string status))
            {
                if (status == "client_unverified" || status == "not_cmd" || status == "creation_time_mismatch") Interlocked.Increment(ref filtered);
                else Interlocked.Increment(ref decodeErrors);
                return false;
            }
            try
            {
                emit(message);
                Interlocked.Increment(ref submitted);
                Counter++;
                return true;
            }
            catch { Interlocked.Increment(ref decodeErrors); return false; }
        }

        private void Report(TraceEventSession owned)
        {
            lock (sessionGate)
            {
                if (!ReferenceEquals(session, owned) || sessionReleased) return;
                try { lost = owned.EventsLost; } catch { lost = null; }
                LogCounts();
            }
        }

        private void LogCounts()
        {
            WintapLogger.Log.Append("WindowsShell providerEvents=" + Interlocked.Read(ref providerEvents) +
                ",inputEvents=" + Interlocked.Read(ref inputEvents) + ",submitted=" + Interlocked.Read(ref submitted) +
                ",filtered=" + Interlocked.Read(ref filtered) + ",decodeErrors=" + Interlocked.Read(ref decodeErrors) +
                ",attributionDrops=" + EventChannel.WindowsShellAttributionDrops + ",etwEventsLost=" + (lost.HasValue ? lost.Value.ToString() : "unknown"), LogLevel.Info);
        }

        public override void Stop()
        {
            lock (lifecycle)
            {
                if (session == null) return;
                Volatile.Write(ref stopRequested, 1);
                reportTimer?.Dispose(); reportTimer = null;
                lock (sessionGate)
                {
                    if (!sessionReleased)
                    {
                        try { lost = session.EventsLost; } catch { lost = null; }
                        // StopProcessing alone cannot unblock an idle realtime reader.
                        // Stop the exact owned session before joining its consumer.
                        try { session.Stop(); }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append("WindowsShell ETW stop failed: " + ex.GetType().Name, LogLevel.Warn);
                            try { session.Dispose(); } catch { }
                        }
                    }
                }
                if (consumer != null && !consumer.Wait(TimeSpan.FromSeconds(5)))
                {
                    WintapLogger.Log.Append("WindowsShell ETW consumer did not stop within 5 seconds; ownership retained", LogLevel.Warn);
                    return;
                }
                lock (sessionGate)
                {
                    try { session.Dispose(); }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append("WindowsShell ETW disposal failed: " + ex.GetType().Name, LogLevel.Warn);
                    }
                    session = null;
                    consumer = null;
                    LogCounts();
                }
            }
        }

        internal const int MaximumTextLength = 65536;
        internal const int MaximumPayloadFields = 64;
        internal static readonly Guid Provider = new Guid("fe1ff234-1f09-50a8-d38d-c44fab43e818");  // Microsoft.Windows.Console.Host
        internal const ulong Keywords = 0x1000;

        // These event names are defined by the console ETW provider.
        internal static bool IsSubmittedInputEvent(string name, string task) =>
            string.Equals(name, "CookedRead", StringComparison.Ordinal) ||
            (name != null && name.StartsWith("CookedRead/", StringComparison.Ordinal)) ||
            string.Equals(task, "CookedRead", StringComparison.Ordinal);

        internal static bool TryCreateMessage(IReadOnlyDictionary<string, object> fields, DateTime eventTimeUtc,
            Func<int, long, WindowsShellClientIdentity> inspect, out WintapMessage message, out string status)
        {
            message = null;
            status = "invalid_payload";
            if (fields == null || fields.Count > MaximumPayloadFields || inspect == null) return false;
            try
            {
                if (!fields.TryGetValue("ReadBuffer", out object rawText) || rawText is not string text || text.Length == 0 || text.Length > MaximumTextLength || text.IndexOf('\0') >= 0) return false;
                if (!fields.TryGetValue("AttachedProcessId", out object rawPid) || !TryInt32(rawPid, out int pid)) return false;
                if (pid <= 0) return false;
                if (fields.TryGetValue("ReadBufferLength", out object rawLength))
                {
                    if (!TryInt32(rawLength, out int length) || length != text.Length) return false;
                }
                status = "creation_time_unavailable";
                if (!fields.TryGetValue("AttachedProcessCreationTime", out object rawTime)) return false;
                DateTime creationTime = rawTime switch
                {
                    DateTime dt => dt.ToUniversalTime(),
                    DateTimeOffset dto => dto.UtcDateTime,
                    long filetime when filetime > 0 => DateTime.FromFileTimeUtc(filetime),
                    ulong filetime when filetime > 0 && filetime <= long.MaxValue => DateTime.FromFileTimeUtc((long)filetime),
                    _ => default
                };
                if (creationTime == default) return false;
                long startTime = creationTime.ToFileTimeUtc();
                if (startTime <= 0) return false;
                status = "invalid_timestamp";
                DateTime observed = eventTimeUtc.ToUniversalTime();
                if (observed == default || observed < creationTime) return false;
                _ = observed.ToFileTimeUtc();
                status = "client_unverified";
                WindowsShellClientIdentity identity = inspect(pid, startTime);
                if (identity == null || !identity.Verified) return false;
                status = "creation_time_mismatch";
                if (identity.StartTime != startTime) return false;
                status = "not_cmd";
                if (!string.Equals(identity.Name, "cmd", StringComparison.OrdinalIgnoreCase) && !string.Equals(identity.Name, "cmd.exe", StringComparison.OrdinalIgnoreCase)) return false;
                message = new WintapMessage(observed, pid, WintapMessage.MessageTypeEnum.WindowsShell)
                {
                    ActivityType = WintapMessage.ActivityTypeEnum.EventWritten,
                    WindowsShell = new WintapMessage.WindowsShellData
                    {
                        CommandText = text,
                        SessionId = identity.SessionId
                    }
                };
                // Match the attached client lifetime, since PIDs can be reused.
                ProcessAttribution.RecordExpectedProcessStart(message, startTime);
                status = "ok";
                return true;
            }
            catch (Exception)
            {
                // Exception text may contain provider text. Return only a bounded category.
                return false;
            }
        }

        private static bool TryInt32(object value, out int result)
        {
            result = 0;
            switch (value)
            {
                case int number: result = number; return true;
                case uint number when number <= int.MaxValue: result = (int)number; return true;
                case long number when number >= int.MinValue && number <= int.MaxValue: result = (int)number; return true;
                case ulong number when number <= int.MaxValue: result = (int)number; return true;
                case short number: result = number; return true;
                case ushort number: result = number; return true;
                case byte number: result = number; return true;
                case sbyte number: result = number; return true;
                default: return false;
            }
        }

        internal static WindowsShellClientIdentity InspectClient(int pid, long startTime)
        {
            try
            {
                using Process process = Process.GetProcessById(pid);
                // Holding the handle through all PID-based lookups prevents PID reuse.
                _ = process.SafeHandle;
                long actualStart = process.StartTime.ToUniversalTime().ToFileTimeUtc();
                if (actualStart != startTime) return new WindowsShellClientIdentity(false, 0, null, actualStart);
                return new WindowsShellClientIdentity(true, process.SessionId, process.ProcessName, actualStart);
            }
            catch { return new WindowsShellClientIdentity(false, 0, null, 0); }
        }
    }
}
