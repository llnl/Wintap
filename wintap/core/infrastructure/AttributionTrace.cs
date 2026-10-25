using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using gov.llnl.wintap.collect.models;
using com.espertech.esper.common.client;

namespace gov.llnl.wintap.core.infrastructure
{
    // Experimental observer, not telemetry or durable-fate evidence. No raw-schema IDs.
    internal static class AttributionTrace
    {
        private static readonly Lazy<BoundedAttributionTrace> writer = new(Create);
        private static BoundedAttributionTrace Create()
        {
            string path = Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_ATTRIBUTION_TRACE_PATH");
            if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(path)) return null;
            try
            {
                var limits = BoundedAttributionTrace.ParseLimits(
                    Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_TRACE_BUDGET"));
                return new BoundedAttributionTrace(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read),
                    limits.Capacity, limits.Records, limits.Bytes,
                    Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_TRACE_FILE_PREFIX"));
            }
            catch (Exception ex)
            {
                try { WintapLogger.Log.Append("Attribution trace disabled: " + ex.Message, LogLevel.Warn); } catch { }
                return null;
            }
        }

        internal static Action<WintapMessage, string, int, int> QueueObserver =>
            writer.Value == null ? null : (message, stage, attempt, pending) => Record(message, stage, attempt, pending);

        internal static void Record(WintapMessage message, string stage, int attempt = 0, int pending = -1)
        {
            try { writer.Value?.Record(message, stage, attempt, pending); } catch { }
        }

        internal static void RecordRow(ExpandoObject row, string stage, string outputPath = null)
        {
            try { writer.Value?.RecordRow(row, stage, outputPath); } catch { }
        }

        internal static bool Enabled => writer.Value != null;

        internal static void RecordBoundary(string stage, string component, long depth = -1,
            long accepted = -1, int callbacks = -1, bool? complete = null)
        {
            try { writer.Value?.RecordBoundary(stage, component, depth, accepted, callbacks, complete); } catch { }
        }

        internal static void RecordQuery(string stage, string serializer, string queryPath,
            string queryName, string statementName = null, string error = null)
        {
            try { writer.Value?.RecordQuery(stage, serializer, queryPath, queryName, statementName, error); } catch { }
        }

        internal static void RecordProjection(EventBean projection, string stage, ExpandoObject row = null, string error = null)
        {
            try { writer.Value?.RecordProjection(projection, stage, row, error); } catch { }
        }

        internal static void RecordRows(IEnumerable<ExpandoObject> rows, string stage, string outputPath = null)
        {
            try
            {
                if (writer.Value == null) return;
                foreach (var row in rows) writer.Value.RecordRow(row, stage, outputPath);
            }
            catch { }
        }

        internal static void Close()
        {
            if (!writer.IsValueCreated || writer.Value == null) return;
            bool finished = writer.Value.Close(TimeSpan.FromSeconds(2));
            try { WintapLogger.Log.Append($"Attribution trace: finished={finished},counts={JsonSerializer.Serialize(writer.Value.Snapshot())}; handoff is not durable output", LogLevel.Info); } catch { }
        }
    }

    internal sealed class BoundedAttributionTrace
    {
        internal sealed record Counts(long Accepted, long Refused, long Written, long ByteRefused,
            long Errors, long DiscardedOnError, long Truncated, long Bytes, bool Closed, long ScopedOut);
        internal sealed record Limits(int Capacity, int Records, long Bytes);
        internal static Limits ParseLimits(string value) => value switch
        {
            null or "" => new Limits(1024, 100000, 32 * 1024 * 1024),
            "diagnostic" => new Limits(8192, 250000, 128 * 1024 * 1024),
            "delivery" => new Limits(32768, 250000, 128 * 1024 * 1024),
            _ => throw new ArgumentException("Trace budget must be empty, diagnostic or delivery; attribution capacity is unaffected")
        };
        private sealed record Identity(long Id);
        private sealed record Receipt(long Sequence, long EventId, long UtcFiletime, long MonotonicTicks,
            string Stage, int Attempt, int Pending, int Pid, long EventTime, string Stream,
            string Activity, string PidHash, string Path, int? EventCount, int? BytesRequested,
            long? FirstSeenEventTime, long? LastSeenEventTime,
            string SourceAddress, int? SourcePort, string DestinationAddress, int? DestinationPort, long? PacketSize);
        private sealed record RowReceipt(long Sequence, long RowId, long UtcFiletime, long MonotonicTicks,
            string Stage, int Pid, string Stream, string Activity, string PidHash, string Path,
            long? EventCount, long? BytesRequested, long? FirstSeenEventTime, long? LastSeenEventTime,
            string ConnId, string SourceAddress, long? SourcePort, string DestinationAddress,
            long? DestinationPort, long? PacketSize, string OutputPath);
        private sealed record QueryReceipt(long Sequence, long UtcFiletime, long MonotonicTicks,
            string Stage, string Serializer, string QueryPath, string QueryName, string StatementName, string Error);
        private sealed record BoundaryReceipt(long Sequence, long UtcFiletime, long MonotonicTicks,
            string Stage, string Component, long QueueDepth, long AcceptedTotal, int ActiveCallbacks, bool? Complete);
        private sealed record ProjectionReceipt(long Sequence, long ProjectionId, long? RowId,
            long UtcFiletime, long MonotonicTicks, string Stage, int Pid, string Stream, string Activity,
            string PidHash, long? EventCount, long? FirstSeenEventTime, long? LastSeenEventTime,
            string SourceAddress, long? SourcePort, string DestinationAddress, long? DestinationPort,
            long? PacketSize, string Error);
        private readonly object gate = new();
        private readonly ConditionalWeakTable<object, Identity> identities = new();
        private readonly Channel<object> queue;
        private readonly Task worker;
        private readonly int maxRecords;
        private readonly long maxBytes;
        private readonly string filePrefix;
        private long scopedOut;
        private long nextId, sequence, accepted, refused, written, byteRefused, errors, discardedOnError, truncated, bytes;
        private bool closed;

        internal BoundedAttributionTrace(Stream output, int capacity = 1024,
            int maxRecords = 100000, long maxBytes = 32 * 1024 * 1024, string filePrefix = null)
        {
            if (capacity < 1 || maxRecords < 1 || maxBytes < 4096) throw new ArgumentOutOfRangeException();
            this.maxRecords = maxRecords;
            this.maxBytes = maxBytes;
            this.filePrefix = string.IsNullOrWhiteSpace(filePrefix) ? null : filePrefix.TrimEnd('/') + "/";
            if (this.filePrefix?.Length > 512) throw new ArgumentException("Trace file prefix exceeds 512 characters");
            queue = Channel.CreateBounded<object>(new BoundedChannelOptions(capacity)
                { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
            worker = Task.Run(async () =>
            {
                bool processingReceipt = false;
                try
                {
                    using (output)
                    {
                        await foreach (var receipt in queue.Reader.ReadAllAsync())
                        {
                            processingReceipt = true;
                            byte[] line = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(receipt) + "\n");
                            // Reserve space for the terminal summary. Refuse whole receipts, not partial JSON.
                            if (Interlocked.Read(ref bytes) + line.Length > maxBytes - 2048)
                            { Interlocked.Increment(ref byteRefused); processingReceipt = false; continue; }
                            await output.WriteAsync(line);
                            Interlocked.Add(ref bytes, line.Length);
                            Interlocked.Increment(ref written);
                            processingReceipt = false;
                        }
                        byte[] summary = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                        { Kind = "summary", RuleVersion = "attribution-trace-v2", StopwatchFrequency = Stopwatch.Frequency,
                            Limits = new { Capacity = capacity, MaxRecords = maxRecords, MaxBytes = maxBytes, StringLength = 512 },
                            FilePrefix = this.filePrefix,
                            Counts = Snapshot(), DurableFateProven = false }) + "\n");
                        await output.WriteAsync(summary);
                        Interlocked.Add(ref bytes, summary.Length);
                        await output.FlushAsync();
                    }
                }
                catch
                {
                    Interlocked.Increment(ref errors);
                    if (processingReceipt) Interlocked.Increment(ref discardedOnError);
                    lock (gate) { closed = true; queue.Writer.TryComplete(); }
                    // Drop buffered receipts on I/O failure; do not retain failed histories.
                    while (queue.Reader.TryRead(out _)) Interlocked.Increment(ref discardedOnError);
                    try { output.Dispose(); } catch { }
                }
            });
        }

        private string Clip(string value)
        {
            if (value == null || value.Length <= 512) return value;
            Interlocked.Increment(ref truncated);
            return value.Substring(0, 512);
        }

        internal void Record(WintapMessage message, string stage, int attempt = 0, int pending = -1)
        {
            if (message == null) return;
            try
            {
                lock (gate)
                {
                    if (closed || accepted >= maxRecords) { refused++; return; }
                    if (OutOfScope(message.File?.Path)) { scopedOut++; return; }
                    var id = identities.GetValue(message, _ => new Identity(++nextId));
                    var receipt = new Receipt(++sequence, id.Id, DateTime.UtcNow.ToFileTimeUtc(), Stopwatch.GetTimestamp(),
                        Clip(stage), attempt, pending, message.PID, message.EventTime, message.MessageType.ToString(),
                        message.ActivityType.ToString(), Clip(message.PidHash), Clip(message.File?.Path),
                        message.File?.EventCount, message.File?.BytesRequested,
                        message.File?.FirstSeenEventTime, message.File?.LastSeenEventTime,
                        Clip(message.TcpConnection?.SourceAddress), message.TcpConnection?.SourcePort,
                        Clip(message.TcpConnection?.DestinationAddress), message.TcpConnection?.DestinationPort,
                        message.TcpConnection?.PacketSize);
                    if (queue.Writer.TryWrite(receipt)) accepted++;
                    else refused++;
                }
            }
            catch { Interlocked.Increment(ref errors); }
        }

        private bool OutOfScope(string path) => filePrefix != null && path != null &&
            !path.StartsWith(filePrefix, StringComparison.Ordinal);

        internal void RecordBoundary(string stage, string component, long depth = -1,
            long acceptedTotal = -1, int callbacks = -1, bool? complete = null)
        {
            try
            {
                lock (gate)
                {
                    if (closed || accepted >= maxRecords) { refused++; return; }
                    var receipt = new BoundaryReceipt(++sequence, DateTime.UtcNow.ToFileTimeUtc(), Stopwatch.GetTimestamp(),
                        Clip(stage), Clip(component), depth, acceptedTotal, callbacks, complete);
                    if (queue.Writer.TryWrite(receipt)) accepted++;
                    else refused++;
                }
            }
            catch { Interlocked.Increment(ref errors); }
        }

        internal void RecordQuery(string stage, string serializer, string queryPath, string queryName,
            string statementName = null, string error = null)
        {
            try
            {
                lock (gate)
                {
                    if (closed || accepted >= maxRecords) { refused++; return; }
                    var receipt = new QueryReceipt(++sequence, DateTime.UtcNow.ToFileTimeUtc(), Stopwatch.GetTimestamp(),
                        Clip(stage), Clip(serializer), Clip(queryPath), Clip(queryName), Clip(statementName), Clip(error));
                    if (queue.Writer.TryWrite(receipt)) accepted++;
                    else refused++;
                }
            }
            catch { Interlocked.Increment(ref errors); }
        }

        internal void RecordProjection(EventBean projection, string stage, ExpandoObject row = null, string error = null)
        {
            if (projection == null) return;
            try
            {
                lock (gate)
                {
                    if (closed || accepted >= maxRecords) { refused++; return; }
                    var id = identities.GetValue(projection, _ => new Identity(++nextId));
                    long? rowId = row == null ? null : identities.GetValue(row, _ => new Identity(++nextId)).Id;
                    long? Number(string name) => projection[name] == null ? null : Convert.ToInt64(projection[name]);
                    var receipt = new ProjectionReceipt(++sequence, id.Id, rowId, DateTime.UtcNow.ToFileTimeUtc(),
                        Stopwatch.GetTimestamp(), Clip(stage), checked((int)(Number("PID") ?? 0)),
                        Clip(projection["MessageType"]?.ToString()), Clip(projection["activityType"]?.ToString()),
                        Clip(projection["PidHash"]?.ToString()), Number("eventCount"), Number("firstSeen"), Number("lastSeen"),
                        Clip(projection["srcIp"]?.ToString()), Number("srcPort"), Clip(projection["destIp"]?.ToString()),
                        Number("destPort"), Number("packetSize"), Clip(error));
                    if (queue.Writer.TryWrite(receipt)) accepted++;
                    else refused++;
                }
            }
            catch { Interlocked.Increment(ref errors); }
        }

        private static object Field(IDictionary<string, object> row, params string[] names)
        {
            foreach (string name in names)
                if (row.TryGetValue(name, out object value)) return value;
            return null;
        }
        private static string Text(IDictionary<string, object> row, params string[] names) => Field(row, names)?.ToString();
        private static long? Number(IDictionary<string, object> row, params string[] names)
        {
            object value = Field(row, names);
            return value == null ? null : Convert.ToInt64(value);
        }

        internal void RecordRow(ExpandoObject row, string stage, string outputPath = null)
        {
            if (row == null) return;
            try
            {
                lock (gate)
                {
                    if (closed || accepted >= maxRecords) { refused++; return; }
                    var fields = (IDictionary<string, object>)row;
                    string path = Text(fields, "File_Path", "Path");
                    if (OutOfScope(path)) { scopedOut++; return; }
                    var id = identities.GetValue(row, _ => new Identity(++nextId));
                    var receipt = new RowReceipt(++sequence, id.Id, DateTime.UtcNow.ToFileTimeUtc(), Stopwatch.GetTimestamp(),
                        Clip(stage), checked((int)(Number(fields, "PID") ?? 0)), Clip(Text(fields, "MessageType")),
                        Clip(Text(fields, "ActivityType")), Clip(Text(fields, "PidHash")), Clip(path),
                        Number(fields, "EventCount"), Number(fields, "BytesRequested"),
                        Number(fields, "FirstSeen", "FirstSeenMs", "EventTime"), Number(fields, "LastSeen", "LastSeenMs", "EventTime"),
                        Clip(Text(fields, "ConnId")), Clip(Text(fields, "SourceIpAddressString")), Number(fields, "SourcePort"),
                        Clip(Text(fields, "DestinationIpAddressString")), Number(fields, "DestinationPort"), Number(fields, "PacketSize"), Clip(outputPath));
                    if (queue.Writer.TryWrite(receipt)) accepted++;
                    else refused++;
                }
            }
            catch { Interlocked.Increment(ref errors); }
        }

        internal Counts Snapshot()
        {
            lock (gate) return new Counts(accepted, refused, Interlocked.Read(ref written),
                Interlocked.Read(ref byteRefused), Interlocked.Read(ref errors), Interlocked.Read(ref discardedOnError), Interlocked.Read(ref truncated),
                Interlocked.Read(ref bytes), closed, scopedOut);
        }

        internal bool Close(TimeSpan timeout)
        {
            lock (gate) { closed = true; queue.Writer.TryComplete(); }
            return worker.Wait(timeout);
        }
    }
}
