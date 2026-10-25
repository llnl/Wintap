using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Text.Json;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;
using com.espertech.esper.common.client;
using System.Reflection;

namespace Wintap.Tests
{
    // These tests deliberately block/limit a background writer. Concurrent EPL
    // code generation can starve its Task.Run worker and confound the 2s budget.
    [CollectionDefinition("Bounded attribution writer", DisableParallelization = true)]
    public class BoundedAttributionWriterCollection { }

    [Collection("Bounded attribution writer")]
    public class AttributionTraceTests
    {
        private static WintapMessage Message() => new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.File)
        { File = new WintapMessage.FileActivityObject { Path = "/proof", EventCount = 7, BytesRequested = 12 } };

        [Fact]
        public void RetryReceiptsReuseObjectIdWithoutMutatingPayload()
        {
            var stream = new MemoryStream();
            var trace = new BoundedAttributionTrace(stream);
            var message = Message();
            trace.Record(message, "owner-miss");
            message.PidHash = "canonical";
            trace.Record(message, "owner-resolved", 1);
            trace.Record(Message(), "owner-miss");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            var lines = System.Text.Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            using var first = JsonDocument.Parse(lines[0]);
            using var second = JsonDocument.Parse(lines[1]);
            using var third = JsonDocument.Parse(lines[2]);
            Assert.Equal(first.RootElement.GetProperty("EventId").GetInt64(), second.RootElement.GetProperty("EventId").GetInt64());
            Assert.NotEqual(first.RootElement.GetProperty("EventId").GetInt64(), third.RootElement.GetProperty("EventId").GetInt64());
            Assert.Equal(JsonValueKind.Null, first.RootElement.GetProperty("PidHash").ValueKind);
            Assert.Equal("canonical", second.RootElement.GetProperty("PidHash").GetString());
            Assert.Equal(7, second.RootElement.GetProperty("EventCount").GetInt32());
            Assert.Equal("/proof", message.File.Path);
            using var summary = JsonDocument.Parse(lines.Last());
            Assert.False(summary.RootElement.GetProperty("DurableFateProven").GetBoolean());
        }

        [Fact]
        public void ReceiptLimitAndPostCloseRefusalAreExplicit()
        {
            var trace = new BoundedAttributionTrace(new MemoryStream(), capacity: 16, maxRecords: 2);
            for (int i = 0; i < 5; i++) trace.Record(Message(), "test");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            trace.Record(Message(), "after-close");
            var counts = trace.Snapshot();
            Assert.Equal(2, counts.Accepted);
            Assert.Equal(4, counts.Refused);
            Assert.Equal(2, counts.Written);
        }

        [Fact]
        public void EscapedUnicodeBytesAndLongStringsAreBounded()
        {
            var stream = new MemoryStream();
            var trace = new BoundedAttributionTrace(stream, capacity: 16, maxBytes: 4096);
            var message = Message();
            message.File.Path = new string('\u2028', 10000);
            for (int i = 0; i < 5; i++) trace.Record(message, "test");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            var counts = trace.Snapshot();
            Assert.Equal(5, counts.Truncated);
            Assert.True(counts.ByteRefused > 0);
            Assert.True(stream.ToArray().Length <= 4096);
            Assert.Equal(10000, message.File.Path.Length);
        }

        [Fact]
        public void ThrowingQueueObserverDoesNotAlterAdmissionOrDelivery()
        {
            long clock = 0;
            var invoked = new List<int>();
            var queue = new AttributionRetryQueue((m, attempt) => invoked.Add(attempt), capacity: 1,
                clock: () => clock, startTimer: false, observer: (_, _, _, _) => throw new Exception("observer only"));
            Assert.True(queue.TrySchedule(Message(), 0));
            Assert.False(queue.TrySchedule(Message(), 0));
            clock = 1000;
            queue.Pump();
            queue.Shutdown();
            Assert.Equal(new[] { 1 }, invoked);
            var counts = Assert.Single(queue.SnapshotDiagnostics(), d => d.Stream == WintapMessage.MessageTypeEnum.File);
            Assert.Equal(1, counts.Scheduled);
            Assert.Equal(1, counts.CapacityRefused);
            Assert.Equal(0, counts.CallbackErrors);
        }

        private sealed class BrokenStream : MemoryStream
        {
            public override System.Threading.Tasks.ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
                System.Threading.CancellationToken cancellationToken = default) => throw new IOException("expected test failure");
        }

        [Fact]
        public void QueryAndProjectionReceiptsShareBudgetsAndLinkTheExactRawRow()
        {
            var stream = new MemoryStream();
            var trace = new BoundedAttributionTrace(stream, capacity: 16, maxRecords: 5, filePrefix: "/proof");
            EventBean bean = DispatchProxy.Create<EventBean, NetworkEndpointNormalizationTests.DictionaryEvent>();
            ((NetworkEndpointNormalizationTests.DictionaryEvent)(object)bean).Values = new Dictionary<string, object> {
                ["PID"] = 42, ["MessageType"] = "TcpConnection", ["activityType"] = "TcpIpSend",
                ["PidHash"] = "canonical", ["eventCount"] = 4L, ["firstSeen"] = 134373393392102215L,
                ["lastSeen"] = 134373393397154348L, ["srcIp"] = "192.168.252.48", ["srcPort"] = 22,
                ["destIp"] = "192.168.252.1", ["destPort"] = 62000, ["packetSize"] = 368L
            };
            var row = new ExpandoObject();
            trace.RecordQuery("query-listener-attached", "tcpconnectionserializer", "tcp.epl", "probe", "tcp-activity");
            trace.RecordProjection(bean, "tcp-projection-enter");
            trace.RecordProjection(bean, "tcp-projection-row-ready", row);
            trace.RecordRow(row, "serializer-accepted");
            trace.RecordProjection(bean, "tcp-projection-error", error: new string('e', 600));
            trace.RecordQuery("over-budget", "tcp", null, null);
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            var lines = System.Text.Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            using var entered = JsonDocument.Parse(lines[1]);
            using var ready = JsonDocument.Parse(lines[2]);
            using var saved = JsonDocument.Parse(lines[3]);
            Assert.Equal(entered.RootElement.GetProperty("ProjectionId").GetInt64(), ready.RootElement.GetProperty("ProjectionId").GetInt64());
            Assert.Equal(ready.RootElement.GetProperty("RowId").GetInt64(), saved.RootElement.GetProperty("RowId").GetInt64());
            Assert.Equal(4L, entered.RootElement.GetProperty("EventCount").GetInt64());
            Assert.Equal(134373393392102215L, entered.RootElement.GetProperty("FirstSeenEventTime").GetInt64());
            Assert.Empty((IDictionary<string, object>)row);
            Assert.Equal(1, trace.Snapshot().Truncated);
            Assert.Equal(1, trace.Snapshot().Refused);
            Assert.Equal(0, trace.Snapshot().ScopedOut);
        }

        [Fact]
        public void ShutdownBoundaryCountersShareTheBoundedObserverBudget()
        {
            var stream = new MemoryStream();
            var trace = new BoundedAttributionTrace(stream, capacity: 16, maxRecords: 2);
            trace.RecordBoundary("serializer-shutdown-begin", "tcpconnectionserializer", 2, 54, 1);
            trace.RecordBoundary("serializer-shutdown-end", "tcpconnectionserializer", 0, 54, 0, true);
            trace.RecordBoundary("over-budget", "tcpconnectionserializer");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            var lines = System.Text.Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            using var end = JsonDocument.Parse(lines[1]);
            Assert.Equal(0, end.RootElement.GetProperty("QueueDepth").GetInt64());
            Assert.Equal(54, end.RootElement.GetProperty("AcceptedTotal").GetInt64());
            Assert.True(end.RootElement.GetProperty("Complete").GetBoolean());
            Assert.Equal(1, trace.Snapshot().Refused);
        }

        [Fact]
        public void RowReceiptsCorrelateWithoutAddingRawSchemaFields()
        {
            var stream = new MemoryStream();
            var trace = new BoundedAttributionTrace(stream);
            dynamic row = new ExpandoObject();
            row.PID = 42; row.PidHash = "canonical"; row.File_Path = "/proof/item";
            row.EventCount = 7; row.BytesRequested = 12; row.FirstSeen = 133000000000000001L;
            row.LastSeen = 133000000000000019L; row.MessageType = "PROCESS_FILE";
            var before = ((IDictionary<string, object>)row).ToDictionary(p => p.Key, p => p.Value);
            trace.RecordRow(row, "serializer-accepted");
            trace.RecordRow(row, "parquet-finalized", "/output/proof.parquet");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            var lines = System.Text.Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            using var first = JsonDocument.Parse(lines[0]);
            using var final = JsonDocument.Parse(lines[1]);
            Assert.Equal(first.RootElement.GetProperty("RowId").GetInt64(), final.RootElement.GetProperty("RowId").GetInt64());
            Assert.Equal(133000000000000001L, final.RootElement.GetProperty("FirstSeenEventTime").GetInt64());
            Assert.Equal(7, final.RootElement.GetProperty("EventCount").GetInt64());
            Assert.Equal("/output/proof.parquet", final.RootElement.GetProperty("OutputPath").GetString());
            Assert.Equal(before.OrderBy(p => p.Key), ((IDictionary<string, object>)row).OrderBy(p => p.Key));
        }

        [Fact]
        public void PrefixScopeIsExplicitAndDoesNotExcludeNetworkOrRegistration()
        {
            var stream = new MemoryStream();
            var trace = new BoundedAttributionTrace(stream, filePrefix: "/proof");
            var message = Message(); message.File.Path = "/proof/item";
            trace.Record(message, "in-scope");
            message.File.Path = "/proof-other/item";
            trace.Record(message, "outside");
            dynamic row = new ExpandoObject(); row.File_Path = "/elsewhere/item";
            trace.RecordRow(row, "outside-row");
            trace.Record(new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.TcpConnection), "network");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            Assert.Equal(2, trace.Snapshot().ScopedOut);
            Assert.Equal(2, trace.Snapshot().Written);
            Assert.Equal(0, trace.Snapshot().Refused);
        }

        [Fact]
        public void DiagnosticBudgetIsExplicitAndInvalidBudgetFailsClosed()
        {
            Assert.Equal(new BoundedAttributionTrace.Limits(1024, 100000, 33554432), BoundedAttributionTrace.ParseLimits(null));
            Assert.Equal(new BoundedAttributionTrace.Limits(8192, 250000, 134217728), BoundedAttributionTrace.ParseLimits("diagnostic"));
            Assert.Equal(new BoundedAttributionTrace.Limits(32768, 250000, 134217728), BoundedAttributionTrace.ParseLimits("delivery"));
            Assert.Throws<ArgumentException>(() => BoundedAttributionTrace.ParseLimits("unlimited"));
        }

        [Fact]
        public void MalformedRowDoesNotMutatePayloadAndMarksHistoryIncomplete()
        {
            var trace = new BoundedAttributionTrace(new MemoryStream());
            dynamic row = new ExpandoObject(); row.EventCount = "not an integer";
            trace.RecordRow(row, "malformed");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            Assert.Equal(1, trace.Snapshot().Errors);
            Assert.Equal("not an integer", (string)row.EventCount);
        }

        private sealed class PausedStream : MemoryStream
        {
            internal readonly System.Threading.Tasks.TaskCompletionSource Entered = new(System.Threading.Tasks.TaskCreationOptions.RunContinuationsAsynchronously);
            internal readonly System.Threading.Tasks.TaskCompletionSource Release = new(System.Threading.Tasks.TaskCreationOptions.RunContinuationsAsynchronously);
            public override async System.Threading.Tasks.ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
                System.Threading.CancellationToken cancellationToken = default)
            {
                Entered.TrySetResult();
                await Release.Task;
                await base.WriteAsync(buffer, cancellationToken);
            }
        }

        [Fact]
        public void FullQueueRefusesWithoutWaitingAndCloseHasABoundedDeadline()
        {
            var stream = new PausedStream();
            var trace = new BoundedAttributionTrace(stream, capacity: 1);
            trace.Record(Message(), "first");
            Assert.True(stream.Entered.Task.Wait(TimeSpan.FromSeconds(2)));
            try
            {
                trace.Record(Message(), "buffered");
                trace.Record(Message(), "queue-full");
                Assert.Equal(1, trace.Snapshot().Refused);
                Assert.False(trace.Close(TimeSpan.FromMilliseconds(10)));
            }
            finally { stream.Release.TrySetResult(); }
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            Assert.Equal(2, trace.Snapshot().Written);
        }

        [Fact]
        public void IoFailureClosesObserverButNotTelemetry()
        {
            var trace = new BoundedAttributionTrace(new BrokenStream());
            var message = Message();
            trace.Record(message, "test");
            Assert.True(trace.Close(TimeSpan.FromSeconds(2)));
            Assert.Equal(1, trace.Snapshot().Errors);
            Assert.Equal(1, trace.Snapshot().DiscardedOnError);
            Assert.Equal(7, message.File.EventCount);
            trace.Record(message, "after-io-failure");
            Assert.Equal(1, trace.Snapshot().Refused);
        }
    }
}
