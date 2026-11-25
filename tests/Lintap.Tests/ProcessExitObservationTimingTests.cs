using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.shared.helpers;
using gov.llnl.wintap.platform.linux.collect;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Lintap.Tests
{
    [Trait("Category", "sfx-07")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessExitObservationTimingTests
    {
        [Theory]
        [InlineData(1_700_000_000_000_000_000L, true)]
        [InlineData(0L, false)]
        public void ExitObservationPreservesEventTimeAndIdentity(long offset, bool expectUtc)
        {
            WintapMessage message = Message(null, null, null, null, 101);
            long eventTime = message.EventTime;
            string pidHash = message.PidHash;

            ExitSensor.ApplyObservationTiming(message, 1_000_000_099, offset);

            Assert.Equal(eventTime, message.EventTime);
            Assert.Equal(pidHash, message.PidHash);
            Assert.Equal(1_000_000_099, message.Process.ObservationTimeMonotonicNanoseconds);
            Assert.Equal("linux-bpf-ktime-monotonic", message.Process.ObservationClockDomain);
            Assert.False(string.IsNullOrWhiteSpace(message.Process.ObservationRunId));
            Assert.Equal(expectUtc, message.Process.ObservationTimeFileTimeUtc.HasValue);
        }

        [Fact]
        public async Task NullFirstNormalStopProjectionRetainsObservationTiming()
        {
            ProcessTerminateData missing = Project(Message(null, null, null, null, 101));
            ProcessTerminateData populated = Project(Message(
                133801632000000001, 987654321, "linux-bpf-ktime-monotonic",
                "synthetic-run", 202));
            ExpandoObject[] rows = { missing.ToDynamic(), populated.ToDynamic() };
            MethodInfo schemaMethod = typeof(ParquetWriter).GetMethod(
                "DetermineSchemaFromExpando", BindingFlags.Static | BindingFlags.NonPublic);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { rows[0] });
            DataField utc = schema.GetDataFields().Single(
                field => field.Name == "ObservationTimeFileTimeUtc");
            DataField monotonic = schema.GetDataFields().Single(
                field => field.Name == "ObservationTimeMonotonicNanoseconds");
            Assert.True(utc.IsNullable);
            Assert.True(monotonic.IsNullable);

            using var stream = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(
                rows.Cast<IDictionary<string, object>>().ToArray(), schema, stream);
            stream.Position = 0;
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(stream);

            Assert.Equal(101L, Convert.ToInt64(recovered.Data[0]["ReceiveTime"]));
            Assert.False(recovered.Data[0].ContainsKey("ObservationTimeFileTimeUtc"));
            Assert.Equal(202L, Convert.ToInt64(recovered.Data[1]["ReceiveTime"]));
            Assert.Equal(133801632000000001L,
                Convert.ToInt64(recovered.Data[1]["ObservationTimeFileTimeUtc"]));
            Assert.Equal(987654321L,
                Convert.ToInt64(recovered.Data[1]["ObservationTimeMonotonicNanoseconds"]));
            Assert.Equal("linux-bpf-ktime-monotonic",
                recovered.Data[1]["ObservationClockDomain"]);
            Assert.Equal("synthetic-run", recovered.Data[1]["ObservationRunId"]);
        }

        [Fact]
        public void DirectStopProjectionRetainsObservationTiming()
        {
            WintapMessage message = Message(
                133801632000000001, 987654321, "linux-bpf-ktime-monotonic",
                "synthetic-run", 303);
            IDictionary<string, object> row = DirectParquetProjection.ToExpando(message);

            Assert.Equal(303L, row["ReceiveTime"]);
            Assert.Equal(133801632000000001L, row["Process_ObservationTimeFileTimeUtc"]);
            Assert.Equal(987654321L, row["Process_ObservationTimeMonotonicNanoseconds"]);
            Assert.Equal("linux-bpf-ktime-monotonic", row["Process_ObservationClockDomain"]);
            Assert.Equal("synthetic-run", row["Process_ObservationRunId"]);
        }

        private static ProcessTerminateData Project(WintapMessage message)
        {
            var serializer = (ProcessStopSerializer)RuntimeHelpers.GetUninitializedObject(
                typeof(ProcessStopSerializer));
            typeof(ProcessStopSerializer).GetField(
                "host", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(
                serializer, new HostId { Hostname = "synthetic-host" });
            MethodInfo create = typeof(ProcessStopSerializer).GetMethod(
                "createProcessTerminate", BindingFlags.Instance | BindingFlags.NonPublic);
            return (ProcessTerminateData)create.Invoke(serializer, new object[] { message });
        }

        private static WintapMessage Message(
            long? utc, long? monotonic, string domain, string runId, long receiveTime) => new(
            new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            12345, WintapMessage.MessageTypeEnum.Process)
        {
            ActivityType = WintapMessage.ActivityTypeEnum.Stop,
            PidHash = "synthetic-pid-hash",
            AgentId = "synthetic-agent",
            ProcessName = "fixture",
            ReceiveTime = receiveTime,
            Process = new WintapMessage.ProcessObject
            {
                PID = 12345,
                ParentPID = 0,
                ParentPidHash = "synthetic-parent-hash",
                Name = "fixture",
                Path = "/synthetic/fixture",
                User = string.Empty,
                ObservationTimeFileTimeUtc = utc,
                ObservationTimeMonotonicNanoseconds = monotonic,
                ObservationClockDomain = domain,
                ObservationRunId = runId
            }
        };
    }
}
