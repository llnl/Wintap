using System;
using System.Collections.Concurrent;
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
    [Trait("Category", "sfx-04")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessExecutionObservationTests
    {
        [Theory]
        [InlineData(0x00000000u, "exec_attempt")]
        [InlineData(0x00001000u, "exec_attempt")]
        [InlineData(0x80000000u, "exec_success")]
        [InlineData(0x80000001u, "exec_success")]
        public void ExecFlagsDistinguishAttemptFromSuccessfulImageTransition(
            uint flags, string expected)
        {
            Assert.Equal(expected, ExecveSensor.GetExecutionObservationKind(flags));
        }

        [Fact]
        public void AttemptedExecutableRemainsDistinctFromInstalledImageEvidence()
        {
            var info = new ProcReader.ProcessInfo
            {
                Exists = true,
                Name = "installed-image",
                ExecutablePath = "/synthetic/installed-image"
            };

            var attempted = ExecveSensor.SelectExecutableMetadata(
                "/synthetic/requested-image", "installed-image", info);
            var installed = ExecveSensor.SelectExecutableMetadata(
                "/synthetic/installed-image", "installed-image", info);

            Assert.Equal(("/synthetic/requested-image", "requested-image"), attempted);
            Assert.Equal("exec_attempt", ExecveSensor.GetExecutionObservationKind(0));
            Assert.Equal(("/synthetic/installed-image", "installed-image"), installed);
            Assert.Equal("exec_success", ExecveSensor.GetExecutionObservationKind(0x80000000u));
        }

        [Fact]
        public async Task NonExecProducerLeavesStableNullableDirectField()
        {
            WintapMessage.ProcessObject process = ProcessSensorHelper.CreateProcessObject(
                12345, 0, "fixture", "/synthetic/fixture", "", "synthetic-user");

            Assert.Null(process.ExecutionObservationKind);
            WintapMessage nonExecMessage = Message();
            nonExecMessage.Process = process;
            var nonExec = DirectParquetProjection.ToExpando(nonExecMessage);
            IDictionary<string, object> nonExecValues = nonExec;
            Assert.True(nonExecValues.ContainsKey("Process_ExecutionObservationKind"));
            Assert.Null(nonExecValues["Process_ExecutionObservationKind"]);

            ExpandoObject exec = DirectParquetProjection.ToExpando(Message());
            var recovered = await RoundTripMany(nonExec, exec);
            Assert.True(!recovered[0].TryGetValue("Process_ExecutionObservationKind", out object missing) || missing == null);
            Assert.Equal("exec_success", recovered[1]["Process_ExecutionObservationKind"]);
        }

        [Fact]
        public async Task NormalAndDirectParquetPreserveExecutionObservationKind()
        {
            WintapMessage message = Message();
            var serializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var queue = new ConcurrentQueue<ExpandoObject>();
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(typeof(ProcessSerializer), serializer, "host", new HostId { Hostname = "synthetic-host" });
            MethodInfo handler = typeof(ProcessSerializer).GetMethod(
                "handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            handler.Invoke(serializer, new object[] { message });

            IDictionary<string, object> normal = (IDictionary<string, object>)queue.Single();
            IDictionary<string, object> direct =
                (IDictionary<string, object>)DirectParquetProjection.ToExpando(message);
            Assert.Equal("exec_success", normal["ExecutionObservationKind"]);
            Assert.Equal("exec_success", direct["Process_ExecutionObservationKind"]);

            var normalRecovered = await RoundTrip((ExpandoObject)normal);
            var directRecovered = await RoundTrip((ExpandoObject)direct);
            Assert.Equal("exec_success", normalRecovered["ExecutionObservationKind"]);
            Assert.Equal("exec_success", directRecovered["Process_ExecutionObservationKind"]);
        }

        private static WintapMessage Message() => new(
            new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            12345, WintapMessage.MessageTypeEnum.Process)
        {
            ActivityType = WintapMessage.ActivityTypeEnum.Start,
            PidHash = "synthetic-pid-hash",
            AgentId = "synthetic-agent",
            Process = new WintapMessage.ProcessObject
            {
                PID = 12345,
                ParentPID = 0,
                ParentPidHash = "synthetic-parent-hash",
                Name = "fixture",
                Path = "/synthetic/fixture",
                CommandLine = "fixture --exact",
                User = string.Empty,
                Arguments = "PROC_START_SRC=sched_exec",
                ExecutionObservationKind = "exec_success"
            }
        };

        private static async Task<IDictionary<string, object>> RoundTrip(ExpandoObject row)
        {
            MethodInfo schemaMethod = typeof(ParquetWriter).GetMethod(
                "DetermineSchemaFromExpando", BindingFlags.Static | BindingFlags.NonPublic);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { row });
            using var stream = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(
                new[] { (IDictionary<string, object>)row }, schema, stream);
            stream.Position = 0;
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(stream);
            return recovered.Data.Single();
        }

        private static async Task<IReadOnlyList<IDictionary<string, object>>> RoundTripMany(
            params ExpandoObject[] rows)
        {
            MethodInfo schemaMethod = typeof(ParquetWriter).GetMethod(
                "DetermineSchemaFromExpando", BindingFlags.Static | BindingFlags.NonPublic);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { rows[0] });
            using var stream = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(
                rows.Cast<IDictionary<string, object>>().ToArray(), schema, stream);
            stream.Position = 0;
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(stream);
            return recovered.Data.ToArray();
        }

        private static void SetField(Type type, object target, string name, object value) =>
            type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(target, value);
    }
}
