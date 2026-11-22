using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.platform.linux.collect;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Lintap.Tests
{
    [Trait("Category", "sfx-02")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessObservationTimingTests
    {
        [Fact]
        public void KernelObservationPreservesRawNanosecondOrderingWithoutChangingBirthIdentity()
        {
            DateTime birth = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var first = Message(birth, "same-hash");
            var second = Message(birth, "same-hash");
            const long offset = 1_700_000_000_000_000_000L;

            KernelTimestampConverter.ApplyKernelProcessObservation(first, 1_000_000_001, offset);
            KernelTimestampConverter.ApplyKernelProcessObservation(second, 1_000_000_099, offset);

            Assert.Equal(first.EventTime, second.EventTime);
            Assert.Equal("same-hash", first.PidHash);
            Assert.Equal("same-hash", second.PidHash);
            Assert.Equal(1_000_000_001, first.Process.ObservationTimeMonotonicNanoseconds);
            Assert.Equal(1_000_000_099, second.Process.ObservationTimeMonotonicNanoseconds);
            Assert.Equal(first.Process.ObservationTimeFileTimeUtc, second.Process.ObservationTimeFileTimeUtc);
            Assert.Equal("linux-bpf-ktime-monotonic", first.Process.ObservationClockDomain);
            Assert.False(string.IsNullOrWhiteSpace(first.Process.ObservationRunId));
            Assert.Equal(first.Process.ObservationRunId, second.Process.ObservationRunId);
        }

        [Fact]
        public void FailedUtcConversionRetainsRawKernelObservationWithoutFabricatingUtc()
        {
            var message = Message(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), "birth");
            KernelTimestampConverter.ApplyKernelProcessObservation(message, 123456789, 0);
            Assert.Equal(123456789, message.Process.ObservationTimeMonotonicNanoseconds);
            Assert.Null(message.Process.ObservationTimeFileTimeUtc);
            Assert.Equal("linux-bpf-ktime-monotonic", message.Process.ObservationClockDomain);
        }

        [Fact]
        public void RepeatedLinuxRefreshUsesScanTimeAndPreservesIdentity()
        {
            DateTime birth = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            DateTime firstScan = new(2026, 1, 2, 5, 5, 0, DateTimeKind.Utc);
            DateTime secondScan = firstScan.AddHours(1);
            var times = new Queue<DateTime>(new[] { firstScan, secondScan });
            var emitted = new List<WintapMessage>();
            var info = new ProcReader.ProcessInfo
            {
                Exists = true,
                Pid = 12345,
                PPid = 0,
                Name = "fixture",
                ExecutablePath = "/synthetic/fixture",
                CommandLine = "fixture --exact",
                Username = "",
                StartTimeUtc = birth
            };
            var sensor = new ProcessRundownSensor(
                () => new[] { info },
                emitted.Add,
                () => times.Dequeue(),
                new gov.llnl.wintap.core.infrastructure.ProcessRefreshSchedule
                {
                    Enabled = false,
                    Interval = TimeSpan.FromHours(1),
                    Offset = TimeSpan.FromMinutes(5)
                },
                (_, _) => { });

            Assert.True(sensor.RunSnapshot("first test inventory"));
            Assert.True(sensor.RunSnapshot("second test inventory"));
            Assert.Equal(2, emitted.Count);
            Assert.Equal(emitted[0].PidHash, emitted[1].PidHash);
            Assert.Equal(birth.ToFileTimeUtc(), emitted[0].EventTime);
            Assert.Equal(birth.ToFileTimeUtc(), emitted[1].EventTime);
            Assert.Equal(firstScan.ToFileTimeUtc(), emitted[0].Process.ObservationTimeFileTimeUtc);
            Assert.Equal(secondScan.ToFileTimeUtc(), emitted[1].Process.ObservationTimeFileTimeUtc);
            Assert.All(emitted, message =>
            {
                Assert.Equal("userspace-utc", message.Process.ObservationClockDomain);
                Assert.Null(message.Process.ObservationTimeMonotonicNanoseconds);
                Assert.True(message.ReceiveTime > 0);
            });
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task NormalParquetProjectionTypesOptionalTimingForEitherFirstRow(bool populatedFirst)
        {
            var missing = Message(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), "missing");
            missing.ReceiveTime = 101;
            var populated = Message(new DateTime(2026, 1, 1, 0, 0, 1, DateTimeKind.Utc), "populated");
            populated.ReceiveTime = 202;
            populated.Process.ObservationTimeFileTimeUtc = 133801632000000001;
            populated.Process.ObservationTimeMonotonicNanoseconds = 987654321;
            populated.Process.ObservationClockDomain = "linux-bpf-ktime-monotonic";
            populated.Process.ObservationRunId = "synthetic-run";

            WintapMessage[] messages = populatedFirst ? new[] { populated, missing } : new[] { missing, populated };
            var serializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var queue = new ConcurrentQueue<ExpandoObject>();
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(typeof(ProcessSerializer), serializer, "host", new HostId { Hostname = "synthetic-host" });
            MethodInfo handler = typeof(ProcessSerializer).GetMethod("handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            foreach (WintapMessage message in messages)
                handler.Invoke(serializer, new object[] { message });

            var rows = queue.Select(row => (IDictionary<string, object>)row).ToList();
            MethodInfo schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando", BindingFlags.Static | BindingFlags.NonPublic);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { queue.First() });
            DataField utcField = schema.GetDataFields().Single(field => field.Name == "ObservationTimeFileTimeUtc");
            DataField monotonicField = schema.GetDataFields().Single(field => field.Name == "ObservationTimeMonotonicNanoseconds");
            Assert.Equal(typeof(long), utcField.ClrType);
            Assert.Equal(typeof(long), monotonicField.ClrType);
            Assert.True(utcField.IsNullable);
            Assert.True(monotonicField.IsNullable);

            using var stream = new System.IO.MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(rows, schema, stream);
            stream.Position = 0;
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(stream);
            var byHash = recovered.Data.ToDictionary(row => (string)row["PidHash"]);
            Assert.Equal(101, Convert.ToInt64(byHash["missing"]["ReceiveTime"]));
            Assert.False(byHash["missing"].ContainsKey("ObservationTimeFileTimeUtc"));
            Assert.Equal(202, Convert.ToInt64(byHash["populated"]["ReceiveTime"]));
            Assert.Equal(133801632000000001, Convert.ToInt64(byHash["populated"]["ObservationTimeFileTimeUtc"]));
            Assert.Equal(987654321, Convert.ToInt64(byHash["populated"]["ObservationTimeMonotonicNanoseconds"]));
            Assert.Equal("synthetic-run", byHash["populated"]["ObservationRunId"]);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task DirectParquetProjectionTypesOptionalTimingForEitherFirstRow(bool populatedFirst)
        {
            var missing = Message(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), "missing");
            missing.ReceiveTime = 101;
            var populated = Message(new DateTime(2026, 1, 1, 0, 0, 1, DateTimeKind.Utc), "populated");
            populated.ReceiveTime = 202;
            populated.Process.ObservationTimeFileTimeUtc = 133801632000000001;
            populated.Process.ObservationTimeMonotonicNanoseconds = 987654321;
            populated.Process.ObservationClockDomain = "linux-bpf-ktime-monotonic";
            populated.Process.ObservationRunId = "synthetic-run";

            WintapMessage[] messages = populatedFirst ? new[] { populated, missing } : new[] { missing, populated };
            var rows = messages
                .Select(message => (IDictionary<string, object>)DirectParquetProjection.ToExpando(message))
                .ToList();
            Assert.True(rows.Single(row => (string)row["PidHash"] == "missing")
                .ContainsKey("Process_ObservationTimeMonotonicNanoseconds"));

            MethodInfo schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando", BindingFlags.Static | BindingFlags.NonPublic);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { (ExpandoObject)rows.First() });
            DataField utcField = schema.GetDataFields().Single(field => field.Name == "Process_ObservationTimeFileTimeUtc");
            DataField monotonicField = schema.GetDataFields().Single(field => field.Name == "Process_ObservationTimeMonotonicNanoseconds");
            Assert.Equal(typeof(long), utcField.ClrType);
            Assert.Equal(typeof(long), monotonicField.ClrType);
            Assert.True(utcField.IsNullable);
            Assert.True(monotonicField.IsNullable);

            using var stream = new System.IO.MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(rows, schema, stream);
            stream.Position = 0;
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(stream);
            var byHash = recovered.Data.ToDictionary(row => (string)row["PidHash"]);
            Assert.False(byHash["missing"].ContainsKey("Process_ObservationTimeFileTimeUtc"));
            Assert.False(byHash["missing"].ContainsKey("Process_ObservationTimeMonotonicNanoseconds"));
            Assert.Equal(133801632000000001, Convert.ToInt64(byHash["populated"]["Process_ObservationTimeFileTimeUtc"]));
            Assert.Equal(987654321, Convert.ToInt64(byHash["populated"]["Process_ObservationTimeMonotonicNanoseconds"]));
        }

        [Fact]
        public void DirectProjectionCarriesReceiptAndProcessObservationFields()
        {
            var message = Message(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), "birth");
            message.ReceiveTime = 303;
            message.Process.ObservationTimeFileTimeUtc = 404;
            message.Process.ObservationTimeMonotonicNanoseconds = 505;
            message.Process.ObservationClockDomain = "clock";
            message.Process.ObservationRunId = "run";
            var row = (IDictionary<string, object>)DirectParquetProjection.ToExpando(message);
            Assert.Equal(303L, row["ReceiveTime"]);
            Assert.Equal(404L, row["Process_ObservationTimeFileTimeUtc"]);
            Assert.Equal(505L, row["Process_ObservationTimeMonotonicNanoseconds"]);
            Assert.Equal("clock", row["Process_ObservationClockDomain"]);
            Assert.Equal("run", row["Process_ObservationRunId"]);
        }

        private static WintapMessage Message(DateTime birth, string pidHash) => new(
            birth, 12345, WintapMessage.MessageTypeEnum.Process)
        {
            ActivityType = WintapMessage.ActivityTypeEnum.Start,
            PidHash = pidHash,
            AgentId = "synthetic-agent",
            Process = new WintapMessage.ProcessObject
            {
                PID = 12345,
                ParentPID = 0,
                ParentPidHash = "parent",
                Name = "fixture",
                Path = "/synthetic/fixture",
                CommandLine = "fixture --exact",
                User = ""
            }
        };

        private static void SetField(Type type, object target, string name, object value) =>
            type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(target, value);
    }
}
