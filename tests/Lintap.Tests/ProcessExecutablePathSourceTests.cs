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
    [Trait("Category", "sfx-05")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessExecutablePathSourceTests
    {
        private const string Alias = "/proc/2147483647/exe";

        [Fact]
        public void ExecLabelsExistingEventThenProcfsThenUnavailablePrecedence()
        {
            var info = new ProcReader.ProcessInfo
            {
                ExecutablePath = "/synthetic/proc-image",
                Name = "proc-comm"
            };

            var fromEvent = ExecveSensor.SelectExecutableMetadataAndSource(
                "/synthetic/event-image", "event-comm", info);
            Assert.Equal(("/synthetic/event-image", "event-image", "exec-event-filename"), fromEvent);

            var fromProc = ExecveSensor.SelectExecutableMetadataAndSource(
                Alias, "event-comm", info, _ => null);
            Assert.Equal(("/synthetic/proc-image", "proc-image", "procfs-exe"), fromProc);

            info.ExecutablePath = string.Empty;
            var unavailable = ExecveSensor.SelectExecutableMetadataAndSource(
                string.Empty, string.Empty, info);
            Assert.Equal(("unknown-1", "proc-comm", "unavailable"), unavailable);
        }

        [Fact]
        public void CloneLabelsChildThenInheritedParentThenUnavailablePrecedence()
        {
            var child = new ProcReader.ProcessInfo
            {
                ExecutablePath = "/synthetic/child-image",
                Name = "child-comm"
            };
            var parent = new ProcReader.ProcessInfo
            {
                ExecutablePath = "/synthetic/parent-image",
                Name = "parent-comm"
            };

            var fromChild = CloneSensor.SelectExecutableMetadataAndSource(child, parent, "event-parent");
            Assert.Equal(("/synthetic/child-image", "child-image", "procfs-exe"), fromChild);

            child.ExecutablePath = Alias;
            var fromParent = CloneSensor.SelectExecutableMetadataAndSource(
                child, parent, "event-parent", _ => null);
            Assert.Equal(("/synthetic/parent-image", "parent-image", "parent-procfs-exe"), fromParent);

            parent.ExecutablePath = string.Empty;
            var unavailable = CloneSensor.SelectExecutableMetadataAndSource(
                child, parent, "event-parent", _ => null);
            Assert.Equal(("unknown", "child-comm", "unavailable"), unavailable);
        }

        [Theory]
        [InlineData("/synthetic/rundown-image", "/synthetic/rundown-image", "procfs-exe")]
        [InlineData("", "unknown-5", "unavailable")]
        public void RundownLabelsItsOwnProcfsEvidence(
            string observedPath, string expectedPath, string expectedSource)
        {
            var info = new ProcReader.ProcessInfo
            {
                Exists = true,
                Pid = 12345,
                PPid = 0,
                Name = "rundown-comm",
                ExecutablePath = observedPath,
                StartTimeUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            };

            WintapMessage message = new ProcessRundownSensor().CreateRefreshMessage(info);
            Assert.Equal(expectedPath, message.Process.Path);
            Assert.Equal(expectedSource, message.Process.ExecutablePathSource);
        }

        [Fact]
        public async Task NormalAndNullFirstDirectProjectionPreserveExecutablePathSource()
        {
            WintapMessage message = Message("exec-event-filename");
            var serializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var queue = new ConcurrentQueue<ExpandoObject>();
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(typeof(ProcessSerializer), serializer, "host", new HostId { Hostname = "synthetic-host" });
            MethodInfo handler = typeof(ProcessSerializer).GetMethod(
                "handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            handler.Invoke(serializer, new object[] { message });

            IDictionary<string, object> normal = (IDictionary<string, object>)queue.Single();
            Assert.Equal("exec-event-filename", normal["ExecutablePathSource"]);

            ExpandoObject nullFirst = DirectParquetProjection.ToExpando(Message(null));
            IDictionary<string, object> nullValues = nullFirst;
            Assert.True(nullValues.ContainsKey("Process_ExecutablePathSource"));
            Assert.Null(nullValues["Process_ExecutablePathSource"]);

            ExpandoObject populated = DirectParquetProjection.ToExpando(message);
            var recovered = await RoundTripMany(nullFirst, populated);
            Assert.True(!recovered[0].TryGetValue("Process_ExecutablePathSource", out object missing) || missing == null);
            Assert.Equal("exec-event-filename", recovered[1]["Process_ExecutablePathSource"]);
        }

        private static WintapMessage Message(string source) => new(
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
                ExecutionObservationKind = "exec_success",
                ExecutablePathSource = source
            }
        };

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
