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
using gov.llnl.wintap.platform.linux.collect;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Lintap.Tests
{
    [Trait("Category", "sfx-01")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessNameProjectionTests
    {
        [Theory]
        [InlineData(@"C:\Synthetic\MixedCase.EXE", "ignored-sensor-name", "mixedcase.exe")]
        [InlineData("/synthetic/MixedCase.EXE", "ignored-sensor-name", "mixedcase.exe")]
        [InlineData(null, "ignored-sensor-name", "unknown")]
        [InlineData("", "ignored-sensor-name", "unknown")]
        public void NonLinuxProjectionRetainsExistingPathBasedLowercase(string path, string name, string expected)
        {
            Assert.Equal(expected, ProcessSerializer.ProjectProcessName(path, name, isLinux: false));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void LinuxMissingSelectedNameIsExplicitUnknown(string name)
        {
            Assert.Equal("unknown", ProcessSerializer.ProjectProcessName("/proc/2147483647/exe", name, isLinux: true));
        }

        [Fact]
        public async Task NormalSerializerAndParquetPreserveSelectedLinuxName()
        {
            var serializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var queue = new ConcurrentQueue<ExpandoObject>();
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(typeof(ProcessSerializer), serializer, "host", new HostId { Hostname = "synthetic-host" });
            var handler = typeof(ProcessSerializer).GetMethod("handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            var info = new ProcReader.ProcessInfo
            {
                Exists = true, Pid = 2147483647, PPid = 0, ExecutablePath = "/proc/2147483647/exe",
                Name = "RundownComm", CommandLine = "synthetic payload --exact", Username = "",
                StartTimeUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            };
            var exec = ExecveSensor.SelectExecutableMetadata(info.ExecutablePath, "ExecComm", info, _ => null);
            var clone = CloneSensor.SelectExecutableMetadata(info, default, "ParentComm", _ => null);
            var rundown = new ProcessRundownSensor().CreateRefreshMessage(info);
            rundown.AgentId = "synthetic-agent";
            rundown.Process.ParentPidHash = "synthetic-parent-hash";
            var messages = new[]
            {
                Message("ObservedComm", "/proc/2147483647/exe", WintapMessage.ActivityTypeEnum.Start),
                Message("My Worker", "/opt/synthetic/My Worker", WintapMessage.ActivityTypeEnum.Refresh),
                Message("unknown", "unknown-1", WintapMessage.ActivityTypeEnum.Start),
                Message("exe", "/opt/synthetic/exe", WintapMessage.ActivityTypeEnum.Start),
                Message(exec.Name, exec.Path, WintapMessage.ActivityTypeEnum.Start),
                Message(clone.Name, clone.Path, WintapMessage.ActivityTypeEnum.Start),
                rundown
            };
            foreach (var message in messages) handler.Invoke(serializer, new object[] { message });
            Assert.Equal(messages.Length, queue.Count);
            var rows = queue.Select(row => (IDictionary<string, object>)row).ToList();
            var schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando", BindingFlags.Static | BindingFlags.NonPublic);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { queue.First() });
            using var directory = new SyntheticDirectory();
            string path = Path.Combine(directory.Path, "process.parquet");
            using (var output = File.Create(path))
                await ParquetSerializer.SerializeUntypedAsync(rows, schema, output);
            using var input = File.OpenRead(path);
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(input);
            Assert.Equal(messages.Length, recovered.Data.Count);
            for (int i = 0; i < messages.Length; i++)
            {
                var message = messages[i];
                var row = recovered.Data[i];
                Assert.Equal(message.Process.Name, row["ProcessName"]);
                Assert.Equal(message.Process.Path, row["ProcessPath"]);
                Assert.Equal(message.Process.CommandLine, row["CommandLine"]);
                Assert.Equal(message.PidHash, row["PidHash"]);
                Assert.Equal(message.Process.ParentPidHash, row["ParentPidHash"]);
                Assert.Equal(message.EventTime, Convert.ToInt64(row["StartTime"]));
                Assert.Equal(message.EventTime, Convert.ToInt64(row["EventTime"]));
                Assert.Equal(message.ActivityType.ToString(), row["ActivityType"]);
                row.TryGetValue("ProcessStartSource", out var source);
                Assert.Equal(message == rundown ? null : "sched_exec", source);
                Assert.Equal("synthetic-agent", row["AgentId"]);
                Assert.Equal("SYNTHETIC-HOST", row["Hostname"]);
            }
        }

        private static WintapMessage Message(string name, string path, WintapMessage.ActivityTypeEnum activity) => new(
            new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), 2147483647, WintapMessage.MessageTypeEnum.Process)
        {
            ActivityType = activity, PidHash = "synthetic-pid-hash", AgentId = "synthetic-agent",
            Process = new WintapMessage.ProcessObject
            {
                Name = name, Path = path, CommandLine = "synthetic payload --exact", User = "",
                ParentPID = 0, ParentPidHash = "synthetic-parent-hash", Arguments = "PROC_START_SRC=sched_exec"
            }
        };

        private static void SetField(Type type, object target, string name, object value) =>
            type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(target, value);
    }

    internal sealed class SyntheticDirectory : IDisposable
    {
        internal string Path { get; }

        internal SyntheticDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sfx-01-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
