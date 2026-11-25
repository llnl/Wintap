using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
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
    [Trait("Category", "sfx-03")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessCommandLineQualityTests
    {
        [Fact]
        public void ProcfsReadDistinguishesCapturedEmptyAndUnavailable()
        {
            using var directory = new SyntheticDirectory();
            string capturedPath = Path.Combine(directory.Path, "captured");
            File.WriteAllBytes(capturedPath, Encoding.UTF8.GetBytes("tool\0arg with space"));
            string emptyPath = Path.Combine(directory.Path, "empty");
            File.WriteAllBytes(emptyPath, Array.Empty<byte>());

            var captured = ProcReader.ReadCommandLineFile(capturedPath);
            Assert.Equal("tool arg with space", captured.CommandLine);
            Assert.Equal("procfs-cmdline", captured.Source);
            Assert.Equal("captured", captured.Status);

            var empty = ProcReader.ReadCommandLineFile(emptyPath);
            Assert.Equal(string.Empty, empty.CommandLine);
            Assert.Equal("empty", empty.Status);

            var unavailable = ProcReader.ReadCommandLineFile(Path.Combine(directory.Path, "missing"));
            Assert.Equal(string.Empty, unavailable.CommandLine);
            Assert.Equal("procfs-cmdline", unavailable.Source);
            Assert.Equal("unavailable", unavailable.Status);
        }

        [Fact]
        public void ProcfsReadReportsErrorWithoutLeakingExceptionText()
        {
            using var directory = new SyntheticDirectory();
            string path = Path.Combine(directory.Path, "fixture");
            File.WriteAllText(path, "fixture");

            var observation = ProcReader.ReadCommandLineFile(
                path, _ => throw new IOException("synthetic-private-detail"));

            Assert.Equal(string.Empty, observation.CommandLine);
            Assert.Equal("procfs-cmdline", observation.Source);
            Assert.Equal("read-error", observation.Status);
        }

        [Fact]
        public void ProcfsReadTruncatesOnlyAtCompleteArgumentBoundary()
        {
            using var directory = new SyntheticDirectory();
            string path = Path.Combine(directory.Path, "bounded");
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes("first\0second\0partial\0"));

            var observation = ProcReader.ReadCommandLineFile(path, maxBytes: 13);

            Assert.Equal("first second", observation.CommandLine);
            Assert.Equal("truncated", observation.Status);
            Assert.DoesNotContain("partial", observation.CommandLine);
        }

        [Fact]
        public void CloneNeverAttributesParentCommandLineToChild()
        {
            var child = new ProcReader.ProcessInfo
            {
                CommandLine = string.Empty,
                CommandLineSource = "procfs-cmdline",
                CommandLineCaptureStatus = "unavailable"
            };
            var parent = new ProcReader.ProcessInfo
            {
                CommandLine = "parent-only --must-not-copy",
                CommandLineSource = "procfs-cmdline",
                CommandLineCaptureStatus = "captured"
            };

            var selected = CloneSensor.SelectCommandLineMetadata(child, parent);

            Assert.Equal(string.Empty, selected.CommandLine);
            Assert.Equal("procfs-cmdline", selected.Source);
            Assert.Equal("unavailable", selected.Status);
        }

        [Fact]
        public void RundownPropagatesCommandLineProvenanceWithoutChangingIdentity()
        {
            DateTime birth = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var info = new ProcReader.ProcessInfo
            {
                Exists = true,
                Pid = 12345,
                PPid = 0,
                Name = "fixture",
                ExecutablePath = "/synthetic/fixture",
                CommandLine = "fixture --exact",
                CommandLineSource = "procfs-cmdline",
                CommandLineCaptureStatus = "captured",
                Username = string.Empty,
                StartTimeUtc = birth
            };

            WintapMessage message = new ProcessRundownSensor().CreateRefreshMessage(info);

            Assert.Equal("fixture --exact", message.Process.CommandLine);
            Assert.Equal("procfs-cmdline", message.Process.CommandLineSource);
            Assert.Equal("captured", message.Process.CommandLineCaptureStatus);
            Assert.Equal(birth.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(new ProcessHash().GenPidHash(12345, birth.ToFileTimeUtc()), message.PidHash);
        }

        [Fact]
        public async Task NormalAndDirectParquetPreserveCommandLineProvenance()
        {
            WintapMessage message = Message();
            var serializer = (ProcessSerializer)RuntimeHelpers.GetUninitializedObject(typeof(ProcessSerializer));
            var queue = new ConcurrentQueue<ExpandoObject>();
            SetField(typeof(Serializer), serializer, "sensorData", queue);
            SetField(typeof(Serializer), serializer, "flushHighWaterEvents", int.MaxValue);
            SetField(typeof(ProcessSerializer), serializer, "host", new HostId { Hostname = "synthetic-host" });
            MethodInfo handler = typeof(ProcessSerializer).GetMethod("handleStartEvent", BindingFlags.Instance | BindingFlags.NonPublic);
            handler.Invoke(serializer, new object[] { message });

            IDictionary<string, object> normal = (IDictionary<string, object>)queue.Single();
            IDictionary<string, object> direct = (IDictionary<string, object>)DirectParquetProjection.ToExpando(message);
            Assert.Equal("procfs-cmdline", normal["CommandLineSource"]);
            Assert.Equal("captured", normal["CommandLineCaptureStatus"]);
            Assert.Equal("procfs-cmdline", direct["Process_CommandLineSource"]);
            Assert.Equal("captured", direct["Process_CommandLineCaptureStatus"]);

            var normalRecovered = await RoundTrip((ExpandoObject)normal);
            var directRecovered = await RoundTrip((ExpandoObject)direct);
            Assert.Equal("procfs-cmdline", normalRecovered["CommandLineSource"]);
            Assert.Equal("captured", normalRecovered["CommandLineCaptureStatus"]);
            Assert.Equal("procfs-cmdline", directRecovered["Process_CommandLineSource"]);
            Assert.Equal("captured", directRecovered["Process_CommandLineCaptureStatus"]);
        }

        private static WintapMessage Message() => new(
            new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), 12345, WintapMessage.MessageTypeEnum.Process)
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
                CommandLineSource = "procfs-cmdline",
                CommandLineCaptureStatus = "captured",
                User = string.Empty,
                Arguments = "PROC_START_SRC=sched_exec"
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

        private static void SetField(Type type, object target, string name, object value) =>
            type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(target, value);
    }
}
