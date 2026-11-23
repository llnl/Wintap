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
    [Trait("Category", "sfx-06")]
    [Trait("TestKind", "contract")]
    [Trait("Execution", "synthetic")]
    public class ProcessExitCodeCaptureStatusTests
    {
        [Theory]
        [InlineData("core", "kernel-wait-status")]
        [InlineData("tracepoint", "unavailable")]
        [InlineData(null, "unavailable")]
        public void ExitTierDeterminesStatusWithoutInterpretingValue(
            string loadedTier, string expected)
        {
            Assert.Equal(expected, ExitSensor.GetExitCodeCaptureStatus(loadedTier));
        }

        [Fact]
        public void NormalStopProjectionPreservesExitCodeAndStatus()
        {
            WintapMessage message = Message("kernel-wait-status", 1792);
            var serializer = (ProcessStopSerializer)RuntimeHelpers.GetUninitializedObject(
                typeof(ProcessStopSerializer));
            SetField(serializer, "host", new HostId { Hostname = "synthetic-host" });
            MethodInfo create = typeof(ProcessStopSerializer).GetMethod(
                "createProcessTerminate", BindingFlags.Instance | BindingFlags.NonPublic);

            var row = (ProcessTerminateData)create.Invoke(serializer, new object[] { message });

            Assert.Equal(1792, row.ExitCode);
            Assert.Equal("kernel-wait-status", row.ExitCodeCaptureStatus);
        }

        [Fact]
        public async Task NullFirstDirectProjectionRetainsExitCodeCaptureStatus()
        {
            ExpandoObject nullFirst = DirectParquetProjection.ToExpando(Message(null, 0));
            IDictionary<string, object> nullValues = nullFirst;
            Assert.True(nullValues.ContainsKey("Process_ExitCodeCaptureStatus"));
            Assert.Null(nullValues["Process_ExitCodeCaptureStatus"]);

            ExpandoObject populated = DirectParquetProjection.ToExpando(
                Message("unavailable", 0));
            var recovered = await RoundTripMany(nullFirst, populated);

            Assert.True(!recovered[0].TryGetValue(
                "Process_ExitCodeCaptureStatus", out object missing) || missing == null);
            Assert.Equal("unavailable", recovered[1]["Process_ExitCodeCaptureStatus"]);
            Assert.Equal(0L, Convert.ToInt64(recovered[1]["Process_ExitCode"]));
        }

        private static WintapMessage Message(string status, long exitCode) => new(
            new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            12345, WintapMessage.MessageTypeEnum.Process)
        {
            ActivityType = WintapMessage.ActivityTypeEnum.Stop,
            PidHash = "synthetic-pid-hash",
            AgentId = "synthetic-agent",
            ProcessName = "fixture",
            Process = new WintapMessage.ProcessObject
            {
                PID = 12345,
                ParentPID = 0,
                ParentPidHash = "synthetic-parent-hash",
                Name = "fixture",
                Path = "/synthetic/fixture",
                CommandLine = string.Empty,
                User = string.Empty,
                ExitCode = exitCode,
                ExitCodeCaptureStatus = status
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

        private static void SetField(object target, string name, object value) =>
            typeof(ProcessStopSerializer).GetField(
                name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(target, value);
    }
}
