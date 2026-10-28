using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.load;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    [Trait("Category", "windows-shell")]
    public class WindowsShellTelemetryTests
    {
        private static readonly DateTime Start = new DateTime(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc).AddTicks(1234567);

        private static WintapMessage Message()
        {
            var message = new WintapMessage(Start.AddSeconds(5), 42, WintapMessage.MessageTypeEnum.WindowsShell)
        {
            ActivityType = WintapMessage.ActivityTypeEnum.EventWritten,
            PidHash = "untrusted",
            ProcessName = "untrusted",
            WindowsShell = new WintapMessage.WindowsShellData
            {
                CommandText = "echo café & dir \".\\Sample Folder\"\r\n",
                SessionId = 3
            }
        };
            ProcessAttribution.RecordExpectedProcessStart(message, Start.ToFileTimeUtc());
            return message;
        }

        private static ProcessRecord Owner() => new ProcessRecord
        {
            ProcessId = 42, CreateTime = Start, PidHash = "canonical", ProcessName = "cmd.exe"
        };

        [Fact]
        public void SchemaPreservesExistingEnumOrdinalsAndMatchesDefaultSerializerReflection()
        {
            Assert.Equal((int)WintapMessage.MessageTypeEnum.SELinuxInteraction + 1,
                (int)WintapMessage.MessageTypeEnum.WindowsShell);
            var message = Message();
            var property = typeof(WintapMessage).GetProperty(message.MessageType.ToString());
            var payload = Assert.IsAssignableFrom<WintapMessage.WintapBase>(property.GetValue(message));
            var flat = (IDictionary<string, object>)payload.ToDynamic();
            Assert.Equal(message.WindowsShell.CommandText, flat["CommandText"]);
            Assert.False(flat.ContainsKey("StartTime"));
            Assert.Equal(2, flat.Count);
            Assert.Equal(3, flat["SessionId"]);
        }

        [Fact]
        public void PayloadRoundTripPreservesUnicodeCompoundTextAndFiletimePrecision()
        {
            var message = Message();
            var options = new JsonSerializerOptions();
            options.Converters.Add(new JsonStringEnumConverter());
            var json = JsonSerializer.Serialize(message, options);
            using var document = JsonDocument.Parse(json);
            Assert.Equal("WindowsShell", document.RootElement.GetProperty("MessageType").GetString());
            Assert.Equal(message.EventTime, document.RootElement.GetProperty("EventTime").GetInt64());
            var recovered = JsonSerializer.Deserialize<WintapMessage.WindowsShellData>(
                document.RootElement.GetProperty("WindowsShell").GetRawText(), options);
            Assert.Equal(message.WindowsShell.CommandText, recovered.CommandText);
            Assert.False(document.RootElement.GetProperty("WindowsShell").TryGetProperty("StartTime", out _));
        }

        [Fact]
        public void LifetimeEvidenceIsAbsentFromDefaultSerializerPayload()
        {
            var payload = new WintapMessage.WindowsShellData();
            var flat = (IDictionary<string, object>)payload.ToDynamic();
            Assert.False(flat.ContainsKey("StartTime"));
        }

        [Fact]
        public async Task ProductionDynamicParquetRoundTripPreservesSubmittedInputPayloadAndCanonicalEnvelope()
        {
            var message = Message();
            Assert.True(ProcessAttribution.TryApply(message, Owner()));
            ExpandoObject flat = message.WindowsShell.ToDynamic();
            var row = (IDictionary<string, object>)flat;
            // Match DefaultSerializer's additive envelope flattening.
            row["PidHash"] = message.PidHash;
            row["ProcessName"] = message.ProcessName;
            row["PID"] = message.PID;
            row["MessageType"] = message.MessageType.ToString();
            row["ActivityType"] = message.ActivityType.ToString();
            row["EventTime"] = message.EventTime;
            row["AgentId"] = "fixture-agent";
            var determineSchema = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(determineSchema);
            var schema = (ParquetSchema)determineSchema.Invoke(null, new object[] { flat });
            using var stream = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(new List<IDictionary<string, object>> { row }, schema, stream);
            stream.Position = 0;
            var recovered = await ParquetSerializer.DeserializeUntypedAsync(stream);
            var result = Assert.Single(recovered.Data);
            Assert.Equal(message.WindowsShell.CommandText, result["CommandText"]);
            Assert.EndsWith("\r\n", (string)result["CommandText"]);
            Assert.False(result.ContainsKey("StartTime"));
            Assert.Equal(message.EventTime, Assert.IsType<long>(result["EventTime"]));
            Assert.Equal("canonical", result["PidHash"]);
            Assert.Equal("cmd.exe", result["ProcessName"]);
            Assert.Equal(message.PID, result["PID"]);
            Assert.Equal("WindowsShell", result["MessageType"]);
            Assert.Equal("EventWritten", result["ActivityType"]);
            Assert.Equal(3, result["SessionId"]);
            foreach (string removed in new[] { "ShellExe", "TimestampMethod", "PollIntervalMs", "ObservationWindowMs", "HistoryIndex" })
            {
                Assert.False(result.ContainsKey(removed));
                Assert.DoesNotContain(recovered.Schema.GetDataFields(), field => field.Name == removed);
            }
        }

        [Fact]
        public void CanonicalIdentityAndStartTimeComeFromSameVerifiedLifetime()
        {
            var message = Message();
            Assert.True(ProcessAttribution.TryApply(message, Owner()));
            Assert.Equal("canonical", message.PidHash);
            Assert.Equal("cmd.exe", message.ProcessName);

        }

        [Theory]
        [InlineData(203, true, true)]
        [InlineData(-12977, true, true)]
        [InlineData(203, false, false)]
        [InlineData(30000000, true, false)]
        public void EtwStartSkewRequiresCanonicalHashAndFreshLiveLifetime(long skew, bool liveMatches, bool accepted)
        {
            var message = Message();
            var owner = Owner();
            owner.CreateTime = Start.AddTicks(skew);
            owner.PidHash = gov.llnl.wintap.core.shared.ProcessIdentity.Compute(
                Environment.MachineName, message.PID, owner.CreateTime.ToFileTimeUtc());
            Assert.Equal(accepted, ProcessAttribution.TryApply(message, owner,
                (pid, start) => pid == message.PID && start == Start.ToFileTimeUtc() && liveMatches));
            if (accepted)
            {
                Assert.Equal(owner.PidHash, message.PidHash);

            }
        }

        [Fact]
        public void DurableTimestampPrecisionLossUsesExactSourceHash()
        {
            var message = Message();
            var owner = Owner();
            owner.CreateTime = Start.AddTicks(-7);
            owner.PidHash = gov.llnl.wintap.core.shared.ProcessIdentity.Compute(
                Environment.MachineName, message.PID, Start.ToFileTimeUtc());
            Assert.True(ProcessAttribution.TryApply(message, owner, (_, _) => false));

            Assert.Equal(owner.PidHash, message.PidHash);
        }

        [Theory]
        [InlineData("pid-reuse")]
        [InlineData("wrong-pid")]
        [InlineData("missing-hash")]
        [InlineData("missing-start")]
        [InlineData("missing-canonical-start")]
        [InlineData("before-start")]
        [InlineData("after-exit")]
        [InlineData("missing-owner")]
        public void InvalidLifetimeIsSuppressedWithoutMutatingObservation(string scenario)
        {
            var message = Message();
            var owner = Owner();
            switch (scenario)
            {
                case "pid-reuse": owner.CreateTime = Start.AddSeconds(1); break;
                case "wrong-pid": owner.ProcessId = 43; break;
                case "missing-hash": owner.PidHash = " "; break;
                case "missing-start": ProcessAttribution.RecordExpectedProcessStart(message, null); break;
                case "missing-canonical-start": owner.CreateTime = default; break;
                case "before-start": message.EventTime = Start.AddTicks(-1).ToFileTimeUtc(); break;
                case "after-exit": owner.ExitTime = Start.AddSeconds(4); break;
                case "missing-owner": owner = null; break;
            }
            var before = JsonSerializer.Serialize(message);
            Assert.False(ProcessAttribution.TryApply(message, owner, requireProcessStart: true));
            Assert.Equal(before, JsonSerializer.Serialize(message));
        }
    }
}
