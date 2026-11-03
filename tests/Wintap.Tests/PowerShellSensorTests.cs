using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using com.espertech.esper.common.client.configuration;
using com.espertech.esper.compiler.client;
using com.espertech.esper.runtime.client;
using DuckDB.NET.Data;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.platform.windows.collect.etw;
using gov.llnl.wintap.platform.windows.infrastructure;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    [Trait("Category", "powershell")]
    public class PowerShellSensorTests
    {
        private static readonly DateTime Time = new(2026, 10, 28, 18, 0, 0, DateTimeKind.Utc);
        private static readonly Guid Activity = Guid.NewGuid(), Related = Guid.NewGuid();
        private const string Text = "Write-Host 'caf\u00e9 \u03bb'\r\n$x = \"a;b\"\r\n";
        private static Dictionary<string, object> Fields() => new()
        {
            ["MessageNumber"] = 3, ["MessageTotal"] = 3,
            ["ScriptBlockText"] = Text, ["ScriptBlockId"] = "975302f1-1bfd-41ca-b23a-fb38b8397659", ["Path"] = ""
        };
        private static WintapMessage Message(Dictionary<string, object> fields = null, Guid? provider = null)
        {
            Assert.True(PowerShellSensor.TryCreateMessage(provider ?? PowerShellSensor.WindowsProvider, 4104, 1,
                Time.AddTicks(12345), 4242, 43, Activity, Related, fields ?? Fields(), out var message));
            return message;
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void BothProvidersPreserveFragmentAndEmitterWithoutInventingIdentity(bool core)
        {
            var provider = core ? PowerShellSensor.CoreProvider : PowerShellSensor.WindowsProvider;
            var message = Message(provider: provider);
            Assert.Equal(WintapMessage.MessageTypeEnum.PowerShell, message.MessageType);
            Assert.Equal(WintapMessage.ActivityTypeEnum.EventWritten, message.ActivityType);
            Assert.Equal(Time.AddTicks(12345).ToFileTimeUtc(), message.EventTime);
            Assert.Equal(4242, message.PID);
            Assert.Null(message.PidHash);
            Assert.Null(message.ProcessName);
            Assert.Equal(Activity.ToString("D"), message.ActivityId);
            Assert.Equal(Related.ToString("D"), message.CorrelationId);
            Assert.Equal(provider.ToString("D"), message.PowerShell.ProviderGuid);
            Assert.Equal(43, message.PowerShell.ThreadId);
            Assert.Equal(Text, message.PowerShell.ScriptBlockText);
            Assert.Equal("", message.PowerShell.Path);
            Assert.Equal(3, message.PowerShell.MessageNumber);
            Assert.Equal(3, message.PowerShell.MessageTotal);
        }

        [Theory]
        [InlineData("missing-number")]
        [InlineData("string-number")]
        [InlineData("zero-number")]
        [InlineData("total-too-small")]
        [InlineData("missing-total")]
        [InlineData("null-text")]
        [InlineData("oversized-text")]
        [InlineData("missing-id")]
        [InlineData("empty-id")]
        [InlineData("missing-path")]
        [InlineData("wrong-provider")]
        [InlineData("wrong-id")]
        [InlineData("wrong-version")]
        [InlineData("invalid-pid")]
        [InlineData("invalid-time")]
        public void InvalidEventsDoNotProducePartialMessages(string scenario)
        {
            var fields = Fields();
            switch (scenario)
            {
                case "missing-number": fields.Remove("MessageNumber"); break;
                case "string-number": fields["MessageNumber"] = "3"; break;
                case "zero-number": fields["MessageNumber"] = 0; break;
                case "total-too-small": fields["MessageTotal"] = 2; break;
                case "missing-total": fields.Remove("MessageTotal"); break;
                case "null-text": fields["ScriptBlockText"] = null; break;
                case "oversized-text": fields["ScriptBlockText"] = new string('x', PowerShellSensor.MaximumTextLength + 1); break;
                case "missing-id": fields.Remove("ScriptBlockId"); break;
                case "empty-id": fields["ScriptBlockId"] = ""; break;
                case "missing-path": fields.Remove("Path"); break;
            }
            Assert.False(PowerShellSensor.TryCreateMessage(
                scenario == "wrong-provider" ? Guid.Empty : PowerShellSensor.WindowsProvider,
                scenario == "wrong-id" ? 4103 : 4104, scenario == "wrong-version" ? 2 : 1,
                scenario == "invalid-time" ? default : Time, scenario == "invalid-pid" ? 0 : 4242,
                43, Activity, Related, fields, out var message));
            Assert.Null(message);
        }

        [Fact]
        public void CallbackKeepsDuplicatesEmptyTextAndFilePathAndFiltersOtherEvents()
        {
            var messages = new List<WintapMessage>();
            var sensor = new PowerShellSensor(messages.Add, () => false);
            try
            {
                Assert.True(sensor.Start()); // Disabled startup creates no ETW session.
                Assert.False(sensor.HandleEvent(Guid.Empty, 4104, 1, Time, 4242, 43, Activity, Related, null));
                Assert.False(sensor.HandleEvent(PowerShellSensor.WindowsProvider, 7937, 1, Time, 4242, 43, Activity, Related, null));
                for (int i = 0; i < 2; i++)
                    Assert.True(sensor.HandleEvent(PowerShellSensor.WindowsProvider, 4104, 1, Time, 4242, 43, Activity, Related, Fields()));
                var file = Fields();
                file["Path"] = @"C:\Sample Folder\MixedCase.ps1";
                file["ScriptBlockText"] = "";
                Assert.True(sensor.HandleEvent(PowerShellSensor.CoreProvider, 4104, 1, Time, 4242, 43, Guid.Empty, Guid.Empty, file));
                Assert.Equal(3, messages.Count);
                Assert.Equal(messages[0].PowerShell.ScriptBlockText, messages[1].PowerShell.ScriptBlockText);
                Assert.Equal(@"C:\Sample Folder\MixedCase.ps1", messages[2].PowerShell.Path);
                Assert.Equal("", messages[2].PowerShell.ScriptBlockText);
                Assert.Equal("", messages[2].ActivityId);
            }
            finally { sensor.Stop(); sensor.Stop(); }
        }

        [Fact]
        public void ConfigurationDiscoversIndependentSensorAndPreservesEnumOrdinals()
        {
            Assert.Equal((int)WintapMessage.MessageTypeEnum.WindowsShell + 1, (int)WintapMessage.MessageTypeEnum.PowerShell);
            Assert.NotNull(typeof(WintapMessage).GetProperty("PowerShell"));
            Assert.False(gov.llnl.wintap.Properties.Settings.Default.PowerShellSensor);
            var sensor = new PowerShellSensor(_ => { }, () => false);
            var plan = WindowsSubscriptionManager.CreateStartupPlan(new[] { WindowsSubscriptionManager.CreateCollectorEntry("PowerShell", sensor) });
            Assert.Same(sensor, Assert.Single(plan.IndependentSensors).Sensor);
            Assert.Empty(plan.SharedKernelSensors);
            sensor.Stop();
        }

        [Fact]
        public void DelayedFragmentUsesExitedHostLifetimeInsteadOfReusedPid()
        {
            using var db = new DuckDBConnection("Data Source=:memory:");
            db.Open();
            ProcessResolver.EnsureEventStoreTables(db);
            var resolver = new ProcessResolver(db, 16, enableMaintenance: false, registrationLogSink: (_, _) => { });
            var old = Birth(Time.AddSeconds(-5), "embedded-host.exe", "old-host");
            resolver.RegisterProcess(old);
            resolver.RegisterProcess(new WintapMessage(Time.AddSeconds(1), 4242, WintapMessage.MessageTypeEnum.Process)
            { PidHash = old.PidHash, ActivityType = WintapMessage.ActivityTypeEnum.Stop, Process = old.Process });
            resolver.RegisterProcess(Birth(Time.AddSeconds(2), "pwsh.exe", "reused-pid"));
            var message = Message();
            var owner = EventOwnerSelection.ResolveOwner(resolver, message, DateTime.FromFileTimeUtc(message.EventTime), true, out _);
            Assert.True(ProcessAttribution.TryApply(message, owner));
            Assert.Equal("old-host", message.PidHash);
            Assert.Equal("embedded-host.exe", message.ProcessName);
            Assert.Equal(Text, message.PowerShell.ScriptBlockText);
        }

        [Fact]
        public void RegistrationRaceRetriesSameObservationThenUsesCanonicalOwner()
        {
            using var db = new DuckDBConnection("Data Source=:memory:");
            db.Open();
            ProcessResolver.EnsureEventStoreTables(db);
            var resolver = new ProcessResolver(db, 16, enableMaintenance: false, registrationLogSink: (_, _) => { });
            var message = Message();
            long eventTime = message.EventTime, receiveTime = message.ReceiveTime, clock = 0;
            Assert.Null(EventOwnerSelection.ResolveOwner(resolver, message, Time, true, out _));
            int emitted = 0;
            var queue = new AttributionRetryQueue((pending, attempt) =>
            {
                Assert.Same(message, pending);
                var owner = EventOwnerSelection.ResolveOwner(resolver, pending, DateTime.FromFileTimeUtc(pending.EventTime), true, out _);
                Assert.True(ProcessAttribution.TryApply(pending, owner));
                emitted++;
            }, clock: () => clock, startTimer: false);
            try
            {
                Assert.True(queue.TrySchedule(message, 0));
                resolver.RegisterProcess(Birth(Time.AddSeconds(-1), "powershell.exe", "registered-host"));
                clock = 1000;
                queue.Pump(); queue.Pump();
                Assert.Equal(1, emitted);
                Assert.Equal("registered-host", message.PidHash);
                Assert.Equal(eventTime, message.EventTime);
                Assert.Equal(receiveTime, message.ReceiveTime);
            }
            finally { queue.Shutdown(); }
        }

        private static WintapMessage Birth(DateTime time, string name, string hash) => new(time, 4242, WintapMessage.MessageTypeEnum.Process)
        {
            PidHash = hash, ActivityType = WintapMessage.ActivityTypeEnum.Start,
            Process = new WintapMessage.ProcessObject { PID = 4242, ParentPID = 4, Name = name, Path = @"C:\fixture\" + name, CommandLine = name, User = "fixture" }
        };

        [Fact]
        public async Task ProductionDefaultEplAndSerializerPreserveAllFragmentsThroughParquet()
        {
            var config = new Configuration();
            config.Common.EventMeta.ClassPropertyResolutionStyle = com.espertech.esper.compat.PropertyResolutionStyle.CASE_INSENSITIVE;
            config.Common.AddEventType(typeof(WintapMessage));
            config.Runtime.Threading.IsInternalTimerEnabled = false;
            var runtime = EPRuntimeProvider.GetRuntime("powershell-plumbing-" + Guid.NewGuid(), config);
            var rows = new List<IDictionary<string, object>>();
            try
            {
                using var epl = typeof(EventChannel).Assembly.GetManifestResourceStream("gov.llnl.wintap.core.etl.esper.default.epl");
                using var reader = new StreamReader(epl);
                var deployed = runtime.DeploymentService.Deploy(EPCompilerProvider.Compiler.Compile(reader.ReadToEnd(), new CompilerArguments(config)));
                deployed.Statements[0].Events += (_, e) =>
                {
                    foreach (var row in e.NewEvents)
                        rows.Add(DefaultSerializer.BuildFlatMessage((WintapMessage)row.Underlying));
                };
                for (int i = 0; i < 3; i++)
                {
                    var message = Message();
                    Assert.True(ProcessAttribution.TryApply(message, new ProcessRecord
                    { ProcessId = 4242, PidHash = "canonical-host", ProcessName = "embedded-host.exe" }));
                    message.AgentId = "fixture-agent";
                    runtime.EventService.SendEventBean(message, "WintapMessage");
                }
                Assert.Equal(3, rows.Count);
                var schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando", BindingFlags.NonPublic | BindingFlags.Static);
                var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { rows[0] });
                using var output = new MemoryStream();
                await ParquetSerializer.SerializeUntypedAsync(rows, schema, output);
                output.Position = 0;
                var recovered = await ParquetSerializer.DeserializeUntypedAsync(output);
                Assert.Equal(3, recovered.Data.Count);
                foreach (var row in recovered.Data)
                {
                    Assert.Equal(Text, row["ScriptBlockText"]);
                    Assert.Equal("", row["Path"]);
                    Assert.Equal(3, Convert.ToInt32(row["MessageNumber"]));
                    Assert.Equal("canonical-host", row["PidHash"]);
                    Assert.Equal("embedded-host.exe", row["ProcessName"]);
                    Assert.Equal("PowerShell", row["MessageType"]);
                    Assert.Equal(Activity.ToString("D"), row["ActivityId"]);
                    Assert.Equal(Time.AddTicks(12345).ToFileTimeUtc(), row["EventTime"]);
                }
            }
            finally { runtime.Destroy(); }
        }

        [Fact]
        public void DirectSinkAlsoRetainsPowerShellPayload()
        {
            var row = (IDictionary<string, object>)DirectParquetProjection.ToExpando(Message());
            Assert.Equal(Text, row["PowerShell_ScriptBlockText"]);
            Assert.Equal("", row["PowerShell_Path"]);
            Assert.Equal(3, row["PowerShell_MessageTotal"]);
            Assert.Equal(Activity.ToString("D"), row["ActivityId"]);
            Assert.Equal(Related.ToString("D"), row["CorrelationId"]);
        }
    }
}
