using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using com.espertech.esper.common.client.configuration;
using com.espertech.esper.compiler.client;
using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class TcpStartupProjectionTests
    {
        private static string Query(string name)
        {
            using var stream = typeof(EventChannel).Assembly.GetManifestResourceStream("gov.llnl.wintap.core.etl.esper." + name + ".epl");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        // Real production context and TCP aggregation. External time removes sleeps,
        // scheduling luck and native sensors from this subscription-boundary control.
        [Theory]
        [InlineData(false, 4)]
        [InlineData(true, 8)]
        public void TcpEventsBeforeQueryDeploymentAreNotReplayed(bool registerBeforeProducer, long expected)
        {
            var config = new Configuration();
            config.Common.EventMeta.ClassPropertyResolutionStyle = com.espertech.esper.compat.PropertyResolutionStyle.CASE_INSENSITIVE;
            config.Common.AddEventType(typeof(WintapMessage));
            config.Compiler.ByteCode.SetAccessModifiersPublic();
            config.Runtime.Threading.IsInternalTimerEnabled = false;
            var runtime = EPRuntimeProvider.GetRuntime("tcp-startup-" + Guid.NewGuid(), config);
            try
            {
                runtime.EventService.ClockExternal();
                runtime.EventService.AdvanceTime(0);
                runtime.DeploymentService.Deploy(EPCompilerProvider.Compiler.Compile(Query("esper-context"), new CompilerArguments(config)));
                var rows = new List<long>();
                void Register()
                {
                    var args = new CompilerArguments(config);
                    args.Path.Add(runtime.RuntimePath);
                    var deployment = runtime.DeploymentService.Deploy(EPCompilerProvider.Compiler.Compile(Query("tcp"), args));
                    foreach (var statement in deployment.Statements)
                        statement.Events += (_, e) => {
                            if (e.NewEvents != null) foreach (var row in e.NewEvents) rows.Add(Convert.ToInt64(row["eventCount"]));
                        };
                }
                void SendFour()
                {
                    for (int i = 0; i < 4; i++)
                        runtime.EventService.SendEventBean(new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.TcpConnection) {
                            PidHash = "canonical", ProcessName = "probe", AgentId = "agent",
                            ActivityType = WintapMessage.ActivityTypeEnum.TcpIpSend,
                            TcpConnection = new WintapMessage.TcpConnectionObject {
                                SourceAddress = "192.168.252.48", SourcePort = 22,
                                DestinationAddress = "192.168.252.1", DestinationPort = 62000, PacketSize = 92
                            }
                        }, "WintapMessage");
                }
                if (registerBeforeProducer) Register();
                SendFour();
                if (!registerBeforeProducer) Register();
                SendFour();
                runtime.EventService.AdvanceTime(10000);
                Assert.Equal(expected, rows.Sum());
                runtime.EventService.AdvanceTime(20000);
                Assert.Equal(expected, rows.Sum());
            }
            finally { runtime.Destroy(); }
        }
    }
}
