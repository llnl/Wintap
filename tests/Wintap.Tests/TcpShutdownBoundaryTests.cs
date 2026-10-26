using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using com.espertech.esper.common.client.configuration;
using com.espertech.esper.compiler.client;
using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class TcpShutdownBoundaryTests
    {
        private static string Query(string name)
        {
            using var stream = typeof(EventChannel).Assembly.GetManifestResourceStream("gov.llnl.wintap.core.etl.esper." + name + ".epl");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        [Theory]
        [InlineData(false, 0, 6)]
        [InlineData(true, 6, 0)]
        public async Task FinalWindowAfterQueueDrainStrandsRows(bool finishWindowFirst, long exported, long stranded)
        {
            var config = new Configuration();
            config.Common.EventMeta.ClassPropertyResolutionStyle = com.espertech.esper.compat.PropertyResolutionStyle.CASE_INSENSITIVE;
            config.Common.AddEventType(typeof(WintapMessage));
            config.Compiler.ByteCode.SetAccessModifiersPublic();
            config.Runtime.Threading.IsInternalTimerEnabled = false;
            var runtime = EPRuntimeProvider.GetRuntime("tcp-shutdown-" + Guid.NewGuid(), config);
            try
            {
                runtime.EventService.ClockExternal();
                runtime.EventService.AdvanceTime(0);
                runtime.DeploymentService.Deploy(EPCompilerProvider.Compiler.Compile(Query("esper-context"), new CompilerArguments(config)));
                var args = new CompilerArguments(config);
                args.Path.Add(runtime.RuntimePath);
                var deployment = runtime.DeploymentService.Deploy(EPCompilerProvider.Compiler.Compile(Query("tcp"), args));
                var queue = new List<long>();
                foreach (var statement in deployment.Statements)
                    statement.Events += (_, e) => {
                        if (e.NewEvents != null) foreach (var row in e.NewEvents) queue.Add(Convert.ToInt64(row["eventCount"]));
                    };
                for (int i = 0; i < 6; i++)
                    runtime.EventService.SendEventBean(new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.TcpConnection) {
                        PidHash = "canonical", ProcessName = "probe", AgentId = "agent",
                        ActivityType = i < 3 ? WintapMessage.ActivityTypeEnum.TcpIpSend : WintapMessage.ActivityTypeEnum.TcpIpRecv,
                        TcpConnection = new WintapMessage.TcpConnectionObject {
                            SourceAddress = "192.168.252.48", SourcePort = 22,
                            DestinationAddress = "192.168.252.1", DestinationPort = 62000, PacketSize = 148
                        }
                    }, "WintapMessage");
                Assert.Empty(queue);
                if (finishWindowFirst) await EtlShutdownBarrier.FinishWindowsAsync(
                    runtime.EventService.ClockExternal, () => runtime.EventService.CurrentTime,
                    target => runtime.EventService.AdvanceTimeSpan(target), TimeSpan.FromSeconds(30));
                long written = queue.Sum();
                queue.Clear(); // Same queue-before-final-context-boundary ordering as Serializer.Shutdown.
                if (!finishWindowFirst) runtime.EventService.AdvanceTimeSpan(10000);
                Assert.Equal(exported, written);
                Assert.Equal(stranded, queue.Sum());
            }
            finally { runtime.Destroy(); }
        }
    }
}
