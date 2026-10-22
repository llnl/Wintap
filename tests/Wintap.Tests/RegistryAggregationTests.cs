using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using com.espertech.esper.common.client.configuration;
using com.espertech.esper.compiler.client;
using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class RegistryAggregationTests
    {
        [Fact]
        public void BatchEmitsOneAggregatePerGroupRatherThanPerInputEvent()
        {
            using var stream = typeof(EventChannel).Assembly.GetManifestResourceStream("gov.llnl.wintap.core.etl.esper.registry.epl");
            using var reader = new StreamReader(stream);
            var config = new Configuration();
            config.Common.EventMeta.ClassPropertyResolutionStyle = com.espertech.esper.compat.PropertyResolutionStyle.CASE_INSENSITIVE;
            config.Common.AddEventType(typeof(WintapMessage));
            config.Runtime.Threading.IsInternalTimerEnabled = false;
            var runtime = EPRuntimeProvider.GetRuntime("registry-aggregate-" + Guid.NewGuid(), config);
            try
            {
                runtime.EventService.ClockExternal();
                runtime.EventService.AdvanceTime(0);
                var compiled = EPCompilerProvider.Compiler.Compile(reader.ReadToEnd(), new CompilerArguments(config));
                var deployment = runtime.DeploymentService.Deploy(compiled);
                var counts = new List<long>();
                deployment.Statements[0].Events += (_, e) => {
                    if (e.NewEvents != null) foreach (var row in e.NewEvents) counts.Add(Convert.ToInt64(row["eventCount"]));
                };
                for (int group = 0; group < 3; group++)
                    for (int i = 0; i < group + 2; i++)
                        runtime.EventService.SendEventBean(new WintapMessage(DateTime.UtcNow, 4242, WintapMessage.MessageTypeEnum.Registry) {
                            PidHash = "probe", ProcessName = "probe.exe", AgentId = "agent",
                            ActivityType = WintapMessage.ActivityTypeEnum.Read,
                            Registry = new WintapMessage.RegActivityObject { Path = "test", ValueName = "Probe" + group, Data = "" }
                        }, "WintapMessage");
                runtime.EventService.AdvanceTime(10000);
                counts.Sort();
                Assert.Equal(new long[] { 2, 3, 4 }, counts);
                runtime.EventService.AdvanceTime(20000);
                Assert.Equal(3, counts.Count);
            }
            finally { runtime.Destroy(); }
        }
    }
}

