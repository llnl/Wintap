using System;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    public class CollectorProcessTelemetryTests
    {
        [Theory]
        [InlineData(true, WintapMessage.MessageTypeEnum.Process, false)]
        [InlineData(true, WintapMessage.MessageTypeEnum.File, true)]
        [InlineData(true, WintapMessage.MessageTypeEnum.TcpConnection, true)]
        [InlineData(true, WintapMessage.MessageTypeEnum.UdpPacket, true)]
        [InlineData(true, WintapMessage.MessageTypeEnum.Registry, true)]
        [InlineData(false, WintapMessage.MessageTypeEnum.Process, true)]
        [InlineData(false, WintapMessage.MessageTypeEnum.File, true)]
        public void SelfFilterAdmitsOnlyLinuxProcessRecords(bool linux, WintapMessage.MessageTypeEnum type, bool suppressed)
        {
            var message = new WintapMessage(DateTime.UtcNow, 42, type);
            Assert.Equal(suppressed, CollectorEventPolicy.ShouldSuppress(message, 42, linux));
            Assert.False(CollectorEventPolicy.ShouldSuppress(message, 43, linux));
        }

        [Theory]
        [InlineData(WintapMessage.ActivityTypeEnum.Start)]
        [InlineData(WintapMessage.ActivityTypeEnum.Refresh)]
        [InlineData(WintapMessage.ActivityTypeEnum.Stop)]
        public void ProcessFilterDoesNotRewriteLifecycle(WintapMessage.ActivityTypeEnum activity)
        {
            var message = new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.Process)
            {
                ActivityType = activity
            };
            Assert.False(CollectorEventPolicy.ShouldSuppress(message, 42, true));
            Assert.Equal(activity, message.ActivityType);
        }

        [Fact]
        public void RundownIncludesCollectorWithCanonicalBirthAndMetadata()
        {
            var info = ProcessInfo((uint)Environment.ProcessId);
            Assert.True(ProcessRundownSensor.IsUsableProcess(info));
            var message = new ProcessRundownSensor().CreateRefreshMessage(info);
            Assert.NotNull(message);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Refresh, message.ActivityType);
            Assert.Equal(info.StartTimeUtc.ToFileTimeUtc(), message.EventTime);
            Assert.Equal(new ProcessHash().GenPidHash((int)info.Pid, message.EventTime), message.PidHash);
            Assert.Equal("Lintap", message.ProcessName);
            Assert.Equal(info.ExecutablePath, message.ProcessPath);
            Assert.Equal(info.CommandLine, message.Process.CommandLine);
            Assert.Equal("ubuntu", message.Process.User);
            Assert.Equal(0, message.Process.ParentPID);
            Assert.Contains("CWD=/var/log/lintap", message.Process.Arguments);
        }

        [Fact]
        public void MissingBirthAndInvalidProcessesNeverBecomeFabricatedRefreshes()
        {
            var sensor = new ProcessRundownSensor();
            var info = ProcessInfo(42);
            info.StartTimeUtc = default;
            Assert.Null(sensor.CreateRefreshMessage(info));
            info = ProcessInfo(42);
            info.Exists = false;
            Assert.False(ProcessRundownSensor.IsUsableProcess(info));
            Assert.Null(sensor.CreateRefreshMessage(info));
            info = ProcessInfo(uint.MaxValue);
            Assert.False(ProcessRundownSensor.IsUsableProcess(info));
            Assert.Null(sensor.CreateRefreshMessage(info));
        }

        [Fact]
        public void RestartWithReusedPidHasDistinctCanonicalIdentity()
        {
            var info = ProcessInfo(42);
            var sensor = new ProcessRundownSensor();
            var first = sensor.CreateRefreshMessage(info);
            info.StartTimeUtc = info.StartTimeUtc.AddSeconds(1);
            var second = sensor.CreateRefreshMessage(info);
            Assert.NotEqual(first.PidHash, second.PidHash);
            Assert.Equal(WintapMessage.ActivityTypeEnum.Refresh, second.ActivityType);
        }

        private static ProcReader.ProcessInfo ProcessInfo(uint pid) => new ProcReader.ProcessInfo
        {
            Pid = pid,
            Exists = true,
            StartTimeUtc = new DateTime(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc),
            Name = "Lintap",
            ExecutablePath = "/usr/lib/lintap/Lintap",
            CommandLine = "/usr/lib/lintap/Lintap --collect",
            Username = "ubuntu",
            Cwd = "/var/log/lintap"
        };
    }
}
