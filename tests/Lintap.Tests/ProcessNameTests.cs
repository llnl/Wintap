using System;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Lintap.Tests
{
    [Trait("Category", "sfx-01")]
    [Trait("TestKind", "unit")]
    [Trait("Execution", "synthetic")]
    public class ProcessNameTests
    {
        [Theory]
        [InlineData("/proc/2147483647/exe", "ObservedComm", "ObservedComm")]
        [InlineData("/proc/self/exe", "ObservedComm", "ObservedComm")]
        [InlineData("/proc/thread-self/exe", "ObservedComm", "ObservedComm")]
        [InlineData("/proc/2147483647/task/2147483646/exe", "ObservedComm", "ObservedComm")]
        [InlineData("/proc/2147483647/exe", "", "unknown")]
        [InlineData("/proc/2147483647/exe", "exe", "exe")]
        [InlineData(null, "", "unknown")]
        [InlineData("/opt/synthetic/My Worker", "comm", "My Worker")]
        [InlineData("/opt/synthetic/Worker (deleted)", "comm", "Worker")]
        [InlineData("/opt/synthetic/exe", "comm", "exe")]
        [InlineData("/opt/synthetic/unknown-tool", "comm", "unknown-tool")]
        [InlineData("/opt/synthetic/CaseTool", "comm", "CaseTool")]
        [InlineData("unknown-1", "ObservedComm", "ObservedComm")]
        [InlineData("/opt/synthetic/", "ObservedComm", "ObservedComm")]
        [InlineData("/opt/synthetic/exe (deleted)", "comm", "exe")]
        public void NameUsesPathEvidenceOtherwiseComm(string path, string comm, string expected)
        {
            Assert.Equal(expected, ProcessSensorHelper.ExtractProcessName(path, comm));
        }

        [Theory]
        [InlineData("/proc/2147483647/exe", "ObservedComm", "ObservedComm")]
        [InlineData("", "ObservedComm", "ObservedComm")]
        [InlineData("", "", "unknown")]
        [InlineData("/opt/synthetic/My Worker", "comm", "My Worker")]
        [InlineData("/opt/synthetic/exe", "comm", "exe")]
        public void RundownPreservesNameBirthAndIdentity(string path, string comm, string expected)
        {
            var birth = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var info = new ProcReader.ProcessInfo
            {
                Exists = true, Pid = 2147483647, PPid = 0, StartTimeUtc = birth,
                ExecutablePath = path, Name = comm, Username = "", CommandLine = "invented-command --not-path-evidence"
            };
            var sensor = new ProcessRundownSensor();
            var first = sensor.CreateRefreshMessage(info);
            Assert.Equal(expected, first.Process.Name);
            Assert.Equal(expected, first.ProcessName);
            Assert.Equal(birth.ToFileTimeUtc(), first.EventTime);
            Assert.Equal(info.CommandLine, first.Process.CommandLine);
            info.Name = "OtherComm";
            info.ExecutablePath = "/opt/synthetic/OtherImage";
            var second = sensor.CreateRefreshMessage(info);
            Assert.Equal(first.PidHash, second.PidHash);
            Assert.Equal(first.EventTime, second.EventTime);
            Assert.NotEqual("invented-command", first.Process.Path);
            info.StartTimeUtc = birth.AddSeconds(1);
            var reusedPid = sensor.CreateRefreshMessage(info);
            Assert.NotEqual(first.PidHash, reusedPid.PidHash);
            Assert.Equal(info.StartTimeUtc.ToFileTimeUtc(), reusedPid.EventTime);
        }

        [Fact]
        public void RundownDoesNotInventBirthForMissingOrExitedProcess()
        {
            var sensor = new ProcessRundownSensor();
            var info = new ProcReader.ProcessInfo { Exists = true, Pid = 2147483647, Name = "ObservedComm" };
            Assert.Null(sensor.CreateRefreshMessage(info));
            info.StartTimeUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            info.Exists = false;
            Assert.Null(sensor.CreateRefreshMessage(info));
        }
    }
}
