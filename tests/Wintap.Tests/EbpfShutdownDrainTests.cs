using System;
using System.IO;
using Xunit;

namespace Wintap.Tests
{
    public sealed class EbpfShutdownDrainTests
    {
        [Fact, Trait("Category", "ldq-02")]
        public void NativeWorkersAreJoinedWithoutTimeoutBeforeCleanup()
        {
            string baseSource = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "BaseEbpfSensor.cs"));
            string fileSource = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "FileOpsSensor.cs"));

            Assert.Contains("WaitForThreadExit(PollingThread);", baseSource, StringComparison.Ordinal);
            Assert.Contains("thread?.Join();", baseSource, StringComparison.Ordinal);
            Assert.Contains("WaitForThreadExit(_sendWorker);", fileSource, StringComparison.Ordinal);
            Assert.DoesNotContain("PollingThread?.Join(TimeSpan", baseSource, StringComparison.Ordinal);
            Assert.DoesNotContain("_sendWorker?.Join(TimeSpan", fileSource, StringComparison.Ordinal);
        }
    }
}
