using System;
using System.IO;
using gov.llnl.wintap;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public sealed class ComponentLoggerShutdownTests
    {
        [Fact, Trait("Category", "ldq-02")]
        public void CloseFlushesEveryAcceptedEntryBeforeEndMarker()
        {
            string name = "shutdown-flush-" + Guid.NewGuid().ToString("N");
            string directory = Path.Combine(Path.GetTempPath(), name);
            string path = Path.Combine(directory, name + ".log");
            var logger = new ComponentLogger(name, LogType.Overwrite, LogLevel.Info, 3000000, directory);

            for (int i = 0; i < 250; i++)
            {
                logger.Append($"shutdown-entry-{i:D3}");
            }
            logger.Close();
            logger.Append("post-close-entry");

            string output = File.ReadAllText(path);
            for (int i = 0; i < 250; i++)
            {
                Assert.Contains($"shutdown-entry-{i:D3}", output, StringComparison.Ordinal);
            }
            Assert.DoesNotContain("post-close-entry", output, StringComparison.Ordinal);
            Assert.EndsWith("END OF LOG" + Environment.NewLine, output, StringComparison.Ordinal);

            Directory.Delete(directory, recursive: true);
        }
    }
}
