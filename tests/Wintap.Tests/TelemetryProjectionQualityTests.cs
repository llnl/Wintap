using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.etl.transform;
using Parquet.Schema;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    public class TelemetryProjectionQualityTests
    {
        [Theory]
        [InlineData("PROC_START_SRC=sched_fork", "sched_fork")]
        [InlineData("arguments PROC_START_SRC=sched_exec FLAGS=0x0", "sched_exec")]
        [InlineData("\tPROC_START_SRC=execve_or_execveat\n", "execve_or_execveat")]
        [InlineData(null, null)]
        [InlineData("", null)]
        [InlineData("xPROC_START_SRC=sched_exec", null)]
        [InlineData("PROC_START_SRC=unknown", null)]
        [InlineData("PROC_START_SRC=sched_fork PROC_START_SRC=sched_fork", "sched_fork")]
        [InlineData("PROC_START_SRC=sched_exec PROC_START_SRC=unknown", null)]
        [InlineData("PROC_START_SRC=SCHED_EXEC", null)]
        [InlineData("PROC_START_SRC=sched_fork PROC_START_SRC=sched_exec", null)]
        public void SourceSurvivesProductionProjectionWithoutChangingIdentityOrCommandLine(string arguments, string expected)
        {
            var data = new ProcessStartData("parent", 1, 42, "birth", "fixture", 123456789,
                "/fixture/Process", "fixture", "uid", "md5", "sha2", "unchanged command line", "agent");
            ProcessSerializer.ApplyStartProvenance(data, arguments);
            var flat = (IDictionary<string, object>)data.ToDynamic();
            Assert.True(flat.ContainsKey("ProcessStartSource"));
            Assert.Equal(expected, flat["ProcessStartSource"]);
            Assert.Equal("unchanged command line", data.CommandLine);
            Assert.Equal("birth", data.PidHash);
            Assert.Equal("parent", data.ParentPidHash);
            Assert.Equal(123456789, data.StartTime);
            Assert.Equal("agent", data.AgentId);
        }

        [Fact]
        public void LinuxCaseDistinctPathsRetainDistinctFileKeysAcrossLocales()
        {
            var old = CultureInfo.CurrentCulture;
            try
            {
                foreach (var culture in new[] { "en-US", "tr-TR" })
                {
                    CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                    var upper = FileSerializer.SelectPath("/fixture/I/File", false);
                    var lower = FileSerializer.SelectPath("/fixture/i/file", false);
                    Assert.Equal("/fixture/I/File", upper);
                    Assert.Equal("/fixture/i/file", lower);
                    var generator = new IdGenerator();
                    Assert.NotEqual(generator.GenKeyForFile("context", "host", "agent", upper),
                        generator.GenKeyForFile("context", "host", "agent", lower));
                    Assert.Null(FileSerializer.SelectPath(null, false));
                }
            }
            finally { CultureInfo.CurrentCulture = old; }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("sched_exec")]
        public async Task ProductionSchemaRoundTripsNullAndKnownSource(string firstSource)
        {
            var first = new ProcessStartData("parent", 1, 42, "birth", "fixture", 123456789,
                "/fixture/Process", "fixture", "uid", "md5", "sha2", "unchanged command line", "agent");
            var second = new ProcessStartData("parent", 1, 43, "other birth", "fixture", 123456790,
                "/fixture/Process", "fixture", "uid", "md5", "sha2", "unchanged command line", "agent");
            first.ProcessStartSource = firstSource;
            second.ProcessStartSource = "sched_fork";
            var flat = first.ToDynamic();
            var schemaMethod = typeof(ParquetWriter).GetMethod("DetermineSchemaFromExpando",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(schemaMethod);
            var schema = (ParquetSchema)schemaMethod.Invoke(null, new object[] { flat });
            using var stream = new MemoryStream();
            await ParquetSerializer.SerializeUntypedAsync(new List<IDictionary<string, object>>
                { (IDictionary<string, object>)flat, (IDictionary<string, object>)second.ToDynamic() }, schema, stream);
            stream.Position = 0;
            var read = await ParquetSerializer.DeserializeUntypedAsync(stream);
            Assert.Contains(read.Schema.GetDataFields(), field => field.Name == "ProcessStartSource");
            // Untyped deserialization omits null-valued dictionary entries.
            read.Data[0].TryGetValue("ProcessStartSource", out var source);
            Assert.Equal(firstSource, source);
            Assert.Equal("sched_fork", read.Data[1]["ProcessStartSource"]);
            Assert.Equal("birth", read.Data[0]["PidHash"]);
            Assert.Equal("unchanged command line", read.Data[0]["CommandLine"]);
        }
    }
}
