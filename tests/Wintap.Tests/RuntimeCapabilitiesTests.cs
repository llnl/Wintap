using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.models;
using Parquet.Serialization;
using Xunit;

namespace Wintap.Tests
{
    [CollectionDefinition("RuntimeCapabilities", DisableParallelization = true)]
    public class RuntimeCapabilitiesCollection { }

    [Collection("RuntimeCapabilities")]
    public class RuntimeCapabilitiesTests
    {
        [Theory]
        [InlineData("attached", true, "running")]
        [InlineData("failed", true, "partial")]
        [InlineData("not-found", true, "partial")]
        [InlineData("not-applicable", true, "running")]
        [InlineData("attached", false, "failed")]
        public void HookEvidenceDeterminesStatus(string outcome, bool started, string expected)
        {
            RuntimeCapabilities.Begin();
            RuntimeCapabilities.Sensor("Clone", true, "environment:WINTAP_ENABLE_CLONE_SENSOR");
            RuntimeCapabilities.Hook("Clone", "clone3", "auxiliary", outcome, outcome == "failed" ? -13 : null);
            RuntimeCapabilities.Finished("Clone", started);
            using var doc = JsonDocument.Parse(RuntimeCapabilities.Complete());
            Assert.Equal(expected, doc.RootElement.GetProperty("sensors").GetProperty("Clone").GetProperty("status").GetString());
        }

        [Fact]
        public void DisabledAndIncompleteAreNotReportedAsRunning()
        {
            RuntimeCapabilities.Begin();
            RuntimeCapabilities.Sensor("Clone", false, "config:test");
            RuntimeCapabilities.Sensor("Execve", true, "default");
            using var doc = JsonDocument.Parse(RuntimeCapabilities.Complete());
            var sensors = doc.RootElement.GetProperty("sensors");
            Assert.Equal("disabled", sensors.GetProperty("Clone").GetProperty("status").GetString());
            Assert.Equal("startup-incomplete", sensors.GetProperty("Execve").GetProperty("failureReason").GetString());
        }

        [Fact]
        public void LazyPluginInitializationPreservesAlreadyRecordedStartupSettings()
        {
            RuntimeCapabilities.Begin();
            RuntimeCapabilities.Setting("WINTAP_SKIP_PROCESS_RESOLVE", false, "default");
            string before = RuntimeCapabilities.GetJson();
            RuntimeCapabilities.EnsureInitialized();
            Assert.Equal(before, RuntimeCapabilities.GetJson());
            using var doc = JsonDocument.Parse(RuntimeCapabilities.Complete());
            Assert.False(doc.RootElement.GetProperty("settings").GetProperty("WINTAP_SKIP_PROCESS_RESOLVE").GetProperty("effectiveValue").GetBoolean());
        }

        [Fact]
        public void CompletionIsFrozenAndRestartCreatesNewRun()
        {
            RuntimeCapabilities.Begin();
            string first = RuntimeCapabilities.Complete();
            RuntimeCapabilities.Feature("Clone", "laterMutation", true);
            Assert.Equal(first, RuntimeCapabilities.GetJson());
            Assert.Equal(first, RuntimeCapabilities.Complete());
            using var a = JsonDocument.Parse(first);
            RuntimeCapabilities.Begin();
            using var b = JsonDocument.Parse(RuntimeCapabilities.Complete());
            Assert.NotEqual(a.RootElement.GetProperty("captureRunId").GetString(), b.RootElement.GetProperty("captureRunId").GetString());
        }

        [Fact]
        public void CandidateHistoryAndObjectFingerprintSurviveFallback()
        {
            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllText(path, "object");
                RuntimeCapabilities.Begin();
                RuntimeCapabilities.Attempt("Clone", "clone_core_tracer.bpf.o", "load-failed", -22);
                RuntimeCapabilities.Attempt("Clone", path, "selected");
                RuntimeCapabilities.Loaded("Clone", path, "tracepoint");
                RuntimeCapabilities.Finished("Clone", true);
                using var doc = JsonDocument.Parse(RuntimeCapabilities.Complete());
                var sensor = doc.RootElement.GetProperty("sensors").GetProperty("Clone");
                Assert.Equal(2, sensor.GetProperty("objectAttempts").GetArrayLength());
                Assert.Equal(64, sensor.GetProperty("objectSha256").GetString().Length);
                Assert.Equal("tracepoint", sensor.GetProperty("tier").GetString());
            }
            finally { File.Delete(path); }
        }

        [Fact]
        public async Task HostJsonRoundTripsThroughParquet()
        {
            RuntimeCapabilities.Begin();
            RuntimeCapabilities.Sensor("Exit", false, "default");
            string json = RuntimeCapabilities.Complete();
            using var stream = new MemoryStream();
            await ParquetSerializer.SerializeAsync(new[] { new HostData { RuntimeCapabilitiesJson = json } }, stream);
            stream.Position = 0;
            var rows = await ParquetSerializer.DeserializeAsync<HostData>(stream);
            Assert.Equal(json, Assert.Single(rows).RuntimeCapabilitiesJson);
        }

        [Fact]
        public void InvalidEnvironmentOverrideDoesNotClaimEffectiveProvenance()
        {
            const string key = "WINTAP_SKIP_PROCESS_RESOLVE";
            string previous = Environment.GetEnvironmentVariable(key);
            try
            {
                Environment.SetEnvironmentVariable(key, "invalid-boolean");
                Assert.DoesNotContain("environment:", gov.llnl.wintap.core.shared.ConfigManager.GetValueSource<bool>(key));
                Environment.SetEnvironmentVariable(key, "true");
                Assert.True(gov.llnl.wintap.core.shared.ConfigManager.GetValue<bool>(key));
                Assert.Equal("environment:" + key, gov.llnl.wintap.core.shared.ConfigManager.GetValueSource<bool>(key));
            }
            finally { Environment.SetEnvironmentVariable(key, previous); }
        }
    }
}
