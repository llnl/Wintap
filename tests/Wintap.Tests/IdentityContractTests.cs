using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using gov.llnl.wintap.core.shared;
using Xunit;

namespace Wintap.Tests
{
    public class IdentityContractTests : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "wintap-identity-" + Guid.NewGuid().ToString("N"));
        private string State(string name = "host") => Path.Combine(root, name, "wintapstate.json");
        private AgentIdentity.Result Load(string host = "HOST", string machine = "machine-1", string name = "host")
            => AgentIdentity.LoadOrCreate(State(name), host, machine);

        private static System.Collections.Generic.IEnumerable<string> SourceFiles(string directory)
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.cs")) yield return file;
            foreach (var child in Directory.EnumerateDirectories(directory))
            {
                string name = Path.GetFileName(child);
                if (new[] { "bin", "obj", ".git", ".venv", "node_modules", "tests" }.Contains(name) ||
                    (File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
                foreach (var file in SourceFiles(child)) yield return file;
            }
        }

        public void Dispose() { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }

        [Theory]
        [InlineData("AXON-TARGET", 3291, 134372000000000000L, "BB5534A4CF755F413420EC9AC6E6CE07")]
        [InlineData("HOST", -1, 0L, "0D429F2989A68867933B8111D67BB105")]
        [InlineData("HOST", 42, 133000000000000000L, "A123B10783FCA3B315A79E9B3700300B")]
        public void ProcessHashHasStableContractVectors(string host, int pid, long start, string expected)
            => Assert.Equal(expected, ProcessIdentity.Compute(host, pid, start));

        [Fact]
        public void ProcessHashNormalizesHostnameAndUsesInvariantNumbers()
        {
            var prior = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
                Assert.Equal(ProcessIdentity.Compute("IDENTITY-HOST", 42, 133000000000000000),
                    ProcessIdentity.Compute(" identity-host ", 42, 133000000000000000));
            }
            finally { CultureInfo.CurrentCulture = prior; }
        }

        [Fact]
        public void EachProcessInstanceInputChangesIdentity()
        {
            string hash = ProcessIdentity.Compute("HOST", 42, 133000000000000000);
            Assert.NotEqual(hash, ProcessIdentity.Compute("OTHER", 42, 133000000000000000));
            Assert.NotEqual(hash, ProcessIdentity.Compute("HOST", 43, 133000000000000000));
            Assert.NotEqual(hash, ProcessIdentity.Compute("HOST", 42, 133000000000000001));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void EmptyHostnameIsRejected(string host)
            => Assert.Throws<ArgumentException>(() => ProcessIdentity.Compute(host, 42, 0));

        [Fact]
        public void AgentReplacementCannotChangeProcessOrParentIdentity()
        {
            var original = Load();
            string process = ProcessIdentity.Compute("HOST", 42, 133000000000000000);
            string parent = ProcessIdentity.Compute("HOST", 41, 132999999999999999);
            File.Delete(State());
            var replacement = Load();
            Assert.NotEqual(original.AgentId, replacement.AgentId);
            Assert.Equal(process, ProcessIdentity.Compute("HOST", 42, 133000000000000000));
            Assert.Equal(parent, ProcessIdentity.Compute("HOST", 41, 132999999999999999));
        }

        [Fact]
        public void SensorAndWindowsHelperUseExactlyTheSameFormula()
        {
            var sensor = new gov.llnl.wintap.core.shared.helpers.ProcessHash();
            var helper = new gov.llnl.wintap.platform.windows.collect.etw.helpers.ProcessHash();
            foreach (var value in new[] { (42, 133000000000000000L), (-1, 0L) })
            {
                string expected = ProcessIdentity.Compute(Environment.MachineName, value.Item1, value.Item2);
                Assert.Equal(expected, sensor.GenPidHash(value.Item1, value.Item2));
                Assert.Equal(expected, helper.GenPidHash(value.Item1, value.Item2));
            }
        }

        [Fact]
        public void FreshAgentPersistsAcrossRestartAndHostnameCase()
        {
            var first = Load();
            var second = Load(" host ", " MACHINE-1 ");
            Assert.NotEqual(Guid.Empty, first.AgentId);
            Assert.True(first.Changed);
            Assert.Equal(first.AgentId, second.AgentId);
            Assert.False(second.Changed);
        }

        [Fact]
        public void IndependentHostsHaveDifferentAgentIds()
        {
            Assert.NotEqual(Load("AXON-TARGET", "machine-1", "a").AgentId,
                Load("CALDERA-HOST", "machine-2", "b").AgentId);
        }

        [Theory]
        [InlineData("OTHER", "machine-1")]
        [InlineData("HOST", "machine-2")]
        public void CopiedBoundStateReissuesOnceWhenHostOrMachineDiffers(string host, string machine)
        {
            var original = Load();
            Directory.CreateDirectory(Path.GetDirectoryName(State("copy")));
            File.Copy(State(), State("copy"));
            var cloned = Load(host, machine, "copy");
            Assert.NotEqual(original.AgentId, cloned.AgentId);
            Assert.Equal("copied-or-changed-host-state", cloned.Reason);
            Assert.Equal(cloned.AgentId, Load(host, machine, "copy").AgentId);
            Assert.Equal(original.AgentId, Load().AgentId);
        }

        [Fact]
        public void DuplicateLegacyUuidMigratesToIndependentPersistedIdsWithoutModifyingInput()
        {
            Directory.CreateDirectory(root);
            string legacy = Path.Combine(root, "legacy.json");
            string json = "{\"AgentId\":\"fc3e4c62-eddf-42d0-9ab4-830773b61f6f\",\"OtherSetting\":7}";
            File.WriteAllText(legacy, json);
            var a = AgentIdentity.LoadOrCreate(State("a"), "AXON-TARGET", "cloned-machine-id", legacy);
            var b = AgentIdentity.LoadOrCreate(State("b"), "CALDERA-HOST", "cloned-machine-id", legacy);
            Assert.NotEqual(a.AgentId, b.AgentId);
            Assert.NotEqual(Guid.Parse("fc3e4c62-eddf-42d0-9ab4-830773b61f6f"), a.AgentId);
            Assert.Equal("legacy-unbound-state", a.Reason);
            Assert.Equal(a.AgentId, Load("AXON-TARGET", "cloned-machine-id", "a").AgentId);
            Assert.Equal(json, File.ReadAllText(legacy));
            using var saved = JsonDocument.Parse(File.ReadAllText(State("a")));
            Assert.Equal(7, saved.RootElement.GetProperty("OtherSetting").GetInt32());
        }

        [Theory]
        [InlineData("")]
        [InlineData("not-a-guid")]
        [InlineData("00000000-0000-0000-0000-000000000000")]
        public void EmptyOrInvalidLegacyAgentGetsPersistedUuid(string id)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(State()));
            File.WriteAllText(State(), JsonSerializer.Serialize(new { AgentId = id }));
            var result = Load();
            Assert.NotEqual(Guid.Empty, result.AgentId);
            Assert.Equal(result.AgentId, Load().AgentId);
        }

        [Theory]
        [InlineData("{broken")]
        [InlineData("null")]
        [InlineData("{\"StateVersion\":99}")]
        public void CorruptOrUnsupportedStateFailsWithoutOverwriting(string json)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(State()));
            File.WriteAllText(State(), json);
            Assert.ThrowsAny<Exception>(() => Load());
            Assert.Equal(json, File.ReadAllText(State()));
        }

        [Fact]
        public async Task ConcurrentInitializersAgreeOnOnePersistedUuid()
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => Load())));
            Assert.Single(results.Select(r => r.AgentId).Distinct());
            Assert.Single(results, r => r.Changed);
            Assert.Equal(results[0].AgentId, Load().AgentId);
        }

        [Fact]
        public void PersistenceFailureDoesNotReturnAnUnstableIdentity()
        {
            Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "blocked"), "not a directory");
            Assert.ThrowsAny<IOException>(() => AgentIdentity.LoadOrCreate(
                Path.Combine(root, "blocked", "state.json"), "HOST", "machine"));
        }

        [Fact]
        public void HostnameOnlyBindingStillDetectsDifferentlyNamedClones()
        {
            Assert.NotEqual(AgentIdentity.CreateHostBinding("HOST", ""), AgentIdentity.CreateHostBinding("OTHER", ""));
            Assert.Equal(Load(machine: "").AgentId, Load(machine: "").AgentId);
        }

        [Fact]
        public void ProcessStoreVersionDoesNotReuseLegacyFiles()
        {
            Assert.NotEqual("main.duckdb", ProcessIdentity.MainStoreFileName);
            Assert.NotEqual("recovery.duckdb", ProcessIdentity.RecoveryStoreFileName);
            Assert.Contains(ProcessIdentity.Version, ProcessIdentity.MainStoreFileName);
            Assert.Contains(ProcessIdentity.Version, ProcessIdentity.RecoveryStoreFileName);
        }

        [Fact]
        public void ProductionSourceHasOneProcessFormulaAndHelperLinksIt()
        {
            var repo = new DirectoryInfo(AppContext.BaseDirectory);
            while (repo != null && !File.Exists(Path.Combine(repo.FullName, "Directory.Build.props"))) repo = repo.Parent;
            Assert.NotNull(repo);
            string sensorSource = Path.Combine(repo.FullName, "wintap", "core", "shared", "ProcessIdentity.cs");
            var formulas = SourceFiles(repo.FullName)
                .Where(p => File.ReadAllText(p).Contains("Process_ID`"))
                .ToArray();
            Assert.Equal(new[] { sensorSource }, formulas);
            foreach (var wrapper in new[] { "wintap/core/shared/ProcessHash.cs", "platform/windows/WintapCoreSvcMgr/ProcessHash.cs" })
            {
                string source = File.ReadAllText(Path.Combine(repo.FullName, wrapper));
                Assert.Contains("ProcessIdentity.Compute", source);
                Assert.DoesNotContain("StateManager.AgentId", source);
            }
            string project = File.ReadAllText(Path.Combine(repo.FullName, "platform/windows/WintapCoreSvcMgr/WintapCoreSvcMgr.csproj"));
            Assert.Contains("wintap\\core\\shared\\ProcessIdentity.cs", project);
        }
    }
}
