using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.etl.load.adapters.baseclass;
using Xunit;

namespace Wintap.Tests
{
    public class RuntimeDataRootTests
    {
        [Fact]
        [Trait("Category", "wpc-09")]
        public void ResolveDataRoot_ProgrammaticOverrideWins()
        {
            string result = Env.ResolveDataRoot(
                @"D:\programmatic",
                @"D:\configured",
                OSPlatform.Windows,
                @"C:\ProgramData");

            Assert.Equal(@"D:\programmatic", result);
        }

        [Fact]
        [Trait("Category", "wpc-09")]
        public void ResolveDataRoot_ConfiguredValueWinsPlatformDefault()
        {
            string result = Env.ResolveDataRoot(
                null,
                @"D:\configured",
                OSPlatform.Windows,
                @"C:\ProgramData");

            Assert.Equal(@"D:\configured", result);
        }

        [Fact]
        [Trait("Category", "rdp-01")]
        public void ResolveRuntimeRoot_ProgrammaticOverrideWins()
        {
            string result = Env.ResolveRuntimeRoot(
                @"D:\programmatic-runtime",
                @"D:\configured-runtime",
                OSPlatform.Windows,
                @"C:\ProgramData");

            Assert.Equal(@"D:\programmatic-runtime", result);
        }

        [Fact]
        [Trait("Category", "rdp-01")]
        public void ResolveRuntimeRoot_ConfiguredValueWinsPlatformDefault()
        {
            string result = Env.ResolveRuntimeRoot(
                null,
                @"D:\configured-runtime",
                OSPlatform.Windows,
                @"C:\ProgramData");

            Assert.Equal(@"D:\configured-runtime", result);
        }

        [Theory]
        [Trait("Category", "wpc-09")]
        [InlineData(null, null)]
        [InlineData("", "")]
        [InlineData("   ", "\t")]
        public void ResolveDataRoot_EmptyValuesUsePlatformDefault(string overridden, string configured)
        {
            string result = Env.ResolveDataRoot(
                overridden,
                configured,
                OSPlatform.Windows,
                @"C:\ProgramData");

            Assert.Equal(@"C:\ProgramData\Wintap\data", result);
        }

        [Theory]
        [Trait("Category", "wpc-09")]
        [InlineData("WINDOWS", @"C:\ProgramData\Wintap\data")]
        [InlineData("OSX", "/Library/Application Support/Mactap/data")]
        [InlineData("LINUX", "/var/lib/lintap/data")]
        public void ResolveDataRoot_UsesExpectedPlatformDefault(string platformName, string expected)
        {
            OSPlatform platform = platformName == "WINDOWS"
                ? OSPlatform.Windows
                : platformName == "OSX"
                    ? OSPlatform.OSX
                    : OSPlatform.Linux;

            string result = Env.ResolveDataRoot(null, null, platform, @"C:\ProgramData");

            Assert.Equal(expected, result);
        }

        [Theory]
        [Trait("Category", "rdp-01")]
        [InlineData("WINDOWS", @"C:\ProgramData\Wintap\data")]
        [InlineData("OSX", "/Library/Application Support/Mactap/data")]
        [InlineData("LINUX", "/var/lib/lintap/data")]
        public void ResolveDataRoot_UsesSplitPlatformDefault(string platformName, string expected)
        {
            OSPlatform platform = platformName == "WINDOWS"
                ? OSPlatform.Windows
                : platformName == "OSX"
                    ? OSPlatform.OSX
                    : OSPlatform.Linux;

            string result = Env.ResolveDataRoot(null, null, platform, @"C:\ProgramData");

            Assert.Equal(expected, result);
        }

        [Theory]
        [Trait("Category", "rdp-01")]
        [InlineData("WINDOWS", @"C:\ProgramData\Wintap\runtime")]
        [InlineData("OSX", "/Library/Application Support/Mactap/runtime")]
        [InlineData("LINUX", "/var/lib/lintap/runtime")]
        public void ResolveRuntimeRoot_UsesExpectedPlatformDefault(string platformName, string expected)
        {
            OSPlatform platform = platformName == "WINDOWS"
                ? OSPlatform.Windows
                : platformName == "OSX"
                    ? OSPlatform.OSX
                    : OSPlatform.Linux;

            string result = Env.ResolveRuntimeRoot(null, null, platform, @"C:\ProgramData");

            Assert.Equal(expected, result);
        }

        [Fact]
        [Trait("Category", "rdp-01")]
        public void SplitRoots_CanBeConfiguredToTheSameDirectory()
        {
            string data = Env.ResolveDataRoot(null, @"/shared", OSPlatform.Linux, @"C:\ProgramData");
            string runtime = Env.ResolveRuntimeRoot(null, @"/shared", OSPlatform.Linux, @"C:\ProgramData");

            Assert.Equal(data, runtime);
        }

        [Fact]
        [Trait("Category", "rdp-02")]
        public void UploaderRelativeKey_RemainsRawSensorRelativeUnderDataRoot()
        {
            string dataRoot = Path.Combine(Path.GetTempPath(), "wintap-data-root");
            string localFile = Path.Combine(dataRoot, "raw_sensor", "process", "dayPK=20261015", "hourPK=12", "host+process+timestamp.parquet");

            string result = Uploader.GetParquetRelativePathForFile(localFile, dataRoot);

            Assert.Equal(Path.Combine("raw_sensor", "process", "dayPK=20261015", "hourPK=12", "host+process+timestamp.parquet"), result);
        }

        [Fact]
        [Trait("Category", "wpc-09")]
        public void ConfigRoot_HasNoDataRootDefault()
        {
            Assert.True(string.IsNullOrEmpty(new ConfigRoot().DataRoot));
            Assert.True(string.IsNullOrEmpty(new ConfigRoot().RuntimeRoot));
        }

        [Fact]
        [Trait("Category", "wpc-09")]
        public void ShippedEtlConfig_HasNoDataRootOverride()
        {
            string configPath = Path.Combine(AppContext.BaseDirectory, "ETLConfig.json");
            using JsonDocument config = JsonDocument.Parse(File.ReadAllText(configPath));

            Assert.False(config.RootElement.TryGetProperty("DataRoot", out _));
            Assert.False(config.RootElement.TryGetProperty("RuntimeRoot", out _));
        }
    }
}
