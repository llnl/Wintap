using System;
using System.IO;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    public class SELinuxSensorHelperTests : IDisposable
    {
        private readonly string tempRoot;

        public SELinuxSensorHelperTests()
        {
            tempRoot = Path.Combine(Path.GetTempPath(), "selinux-decoder-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempRoot);
        }

        public void Dispose()
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }

        [Fact]
        [Trait("Category", "sel-03")]
        public void PermissionDecoder_LoadsClassesAndDecodesMasks()
        {
            CreatePermission("file", classIndex: 6, "read", bitIndex: 2);
            CreatePermission("file", classIndex: 6, "write", bitIndex: 3);
            CreatePermission("file", classIndex: 6, "open", bitIndex: 22);

            SELinuxPermissionDecoder decoder = SELinuxPermissionDecoder.LoadFromSelinuxFs(tempRoot);

            Assert.Equal(1, decoder.ClassCount);
            Assert.Equal(3, decoder.PermissionCount);
            Assert.Equal("file", decoder.GetClassName(6));
            Assert.True(decoder.TryGetClassIndex("file", out uint classIndex));
            Assert.Equal(6u, classIndex);
            Assert.Equal("read,write,open", decoder.DecodePermissions(6, 0x200006, out uint unknownBits));
            Assert.Equal(0u, unknownBits);
        }

        [Fact]
        [Trait("Category", "sel-03")]
        public void PermissionDecoder_ResolvesLoadedClassNamesWithoutHardCodedIndexes()
        {
            CreatePermission("cap_userns", classIndex: 80, "sys_admin", bitIndex: 1);

            SELinuxPermissionDecoder decoder = SELinuxPermissionDecoder.LoadFromSelinuxFs(tempRoot);

            Assert.True(decoder.TryGetClassIndex("cap_userns", out uint classIndex));
            Assert.Equal(80u, classIndex);
            Assert.Equal("sys_admin", decoder.DecodePermissions(classIndex, 0x1, out uint unknownBits));
            Assert.Equal(0u, unknownBits);
        }

        [Fact]
        [Trait("Category", "sel-03")]
        public void PermissionDecoder_PreservesUnknownBits()
        {
            CreatePermission("fd", classIndex: 8, "use", bitIndex: 1);

            SELinuxPermissionDecoder decoder = SELinuxPermissionDecoder.LoadFromSelinuxFs(tempRoot);
            string decoded = decoder.DecodePermissions(8, 0x11, out uint unknownBits);

            Assert.Equal("use,0x10", decoded);
            Assert.Equal(0x10u, unknownBits);
        }

        [Fact]
        [Trait("Category", "sel-03")]
        public void PermissionDecoder_UnknownClassReturnsNumericClassAndMaskBits()
        {
            SELinuxPermissionDecoder decoder = SELinuxPermissionDecoder.LoadFromSelinuxFs(tempRoot);

            Assert.Equal("99", decoder.GetClassName(99));
            Assert.Equal("0x1,0x4", decoder.DecodePermissions(99, 0x5, out uint unknownBits));
            Assert.Equal(0x5u, unknownBits);
        }

        [Fact]
        [Trait("Category", "sel-03")]
        public void SidResolver_LearnsAndClearsKnownContexts()
        {
            var resolver = new SELinuxSidResolver();

            resolver.Learn(42, "system_u:system_r:test_t:s0");
            string resolved = resolver.ResolveKnown(42, out bool hit);

            Assert.True(hit);
            Assert.Equal("system_u:system_r:test_t:s0", resolved);
            Assert.Equal(1, resolver.LearnedCount);

            resolver.Clear();
            resolved = resolver.ResolveKnown(42, out hit);

            Assert.False(hit);
            Assert.Equal(string.Empty, resolved);
            Assert.Equal(0, resolver.LearnedCount);
        }

        [Fact]
        [Trait("Category", "sel-03")]
        public void SidResolver_ResolveSourceMissesForInvalidPidWithoutDroppingSid()
        {
            var resolver = new SELinuxSidResolver();

            string resolved = resolver.ResolveSource(123, -1, out bool hit);

            Assert.False(hit);
            Assert.Equal(string.Empty, resolved);
            Assert.Equal(0, resolver.LearnedCount);
        }

        private void CreatePermission(string className, uint classIndex, string permissionName, uint bitIndex)
        {
            string classDir = Path.Combine(tempRoot, className);
            string permsDir = Path.Combine(classDir, "perms");
            Directory.CreateDirectory(permsDir);
            File.WriteAllText(Path.Combine(classDir, "index"), classIndex.ToString());
            File.WriteAllText(Path.Combine(permsDir, permissionName), bitIndex.ToString());
        }
    }
}
