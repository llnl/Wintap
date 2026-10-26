using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    public class DirIdentityIndexTests
    {
        [Fact]
        public void UnlinkUsesCapturedBaseAfterFdReuseOrProducerExit()
        {
            var index = new DirIdentityIndex(16);
            index.Put(1, 10, 100, "/fixture/Old");
            index.Put(1, 10, 200, "/fixture/new");
            // Same process/fd could now refer to 200, or no longer exist.
            // Neither is an input to resolution of the earlier event.
            Assert.Equal("/fixture/Old/Case.bin", index.ResolveUnlinkPath(1, 10, 100, "Case.bin"));
            Assert.Equal("/fixture/new/Case.bin", index.ResolveUnlinkPath(1, 10, 200, "Case.bin"));
            Assert.Equal("/absolute/Case.bin", index.ResolveUnlinkPath(0, 0, 0, "/absolute/Case.bin"));
        }

        [Fact]
        public void UnlinkUnknownNamespaceEvictionAndParentTraversalStayRelative()
        {
            var index = new DirIdentityIndex(1);
            index.Put(1, 10, 100, "/fixture/Old");
            Assert.Equal("Case.bin", index.ResolveUnlinkPath(2, 10, 100, "Case.bin"));
            Assert.Equal("../Case.bin", index.ResolveUnlinkPath(1, 10, 100, "../Case.bin"));
            Assert.Equal("Case.bin", index.ResolveUnlinkPath(0, 0, 0, "Case.bin"));
            index.Put(1, 10, 200, "/fixture/new");
            Assert.Equal("Case.bin", index.ResolveUnlinkPath(1, 10, 100, "Case.bin"));
            Assert.Null(index.ResolveUnlinkPath(1, 10, 200, null));
        }

        [Fact]
        public void PutThenGet_ReturnsPath()
        {
            var index = new DirIdentityIndex(16);
            index.Put(1, 10, 100, "/usr/lib/rpm");
            Assert.True(index.TryGet(1, 10, 100, out string path));
            Assert.Equal("/usr/lib/rpm", path);
            Assert.Equal(1, index.Count);
        }

        [Fact]
        public void NamespaceQualifiesTheKey()
        {
            // fop-13c: the same (dev, ino) seen from two mount namespaces must
            // never satisfy each other's lookups.
            var index = new DirIdentityIndex(16);
            index.Put(1, 10, 100, "/host/view");
            index.Put(2, 10, 100, "/container/view");

            Assert.True(index.TryGet(1, 10, 100, out string hostPath));
            Assert.Equal("/host/view", hostPath);
            Assert.True(index.TryGet(2, 10, 100, out string containerPath));
            Assert.Equal("/container/view", containerPath);
            Assert.False(index.TryGet(3, 10, 100, out _));
            Assert.Equal(2, index.Count);
        }

        [Fact]
        public void UpdateExistingKey_DoesNotGrowOrEvict()
        {
            var index = new DirIdentityIndex(2);
            index.Put(1, 10, 100, "/old");
            index.Put(1, 10, 100, "/new");
            Assert.Equal(1, index.Count);
            Assert.Equal(0, index.TakeEvictions());
            Assert.True(index.TryGet(1, 10, 100, out string path));
            Assert.Equal("/new", path);
        }

        [Fact]
        public void CapacityIsEnforced_AndEvictionsCounted()
        {
            var index = new DirIdentityIndex(3);
            for (ulong i = 0; i < 10; i++)
            {
                index.Put(1, 10, i, $"/dir/{i}");
            }
            Assert.Equal(3, index.Count);
            Assert.Equal(7, index.TakeEvictions());
        }

        [Fact]
        public void LruEviction_HotEntrySurvivesScanFlood()
        {
            // fop-13d: the field failure mode — a filesystem walk floods the
            // index with one-shot identities. A hot base dir that keeps
            // getting looked up must survive; FIFO would have evicted it.
            var index = new DirIdentityIndex(8);
            index.Put(1, 10, 999, "/usr/lib/rpm"); // the hot base dir

            for (ulong i = 0; i < 100; i++)
            {
                index.Put(1, 10, i, $"/scan/{i}");
                // Steady-state workload touches the hot entry between scan
                // insertions.
                Assert.True(index.TryGet(1, 10, 999, out _));
            }

            Assert.True(index.TryGet(1, 10, 999, out string path));
            Assert.Equal("/usr/lib/rpm", path);
            Assert.Equal(8, index.Count);
        }

        [Fact]
        public void FifoWouldFail_ColdEntryIsEvictedByScanFlood()
        {
            // Complement of the survival test: an entry that is never touched
            // again ages out under the same flood.
            var index = new DirIdentityIndex(8);
            index.Put(1, 10, 999, "/never/touched/again");
            for (ulong i = 0; i < 100; i++)
            {
                index.Put(1, 10, i, $"/scan/{i}");
            }
            Assert.False(index.TryGet(1, 10, 999, out _));
        }

        [Fact]
        public void GetRefreshesLruPosition()
        {
            var index = new DirIdentityIndex(2);
            index.Put(1, 1, 1, "/a");
            index.Put(1, 1, 2, "/b");
            // Touch /a so /b becomes the LRU victim.
            Assert.True(index.TryGet(1, 1, 1, out _));
            index.Put(1, 1, 3, "/c");

            Assert.True(index.TryGet(1, 1, 1, out _));
            Assert.False(index.TryGet(1, 1, 2, out _));
            Assert.True(index.TryGet(1, 1, 3, out _));
        }
    }
}
