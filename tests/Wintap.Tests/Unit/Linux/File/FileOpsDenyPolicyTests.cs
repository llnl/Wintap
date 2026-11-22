using System;
using System.Linq;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Wintap.Tests
{
    [Trait("TestKind", "unit")]
    [Trait("Execution", "synthetic")]
    public class FileOpsDenyPolicyTests
    {
        [Fact]
        public void Parse_EmptyConfiguration_DisablesPolicy()
        {
            Assert.Empty(FileOpsDenyPolicy.Parse(""));
        }

        [Fact]
        public void Parse_UsesExactDeduplicatedRules()
        {
            var rules = FileOpsDenyPolicy.Parse("scanner, scanner, helper");

            Assert.Equal(new[] { "scanner", "helper" }, rules);
        }

        [Fact]
        public void Parse_RejectsTruncatedComm()
        {
            Assert.Throws<ArgumentException>(() => FileOpsDenyPolicy.Parse("sixteen-byte-name"));
        }

        [Fact]
        public void Parse_RejectsTooManyRules()
        {
            string configured = string.Join(',', Enumerable.Range(0, FileOpsDenyPolicy.MaxRules + 1).Select(index => $"r{index}"));

            Assert.Throws<ArgumentException>(() => FileOpsDenyPolicy.Parse(configured));
        }
    }
}
