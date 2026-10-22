using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Wintap.Tests
{
    public sealed class FileOpsRingWakeupPolicyTests
    {
        public static IEnumerable<object[]> FileOpsTiers()
        {
            yield return new object[] { "file_ops_tracer.bpf.c" };
            yield return new object[] { "file_ops_tracepoint.bpf.c" };
        }

        [Theory]
        [MemberData(nameof(FileOpsTiers))]
        [Trait("Category", "ldq-02")]
        public void SubmitUsesAdaptiveRingNotification(string sourceName)
        {
            string source = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, sourceName));
            string submitFunction = ExtractFunction(source, "static __always_inline void submit_file_event");

            Assert.Contains("bpf_ringbuf_submit(event, 0);", submitFunction, StringComparison.Ordinal);
            Assert.DoesNotContain("BPF_RB_NO_WAKEUP", submitFunction, StringComparison.Ordinal);
            Assert.DoesNotContain("BPF_RB_FORCE_WAKEUP", submitFunction, StringComparison.Ordinal);
        }

        private static string ExtractFunction(string source, string signature)
        {
            int start = source.IndexOf(signature, StringComparison.Ordinal);
            Assert.True(start >= 0, $"Missing function: {signature}");
            int nextFunction = source.IndexOf("static __always_inline", start + signature.Length, StringComparison.Ordinal);
            return nextFunction >= 0 ? source.Substring(start, nextFunction - start) : source.Substring(start);
        }
    }
}
