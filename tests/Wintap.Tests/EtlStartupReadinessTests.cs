using System;
using System.Threading;
using System.Threading.Tasks;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class EtlStartupReadinessTests
    {
        [Theory]
        [InlineData(true, "true", true)]
        [InlineData(true, "1", true)]
        [InlineData(true, null, false)]
        [InlineData(true, "false", false)]
        [InlineData(false, "true", false)]
        public void ExperimentalPolicyIsExplicitAndLinuxOnly(bool linux, string value, bool expected) =>
            Assert.Equal(expected, EtlStartupReadiness.Enabled(linux, value));

        [Fact]
        public async Task ProducerCannotProceedUntilActualCompletion()
        {
            var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            bool producerStarted = false;
            async Task Start()
            {
                await EtlStartupReadiness.RequireAsync(ready.Task, TimeSpan.FromSeconds(2));
                producerStarted = true;
            }
            var start = Start();
            Assert.False(start.IsCompleted);
            Assert.False(producerStarted);
            ready.SetResult(true);
            await start;
            Assert.True(producerStarted);
        }

        [Fact]
        public async Task FailureTimeoutAndCancellationNeverAdmitProducers()
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                EtlStartupReadiness.RequireAsync(Task.FromResult(false), TimeSpan.FromSeconds(1)));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                EtlStartupReadiness.RequireAsync(null, TimeSpan.FromSeconds(1)));
            var pending = new TaskCompletionSource<bool>();
            await Assert.ThrowsAsync<TimeoutException>(() =>
                EtlStartupReadiness.RequireAsync(pending.Task, TimeSpan.FromMilliseconds(10)));
            using var cancel = new CancellationTokenSource();
            cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                EtlStartupReadiness.RequireAsync(pending.Task, TimeSpan.FromSeconds(1), cancel.Token));
            Assert.False(pending.Task.IsCompleted);
        }
    }
}
