using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class EtlShutdownBarrierTests
    {
        [Theory]
        [InlineData(true, "true", true)]
        [InlineData(true, "1", true)]
        [InlineData(true, null, false)]
        [InlineData(true, "false", false)]
        [InlineData(false, "true", false)]
        public void BarrierIsExplicitAndLinuxOnly(bool linux, string value, bool expected) =>
            Assert.Equal(expected, EtlShutdownBarrier.Enabled(linux, value));

        [Fact]
        public async Task ClockFreezesBeforePendingWindowCompletion()
        {
            var order = new List<string>();
            await EtlShutdownBarrier.FinishWindowsAsync(() => order.Add("freeze"),
                () => { order.Add("read-clock"); return 12345; },
                target => { order.Add("advance"); Assert.Equal(22345, target); }, TimeSpan.FromSeconds(30));
            Assert.Equal(new[] { "freeze", "read-clock", "advance" }, order);
        }

        [Fact]
        public async Task ClockFailureOrOverflowNeverReturnsSuccessfulBarrier()
        {
            bool advance = false;
            await Assert.ThrowsAsync<InvalidOperationException>(() => EtlShutdownBarrier.FinishWindowsAsync(
                () => throw new InvalidOperationException(), () => 0, _ => advance = true, TimeSpan.FromSeconds(30)));
            await Assert.ThrowsAsync<OverflowException>(() => EtlShutdownBarrier.FinishWindowsAsync(
                () => { }, () => long.MaxValue, _ => advance = true, TimeSpan.FromSeconds(30)));
            Assert.False(advance);
        }

        [Fact]
        public async Task TimeoutDoesNotAdmitSerializerDrainOrCancelAnInFlightNativeCall()
        {
            using var release = new ManualResetEventSlim();
            var finished = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            bool drainAdmitted = false;
            try
            {
                await Assert.ThrowsAsync<TimeoutException>(async () => {
                    await EtlShutdownBarrier.FinishWindowsAsync(() => release.Wait(), () => 0,
                        _ => finished.TrySetResult(true), TimeSpan.FromMilliseconds(20));
                    drainAdmitted = true;
                });
                Assert.False(drainAdmitted);
            }
            finally { release.Set(); }
            // Native work is not claimed cancellable; release/join test worker.
            await finished.Task.WaitAsync(TimeSpan.FromSeconds(30));
        }

        [Fact]
        public async Task CallbackCutoffWaitsForAdmittedWorkAndRefusesLaterAdmission()
        {
            var admission = new SerializerCallbackAdmission();
            Assert.True(admission.TryEnter());
            Assert.True(admission.TryEnter());
            Task joined = admission.Close();
            Assert.False(joined.IsCompleted);
            Assert.False(admission.TryEnter());
            admission.Exit();
            Assert.False(joined.IsCompleted);
            admission.Exit();
            await joined;
            Assert.Same(joined, admission.Close());
            Assert.False(admission.TryEnter());
            Assert.Throws<InvalidOperationException>(() => admission.Exit());
        }

        [Fact]
        public async Task CallbackJoinDeadlineFailsWithoutChangingInFlightAdmission()
        {
            var admission = new SerializerCallbackAdmission();
            Assert.True(admission.TryEnter());
            Task joined = admission.Close();
            await Assert.ThrowsAsync<TimeoutException>(() => joined.WaitAsync(TimeSpan.FromMilliseconds(20)));
            Assert.False(joined.IsCompleted);
            admission.Exit();
            await joined;
        }
    }
}
