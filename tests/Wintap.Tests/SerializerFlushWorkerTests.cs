using System;
using System.Threading;
using gov.llnl.wintap.core.etl.extract;
using Xunit;

namespace Wintap.Tests
{
    public class SerializerFlushWorkerTests
    {
        [Fact]
        public void RequestDuringDrain_IsNotLostAndRunsOutsideThreadPool()
        {
            int depth = 10, drains = 0;
            bool usedPool = true;
            using var entered = new ManualResetEventSlim();
            using var release = new ManualResetEventSlim();
            using var complete = new ManualResetEventSlim();
            using var worker = new SerializerFlushWorker(TimeSpan.FromSeconds(30), () => Volatile.Read(ref depth) >= 10,
                _ =>
                {
                    usedPool = Thread.CurrentThread.IsThreadPoolThread;
                    Interlocked.Add(ref depth, -10);
                    if (Interlocked.Increment(ref drains) == 1)
                    {
                        entered.Set();
                        release.Wait(TimeSpan.FromSeconds(5));
                    }
                    else complete.Set();
                }, _ => { });
            try
            {
                worker.Request();
                Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
                Interlocked.Add(ref depth, 10);
                for (int i = 0; i < 100; i++) worker.Request();
                release.Set();
                Assert.True(complete.Wait(TimeSpan.FromSeconds(5)));
                Assert.Equal(0, Volatile.Read(ref depth));
                Assert.Equal(2, Volatile.Read(ref drains));
                Assert.False(usedPool);
            }
            finally { release.Set(); }
        }

        [Fact]
        public void TimerDrainsLowVolumeWithoutHighWaterRequest()
        {
            string trigger = null;
            using var complete = new ManualResetEventSlim();
            using var worker = new SerializerFlushWorker(TimeSpan.FromMilliseconds(20), () => false,
                value => { trigger = value; complete.Set(); }, _ => { });
            Assert.True(complete.Wait(TimeSpan.FromSeconds(5)));
            Assert.Equal("timer", trigger);
        }

        [Fact]
        public void FailedDrainIsReportedAndPendingWorkIsRetried()
        {
            int depth = 10, attempts = 0, errors = 0;
            using var complete = new ManualResetEventSlim();
            using var worker = new SerializerFlushWorker(TimeSpan.FromSeconds(30), () => Volatile.Read(ref depth) > 0,
                _ =>
                {
                    if (Interlocked.Increment(ref attempts) == 1) throw new InvalidOperationException("test failure");
                    Interlocked.Exchange(ref depth, 0);
                    complete.Set();
                }, _ => Interlocked.Increment(ref errors));
            worker.Request();
            Assert.True(complete.Wait(TimeSpan.FromSeconds(5)));
            Assert.Equal(1, Volatile.Read(ref errors));
            Assert.Equal(2, Volatile.Read(ref attempts));
        }
    }
}
