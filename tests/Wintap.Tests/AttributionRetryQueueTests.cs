using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using Xunit;

namespace Wintap.Tests
{
    public class AttributionRetryQueueTests
    {
        private static WintapMessage Message() => new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.Registry);
        [Fact]
        public void RetriesWaitAndPreserveOriginalMessageExactlyOnce()
        {
            long now = 0; var calls = new List<(WintapMessage Message, int Attempt)>();
            var queue = new AttributionRetryQueue((m, n) => calls.Add((m, n)), clock: () => now, startTimer: false);
            var message = Message(); long eventTime = message.EventTime, receiveTime = message.ReceiveTime;
            Assert.True(queue.TrySchedule(message, 0));
            now = 999; queue.Pump(); Assert.Empty(calls);
            now = 1000; Parallel.For(0, 20, _ => queue.Pump());
            var call = Assert.Single(calls); Assert.Same(message, call.Message); Assert.Equal(1, call.Attempt);
            Assert.Equal(eventTime, message.EventTime); Assert.Equal(receiveTime, message.ReceiveTime);
            queue.Shutdown(); Assert.Single(calls);
        }
        [Fact]
        public void PermanentMissGetsTenRetriesAndOneFinalEmission()
        {
            long now = 0; int attempts = 0, emitted = 0;
            AttributionRetryQueue queue = null;
            queue = new AttributionRetryQueue((m, n) => {
                attempts++; if (!queue.TrySchedule(m, n)) emitted++;
            }, clock: () => now, startTimer: false);
            Assert.True(queue.TrySchedule(Message(), 0));
            for (int i = 1; i <= 12; i++) { now = i * 1000; queue.Pump(); }
            Assert.Equal(10, attempts); Assert.Equal(1, emitted); queue.Shutdown();
        }
        [Fact]
        public void CapacityFailureIsExplicitAndShutdownForcesFinalAttempts()
        {
            var attempts = new List<int>();
            var queue = new AttributionRetryQueue((m, n) => attempts.Add(n), capacity: 2, startTimer: false);
            Assert.True(queue.TrySchedule(Message(), 0)); Assert.True(queue.TrySchedule(Message(), 0));
            Assert.False(queue.TrySchedule(Message(), 0));
            queue.Shutdown(); Assert.Equal(new[] { 10, 10 }, attempts);
            Assert.False(queue.TrySchedule(Message(), 0)); queue.Pump(); queue.Shutdown(); Assert.Equal(2, attempts.Count);
        }
        [Fact]
        public void CallbackFailureDoesNotPreventOtherRetries()
        {
            long now = 0; int calls = 0, errors = 0;
            var queue = new AttributionRetryQueue((m, n) => {
                if (++calls == 1) throw new InvalidOperationException();
            }, clock: () => now, startTimer: false, onError: _ => errors++);
            queue.TrySchedule(Message(), 0); queue.TrySchedule(Message(), 0);
            now = 1000; queue.Pump(); Assert.Equal(2, calls); Assert.Equal(1, errors); queue.Shutdown();
        }
        [Theory]
        [InlineData(WintapMessage.MessageTypeEnum.File)]
        [InlineData(WintapMessage.MessageTypeEnum.TcpConnection)]
        [InlineData(WintapMessage.MessageTypeEnum.UdpPacket)]
        [InlineData(WintapMessage.MessageTypeEnum.ImageLoad)]
        public void SelectedStreamRetriesUntilIdentityArrives(WintapMessage.MessageTypeEnum stream)
        {
            long now = 0; bool identityAvailable = false; int emitted = 0;
            AttributionRetryQueue queue = null;
            var message = new WintapMessage(DateTime.UtcNow, 42, stream);
            long eventTime = message.EventTime, receiveTime = message.ReceiveTime;
            queue = new AttributionRetryQueue((m, attempt) => {
                Assert.Same(message, m);
                if (!identityAvailable && queue.TrySchedule(m, attempt)) return;
                Assert.True(identityAvailable);
                emitted++;
            }, clock: () => now, startTimer: false, enabledStreams: "Registry," + stream);
            Assert.True(queue.TrySchedule(message, 0));
            now = 1000; queue.Pump(); Assert.Equal(0, emitted);
            identityAvailable = true;
            now = 2000; queue.Pump(); queue.Shutdown();
            Assert.Equal(1, emitted);
            Assert.Equal(eventTime, message.EventTime); Assert.Equal(receiveTime, message.ReceiveTime);
        }

        [Fact]
        public void SelectionIsCaseInsensitiveAndCanDisableRegistry()
        {
            var queue = new AttributionRetryQueue((_, _) => { }, startTimer: false, enabledStreams: " file, TCPConnection ");
            Assert.False(queue.TrySchedule(Message(), 0));
            Assert.True(queue.TrySchedule(new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.File), 0));
            queue.Shutdown();
            Assert.Empty(AttributionRetryQueue.ParseStreams("none"));
            Assert.Empty(AttributionRetryQueue.ParseStreams(""));
        }

        [Theory]
        [InlineData("Process")]
        [InlineData("ProcessPartial")]
        [InlineData("Typo")]
        [InlineData("999")]
        [InlineData("5")]
        public void InvalidOrIdentityProducingStreamsAreRejected(string streams)
        {
            Assert.Throws<ArgumentException>(() => AttributionRetryQueue.ParseStreams(streams));
        }

        [Fact]
        public void DefaultSelectionIncludesLifecycleDependentStreams()
        {
            var queue = new AttributionRetryQueue((_, _) => throw new Exception(), startTimer: false);
            var message = Message(); message.MessageType = WintapMessage.MessageTypeEnum.File;
            Assert.True(queue.TrySchedule(message, 0));
            Assert.True(queue.TrySchedule(new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.TcpConnection), 0));
            Assert.True(queue.TrySchedule(new WintapMessage(DateTime.UtcNow, 42, WintapMessage.MessageTypeEnum.UdpPacket), 0));
            Assert.False(queue.TrySchedule(null, 0)); queue.Shutdown();
        }
    }
}
