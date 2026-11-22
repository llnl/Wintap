using System;
using gov.llnl.wintap.collect.models;
using Xunit;

namespace Wintap.Tests
{
    [Trait("TestKind", "unit")]
    [Trait("Execution", "synthetic")]
    public class WintapMessageTests
    {
        [Fact]
        [Trait("Category", "P1.1")]
        public void Constructor_SetsMessageTypeAndPid()
        {
            var message = new WintapMessage(DateTime.UtcNow, 1234, WintapMessage.MessageTypeEnum.Process);

            Assert.Equal(WintapMessage.MessageTypeEnum.Process, message.MessageType);
            Assert.Equal(1234, message.PID);
        }
    }
}
