using System;
using System.IO;
using System.Text.Json;
using gov.llnl.wintap.core.etl.extract;
using Xunit;

namespace Wintap.Tests
{
    public class NetworkSerializerContractTests
    {
        [Fact]
        public void NetworkSerializer_UsesEventAgentId()
        {
            Assert.Equal("agent-from-event", NetworkSerializerContract.GetAgentId("agent-from-event"));
        }

        [Fact]
        public void NetworkSerializer_RejectsMissingAgentId()
        {
            Assert.Throws<InvalidOperationException>(() => NetworkSerializerContract.GetAgentId(null));
        }

        [Fact]
        public void NetworkInactivityMessage_IsProducerNeutral()
        {
            Assert.DoesNotContain("ETW session provider", NetworkSerializerContract.InactivityMessage, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("No network events", NetworkSerializerContract.InactivityMessage);
        }

        [Fact]
        public void ShippedStateTemplate_HasNoAgentId()
        {
            string templatePath = Path.Combine(AppContext.BaseDirectory, "wintapstate.json");
            using JsonDocument template = JsonDocument.Parse(File.ReadAllText(templatePath));

            Assert.Equal(string.Empty, template.RootElement.GetProperty("AgentId").GetString());
        }
    }
}
