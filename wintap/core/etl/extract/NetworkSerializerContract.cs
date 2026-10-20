using System;

namespace gov.llnl.wintap.core.etl.extract
{
    /// <summary>
    /// Shared invariants for TCP and UDP serializer output.
    /// </summary>
    internal static class NetworkSerializerContract
    {
        internal const string InactivityMessage =
            "No network events have been received for 60 seconds. Restart Wintap if this is unexpected.";

        internal static string GetAgentId(object agentId)
        {
            if (agentId == null)
            {
                throw new InvalidOperationException("Network event is missing AgentId.");
            }

            return agentId.ToString();
        }
    }
}
