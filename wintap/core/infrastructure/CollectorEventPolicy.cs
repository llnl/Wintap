using gov.llnl.wintap.collect.models;

namespace gov.llnl.wintap.core.infrastructure
{
    // Isolate the policy from EventChannel/StateManager static runtime startup.
    internal static class CollectorEventPolicy
    {
        internal static bool ShouldSuppress(WintapMessage message, int collectorPid, bool isLinux)
        {
            // Inventory emits a genuine Refresh for the already-running collector.
            // Do not relax self-generated file/network filtering or other platforms.
            return message.PID == collectorPid &&
                !(isLinux && message.MessageType == WintapMessage.MessageTypeEnum.Process);
        }
    }
}
