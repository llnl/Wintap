using System;
using gov.llnl.wintap.collect.models;

namespace gov.llnl.wintap.core.infrastructure
{
    // Isolated from EventChannel initialization so tests exercise the production policy.
    internal static class EventOwnerSelection
    {
        private static bool IsRegistryTeardownWrite(WintapMessage message)
        {
            if (message.MessageType != WintapMessage.MessageTypeEnum.Registry ||
                message.ActivityType != WintapMessage.ActivityTypeEnum.Write ||
                message.Registry?.Path == null ||
                string.IsNullOrWhiteSpace(message.Registry.ValueName)) return false;
            string[] path = message.Registry.Path.TrimStart('\\').Split('\\');
            if (path.Length != 9) return false;
            bool Same(int index, string value) => string.Equals(path[index], value, StringComparison.OrdinalIgnoreCase);
            bool controlSet = Same(3, "currentcontrolset") ||
                (path[3].Length == 13 && path[3].StartsWith("controlset", StringComparison.OrdinalIgnoreCase) &&
                 int.TryParse(path[3].Substring(10), out _));
            return Same(0, "registry") && Same(1, "machine") && Same(2, "system") && controlSet &&
                Same(4, "services") && Same(5, "bam") && Same(6, "state") && Same(7, "usersettings") &&
                path[8].StartsWith("S-1-", StringComparison.OrdinalIgnoreCase);
        }
        internal static ProcessRecord ResolveOwner(IProcessResolver resolver, WintapMessage message,
            DateTime eventTimeUtc, bool isWindows, out bool? fileCacheHit)
        {
            fileCacheHit = null;
            bool isFile = message.MessageType == WintapMessage.MessageTypeEnum.File;
            // Linux eBPF callbacks can synchronously stamp an identity from the
            // active cache or live /proc before their short-lived owner exits.
            // File and network events use that narrow producer-side path; do not
            // treat arbitrary identities on other event families as authoritative.
            bool canUsePrepopulatedIdentity = isFile ||
                message.MessageType == WintapMessage.MessageTypeEnum.TcpConnection ||
                message.MessageType == WintapMessage.MessageTypeEnum.UdpPacket ||
                message.MessageType == WintapMessage.MessageTypeEnum.SELinuxAvc ||
                message.MessageType == WintapMessage.MessageTypeEnum.SELinuxTransition ||
                message.MessageType == WintapMessage.MessageTypeEnum.SELinuxInteraction;
            if (canUsePrepopulatedIdentity && !string.IsNullOrWhiteSpace(message.PidHash) &&
                !string.IsNullOrWhiteSpace(message.ProcessName))
            {
                return new ProcessRecord
                {
                    PidHash = message.PidHash,
                    ProcessId = message.PID,
                    ProcessName = message.ProcessName,
                    CreateTime = eventTimeUtc
                };
            }

            // Prefer the active cache on every platform/event family. On Linux,
            // eBPF file and network callbacks may immediately follow a Clone or
            // Execve lifecycle event.  The active cache is updated synchronously
            // when that lifecycle event is registered, while a durable lookup can
            // miss transiently and turn an otherwise known network event into an
            // Unknown identity.
            bool hit = resolver.TryResolveCurrentProcessAtTime(message.PID, eventTimeUtc, out ProcessRecord owner);
            if (isFile) fileCacheHit = hit;
            if (hit) return owner;

            owner = resolver.ResolveProcessIdentityAtTime(message.PID, eventTimeUtc);
            if (owner == null && isWindows && IsRegistryTeardownWrite(message))
                owner = resolver.ResolveRegistryTeardownProcess(message.PID, eventTimeUtc);
            return owner;
        }
    }
}
