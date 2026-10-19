using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.Collections.Generic;
using System.Reflection;

namespace gov.llnl.wintap.core.infrastructure.health
{
    internal static class DefaultHealthChecks
    {
        internal static IReadOnlyList<IWintapHealthCheck> CreateAll(Func<string> unknownPidHashSentinelProvider = null)
        {
            Lazy<string> defaultSentinel = new Lazy<string>(() => new ProcessHash().GenPidHash(-1, 0));
            Func<string> provider = unknownPidHashSentinelProvider ?? (() => defaultSentinel.Value);
            return new IWintapHealthCheck[]
            {
                new PidHashMissingCheck(),
                new ProcessUnresolvedCheck(provider),
                new ProcessNameMissingCheck(),
                new PayloadMismatchCheck(),
                new PathUnqualifiedCheck()
            };
        }

        private abstract class HealthCheckBase : IWintapHealthCheck
        {
            public abstract string Name { get; }
            public abstract bool Passes(WintapMessage msg);
            public abstract string Describe(WintapMessage msg);

            protected static string Header(WintapMessage msg)
            {
                return $"PID={msg?.PID} ActivityType={msg?.ActivityType} EventTime={msg?.EventTime}";
            }

            protected static string ValueDescription(string name, string value)
            {
                if (value == null) return name + "=<null>";
                if (value.Length == 0) return name + "=<empty>";
                if (string.IsNullOrWhiteSpace(value)) return name + "=<whitespace>";
                return name + "=" + Truncate(value);
            }

            protected static string Truncate(string value)
            {
                return value != null && value.Length > 200 ? value.Substring(0, 200) : value;
            }
        }

        private sealed class PidHashMissingCheck : HealthCheckBase
        {
            public override string Name => "pidhash_missing";
            public override bool Passes(WintapMessage msg) => msg == null || !string.IsNullOrWhiteSpace(msg.PidHash);
            public override string Describe(WintapMessage msg) => Header(msg) + " " + ValueDescription("PidHash", msg?.PidHash);
        }

        private sealed class ProcessUnresolvedCheck : HealthCheckBase
        {
            private readonly Func<string> sentinelProvider;

            internal ProcessUnresolvedCheck(Func<string> sentinelProvider) => this.sentinelProvider = sentinelProvider;
            public override string Name => "process_unresolved";

            public override bool Passes(WintapMessage msg)
            {
                try
                {
                    if (msg == null) return true;
                    if (string.Equals(msg.ProcessName, "Unknown", StringComparison.OrdinalIgnoreCase)) return false;
                    string sentinel = sentinelProvider?.Invoke();
                    return string.IsNullOrEmpty(sentinel) || !string.Equals(msg.PidHash, sentinel, StringComparison.Ordinal);
                }
                catch { return true; }
            }

            public override string Describe(WintapMessage msg)
            {
                bool isSentinel = false;
                try
                {
                    string sentinel = sentinelProvider?.Invoke();
                    isSentinel = !string.IsNullOrEmpty(sentinel) && string.Equals(msg?.PidHash, sentinel, StringComparison.Ordinal);
                }
                catch { }
                return Header(msg) + " ProcessName=" + (msg?.ProcessName ?? "<null>") + " PidHashIsUnknownSentinel=" + isSentinel.ToString().ToLowerInvariant() + " ReceiveTime=" + msg?.ReceiveTime + " InspectionTimeUtc=" + DateTime.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }
        }

        private sealed class ProcessNameMissingCheck : HealthCheckBase
        {
            public override string Name => "processname_missing";
            public override bool Passes(WintapMessage msg) => msg == null || !string.IsNullOrWhiteSpace(msg.ProcessName);
            public override string Describe(WintapMessage msg) => Header(msg) + " " + ValueDescription("ProcessName", msg?.ProcessName);
        }

        private sealed class PayloadMismatchCheck : HealthCheckBase
        {
            private readonly PropertyInfo[] payloadProperties;

            internal PayloadMismatchCheck()
            {
                int count = HighestMessageTypeValue() + 1;
                payloadProperties = new PropertyInfo[count];
                foreach (WintapMessage.MessageTypeEnum type in Enum.GetValues(typeof(WintapMessage.MessageTypeEnum)))
                {
                    int index = (int)type;
                    string propertyName = type == WintapMessage.MessageTypeEnum.ProcessPartial ? "Process" : type.ToString();
                    payloadProperties[index] = typeof(WintapMessage).GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public);
                }
            }

            public override string Name => "payload_mismatch";
            public override bool Passes(WintapMessage msg)
            {
                try
                {
                    if (msg == null) return true;
                    int index = (int)msg.MessageType;
                    return index >= 0 && index < payloadProperties.Length && payloadProperties[index] != null && payloadProperties[index].GetValue(msg) != null;
                }
                catch { return true; }
            }

            public override string Describe(WintapMessage msg)
            {
                int value = msg == null ? int.MinValue : (int)msg.MessageType;
                if (value < 0 || value >= payloadProperties.Length) return Header(msg) + " unmapped MessageType value " + value;
                if (payloadProperties[value] == null) return Header(msg) + " no payload property for " + msg.MessageType;
                return Header(msg) + " payload is null for " + msg.MessageType;
            }
        }

        private sealed class PathUnqualifiedCheck : HealthCheckBase
        {
            public override string Name => "path_unqualified";

            public override bool Passes(WintapMessage msg)
            {
                try
                {
                    if (msg == null) return true;
                    if (msg.MessageType == WintapMessage.MessageTypeEnum.File) return IsQualifiedFile(msg.File?.Path);
                    if (msg.MessageType == WintapMessage.MessageTypeEnum.Registry) return IsQualifiedRegistry(msg.Registry?.Path);
                    return true;
                }
                catch { return true; }
            }

            public override string Describe(WintapMessage msg)
            {
                if (msg?.MessageType == WintapMessage.MessageTypeEnum.File && msg.File == null) return Header(msg) + " no payload";
                if (msg?.MessageType == WintapMessage.MessageTypeEnum.Registry && msg.Registry == null) return Header(msg) + " no payload";
                string path = msg?.MessageType == WintapMessage.MessageTypeEnum.File ? msg.File?.Path : msg?.Registry?.Path;
                return Header(msg) + " Path=" + (path == null ? "<null>" : Truncate(path));
            }

            private static bool IsQualifiedFile(string path)
            {
                if (string.IsNullOrWhiteSpace(path)) return false;
                return (path.Length >= 3 && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1] == ':' && path[2] == '\\')
                    || path.StartsWith("\\\\", StringComparison.Ordinal)
                    || path.StartsWith("\\device\\", StringComparison.OrdinalIgnoreCase);
            }

            private static bool IsQualifiedRegistry(string path)
            {
                return !string.IsNullOrWhiteSpace(path) && (string.Equals(path, "registry", StringComparison.OrdinalIgnoreCase) || path.StartsWith("registry\\", StringComparison.OrdinalIgnoreCase));
            }
        }

        private static int HighestMessageTypeValue()
        {
            int highest = 0;
            foreach (WintapMessage.MessageTypeEnum type in Enum.GetValues(typeof(WintapMessage.MessageTypeEnum))) highest = Math.Max(highest, (int)type);
            return highest;
        }
    }
}
