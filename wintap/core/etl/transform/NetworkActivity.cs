using System;
using gov.llnl.wintap.collect.models;

namespace gov.llnl.wintap.core.etl.transform
{
    /// <summary>Direction of normalized WintapAPI tuples, not native ETW socket tuples.</summary>
    internal static class NetworkActivity
    {
        internal static bool IsInbound(string name)
        {
            // Legacy parquet/ETW names contain '/'; current producers emit enum names.
            string canonical = name?.Trim().Replace("/", "");
            if (string.IsNullOrWhiteSpace(canonical) ||
                !Enum.TryParse(canonical, true, out WintapMessage.ActivityTypeEnum activity) ||
                !canonical.Equals(activity.ToString(), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"Unknown network activity: {name}", nameof(name));
            return IsInbound(activity);
        }

        internal static bool IsInbound(WintapMessage.ActivityTypeEnum activity)
        {
            switch (activity)
            {
                case WintapMessage.ActivityTypeEnum.TcpIpAccept:
                case WintapMessage.ActivityTypeEnum.TcpIpRecv:
                case WintapMessage.ActivityTypeEnum.TcpIpRecvIPV6:
                case WintapMessage.ActivityTypeEnum.TcpIpTCPCopy:
                case WintapMessage.ActivityTypeEnum.UdpIpRecv:
                    return true;
                case WintapMessage.ActivityTypeEnum.TcpIpReconnect:
                case WintapMessage.ActivityTypeEnum.TcpIpRetransmit:
                case WintapMessage.ActivityTypeEnum.TcpIpDisconnect:
                case WintapMessage.ActivityTypeEnum.TcpIpARPCopy:
                case WintapMessage.ActivityTypeEnum.TcpIpDupACK:
                case WintapMessage.ActivityTypeEnum.TcpIpFullACK:
                case WintapMessage.ActivityTypeEnum.TcpIpPartACK:
                case WintapMessage.ActivityTypeEnum.TcpIpConnect:
                case WintapMessage.ActivityTypeEnum.TcpIpSend:
                case WintapMessage.ActivityTypeEnum.TcpIpSendIPV6:
                case WintapMessage.ActivityTypeEnum.TcpIpFail:
                case WintapMessage.ActivityTypeEnum.UdpIpFail:
                case WintapMessage.ActivityTypeEnum.UdpIpSend:
                    return false;
                default:
                    // New/invalid activities must not silently become outbound.
                    throw new ArgumentException($"Unclassified network activity: {activity}", nameof(activity));
            }
        }
    }
}
