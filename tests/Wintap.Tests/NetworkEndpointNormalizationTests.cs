using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using com.espertech.esper.common.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.transform;
using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.etl.models;
using Xunit;

namespace Wintap.Tests
{
    public class NetworkEndpointNormalizationTests
    {
        [Theory]
        [InlineData("TcpIpRecv")]
        [InlineData("TcpIp/Recv")]
        [InlineData("tcpiprecv")]
        [InlineData("TcpIpAccept")]
        [InlineData("TcpIp/Accept")]
        [InlineData("TcpIpTCPCopy")]
        [InlineData("TcpIp/TCPCopy")]
        [InlineData("UdpIpRecv")]
        [InlineData("UdpIp/Recv")]
        public void InboundTuples_KeepHostLocal(string activity)
        {
            AssertEndpoints(activity, true);
        }

        [Theory]
        [InlineData("TcpIpSend")]
        [InlineData("TcpIp/Send")]
        [InlineData("TcpIpConnect")]
        [InlineData("TcpIp/Connect")]
        [InlineData("TcpIpDisconnect")]
        [InlineData("UdpIpSend")]
        [InlineData("UdpIp/Send")]
        public void OutboundTuples_KeepHostLocal(string activity)
        {
            AssertEndpoints(activity, false);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ClientEndpoint_IsLocalEvenWhenPeerOwnsPort22(bool inbound)
        {
            AssertEndpoints(inbound ? "TcpIpRecv" : "TcpIpSend", inbound, 58969, 22);
        }

        [Fact]
        public void BidirectionalEvents_RetainSameConnectionIdAndLocalEndpoint()
        {
            var send = AssertEndpoints("TcpIpSend", false);
            var recv = AssertEndpoints("TcpIpRecv", true);
            Assert.Equal(send.ConnId, recv.ConnId);
            Assert.Equal(send.LocalIpAddr, recv.LocalIpAddr);
            Assert.Equal(send.LocalPort, recv.LocalPort);
        }

        [Fact]
        public void SameIpSamePid_BothSocketRolesKeepDirectedProvenance()
        {
            var serverSend = AssertEndpoints("TcpIpSend", false, 41000, 51000, "192.168.252.40");
            var serverRecv = AssertEndpoints("TcpIpRecv", true, 41000, 51000, "192.168.252.40");
            var clientSend = AssertEndpoints("TcpIpSend", false, 51000, 41000, "192.168.252.40");
            var clientRecv = AssertEndpoints("TcpIpRecv", true, 51000, 41000, "192.168.252.40");
            Assert.Equal(serverSend.ConnId, clientRecv.ConnId);
            Assert.Equal(serverRecv.PidHash, clientSend.PidHash);
            Assert.NotEqual(serverRecv.LocalPort, clientRecv.LocalPort);
            Assert.Equal(serverSend.SourcePort, clientSend.DestinationPort);
        }

        private static ProcessConnIncrData AssertEndpoints(string activity, bool inbound, int localPort = 22, int remotePort = 58969, string peerIp = "192.168.252.1")
        {
            EventBean bean = DispatchProxy.Create<EventBean, DictionaryEvent>();
            ((DictionaryEvent)(object)bean).Values = new Dictionary<string, object> {
                ["activityType"] = activity, ["protocol"] = activity.StartsWith("Udp") ? "UDP" : "TCP",
                ["srcIp"] = inbound ? peerIp : "192.168.252.40",
                ["destIp"] = inbound ? "192.168.252.40" : peerIp,
                ["srcPort"] = inbound ? remotePort : localPort, ["destPort"] = inbound ? localPort : remotePort,
                ["PID"] = 3291, ["firstSeen"] = 134372000000000000L,
                ["lastSeen"] = 134372000000000000L, ["eventCount"] = 1,
                ["packetSize"] = 100, ["initialSeqNum"] = 0
            };
            var result = Transformer.CreateProcessConn(bean, "test-process", new List<NIC>(), "test-host");
            Assert.Equal(0xc0a8fc28L, result.LocalIpAddr);
            Assert.Equal(localPort, result.LocalPort);
            Assert.Equal((long)Converters.ConvertIpToLong(peerIp), result.RemoteIpAddr);
            Assert.Equal(remotePort, result.RemotePort);
            Assert.Equal(inbound ? remotePort : localPort, result.SourcePort);
            Assert.Equal(inbound ? localPort : remotePort, result.DestinationPort);
            // Preserve the recorded activity spelling; only direction is normalized.
            Assert.Equal(activity, result.IpEvent);
            return result;
        }

        [Fact]
        public void EveryNetworkEnumMember_HasExplicitDirectionAndLegacyAlias()
        {
            foreach (var activity in Enum.GetValues<WintapMessage.ActivityTypeEnum>().Where(a =>
                a.ToString().StartsWith("TcpIp") || a.ToString().StartsWith("UdpIp")))
            {
                string name = activity.ToString();
                bool expected = new[] { "TcpIpAccept", "TcpIpRecv", "TcpIpRecvIPV6", "TcpIpTCPCopy", "UdpIpRecv" }.Contains(name);
                Assert.Equal(expected, NetworkActivity.IsInbound(activity));
                Assert.Equal(expected, NetworkActivity.IsInbound(name));
                Assert.Equal(expected, NetworkActivity.IsInbound(name.Insert(5, "/")));
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("Read")]
        [InlineData("TcpIpRecvv")]
        [InlineData("999")]
        [InlineData(" 21 ")]
        [InlineData("TcpIpRecv, TcpIpSend")]
        public void UnknownActivities_DoNotSilentlyBecomeOutbound(string activity)
        {
            Assert.Throws<ArgumentException>(() => NetworkActivity.IsInbound(activity));
        }

        public class DictionaryEvent : DispatchProxy
        {
            public Dictionary<string, object> Values { get; set; }
            protected override object Invoke(MethodInfo method, object[] args)
            {
                if (method.Name == "get_Item") return Values[(string)args[0]];
                throw new NotSupportedException(method.Name);
            }
        }
    }
}
