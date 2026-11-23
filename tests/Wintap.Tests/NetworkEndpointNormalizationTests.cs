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

        [Fact]
        public void OppositeHostSensors_ShareConnectionId_WhenGatewayMetadataMovesEndpointSlots()
        {
            const string clientIp = "192.168.252.40";
            const string serverIp = "192.168.252.41";
            const string gateway = "192.168.252.1";
            ProcessConnIncrData client = CreateConnection(
                "TcpIpSend", clientIp, 58969, serverIp, 22, "client-host",
                new List<NIC> { CreateNic(clientIp, gateway) });
            ProcessConnIncrData server = CreateConnection(
                "TcpIpRecv", clientIp, 58969, serverIp, 22, "server-host",
                new List<NIC> { CreateNic(serverIp, gateway) });

            Assert.Equal(client.ConnId, server.ConnId);
            Assert.NotEqual(client.LocalIpAddr, server.LocalIpAddr);
            Assert.NotEqual(client.RemoteIpAddr, server.RemoteIpAddr);
            Assert.Contains(gateway, new[] { client.LocalIpPrivateGateway, client.RemoteIpPrivateGateway });
            Assert.Contains(gateway, new[] { server.LocalIpPrivateGateway, server.RemoteIpPrivateGateway });
        }

        [Fact]
        public void OrdinaryPrivateGateway_DoesNotChangeConnectionId()
        {
            const string localIp = "192.168.252.40";
            ProcessConnIncrData first = CreateConnection(
                "TcpIpSend", localIp, 58969, "192.168.252.41", 22, "test-host",
                new List<NIC> { CreateNic(localIp, "192.168.252.1") });
            ProcessConnIncrData second = CreateConnection(
                "TcpIpSend", localIp, 58969, "192.168.252.41", 22, "test-host",
                new List<NIC> { CreateNic(localIp, "192.168.252.254") });

            Assert.Equal(first.ConnId, second.ConnId);
            Assert.NotEqual(first.LocalIpPrivateGateway, second.LocalIpPrivateGateway);
        }

        [Fact]
        public void LoopbackConnectionId_RemainsScopedToHost()
        {
            ProcessConnIncrData firstHost = CreateConnection(
                "TcpIpSend", "127.0.0.2", 51000, "127.0.0.3", 41000,
                "first-host", new List<NIC>());
            ProcessConnIncrData secondHost = CreateConnection(
                "TcpIpSend", "127.0.0.2", 51000, "127.0.0.3", 41000,
                "second-host", new List<NIC>());
            ProcessConnIncrData reverseOnFirstHost = CreateConnection(
                "TcpIpRecv", "127.0.0.2", 51000, "127.0.0.3", 41000,
                "first-host", new List<NIC>());

            Assert.NotEqual(firstHost.ConnId, secondHost.ConnId);
            Assert.Equal(firstHost.ConnId, reverseOnFirstHost.ConnId);
            Assert.Equal(
                ConnectionId(
                    "first-host",
                    Converters.ConvertIpToLong("127.0.0.2"),
                    51000,
                    Converters.ConvertIpToLong("127.0.0.3"),
                    41000,
                    "TCP"),
                firstHost.ConnId);
        }

        [Fact]
        public void NonLoopbackConnectionId_UsesPublicContext_NotHostnameOrLegacyContext()
        {
            const string firstIp = "192.168.252.40";
            const string secondIp = "192.168.252.41";
            ProcessConnIncrData firstHost = CreateConnection(
                "TcpIpSend", firstIp, 58969, secondIp, 22,
                "first-host", new List<NIC>());
            ProcessConnIncrData secondHost = CreateConnection(
                "TcpIpSend", firstIp, 58969, secondIp, 22,
                "second-host", new List<NIC>());
            long firstIpLong = Converters.ConvertIpToLong(firstIp);
            long secondIpLong = Converters.ConvertIpToLong(secondIp);

            Assert.Equal(firstHost.ConnId, secondHost.ConnId);
            Assert.Equal(
                ConnectionId("public", firstIpLong, 58969, secondIpLong, 22, "TCP"),
                firstHost.ConnId);
            Assert.NotEqual(
                ConnectionId("llnl", firstIpLong, 58969, secondIpLong, 22, "TCP"),
                firstHost.ConnId);
        }

        [Fact]
        public void ConnectionId_ChangesWithContextAndEveryFiveTupleField()
        {
            const long firstIp = 0x0a000001;
            const long secondIp = 0x0a000002;
            string baseline = ConnectionId("public", firstIp, 49152, secondIp, 22, "TCP");

            Assert.NotEqual(baseline, ConnectionId("other-context", firstIp, 49152, secondIp, 22, "TCP"));
            Assert.NotEqual(baseline, ConnectionId("public", firstIp + 1, 49152, secondIp, 22, "TCP"));
            Assert.NotEqual(baseline, ConnectionId("public", firstIp, 49153, secondIp, 22, "TCP"));
            Assert.NotEqual(baseline, ConnectionId("public", firstIp, 49152, secondIp + 1, 22, "TCP"));
            Assert.NotEqual(baseline, ConnectionId("public", firstIp, 49152, secondIp, 23, "TCP"));
            Assert.NotEqual(baseline, ConnectionId("public", firstIp, 49152, secondIp, 22, "UDP"));
            Assert.Equal(baseline, ConnectionId("public", secondIp, 22, firstIp, 49152, "tcp"));
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

        private static ProcessConnIncrData CreateConnection(
            string activity,
            string sourceIp,
            int sourcePort,
            string destinationIp,
            int destinationPort,
            string hostname,
            List<NIC> activeNics)
        {
            EventBean bean = DispatchProxy.Create<EventBean, DictionaryEvent>();
            ((DictionaryEvent)(object)bean).Values = new Dictionary<string, object> {
                ["activityType"] = activity, ["protocol"] = "TCP",
                ["srcIp"] = sourceIp, ["destIp"] = destinationIp,
                ["srcPort"] = sourcePort, ["destPort"] = destinationPort,
                ["PID"] = 3291, ["firstSeen"] = 134372000000000000L,
                ["lastSeen"] = 134372000000000000L, ["eventCount"] = 1,
                ["packetSize"] = 100, ["initialSeqNum"] = 0
            };
            return Transformer.CreateProcessConn(bean, "test-process", activeNics, hostname);
        }

        private static NIC CreateNic(string ipAddress, string gateway)
        {
            return new NIC {
                IPAddess = ipAddress,
                IPAddrAsLong = Converters.ConvertIpToLong(ipAddress),
                GW = gateway,
                MAC = "001122334455"
            };
        }

        private static string ConnectionId(
            string identityContext,
            long firstIp,
            int firstPort,
            long secondIp,
            int secondPort,
            string protocol)
        {
            var tuple = new LoHi5Tuple(firstIp, secondIp, firstPort, secondPort, protocol);
            return new IdGenerator().GenKeyForFive_Tuple_Conn(
                identityContext,
                tuple.LoAddrStr,
                tuple.LoIPV4LongVal,
                "",
                tuple.LoIPPortInt,
                tuple.HiAddrStr,
                tuple.HiIPV4LongVal,
                "",
                tuple.HiIPPortInt,
                tuple.Protocol.ToUpper());
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
