/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using com.espertech.esper.client;
using com.espertech.esper.common.client;
using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.etl.shared;
using System;
using System.Collections.Generic;
using System.Linq;

namespace gov.llnl.wintap.core.etl.transform
{
    internal class Transformer
    {
        internal static string context = "llnl";


        internal static ProcessConnIncrData CreateProcessConn(EventBean newEvent, string _pidhash, List<NIC> activeNics)
        {
            return CreateProcessConn(newEvent, _pidhash, activeNics, HostSerializer.Instance.HostId.Hostname);
        }

        internal static ProcessConnIncrData CreateProcessConn(EventBean newEvent, string _pidhash, List<NIC> activeNics, string hostname)
        {
            bool inbound = NetworkActivity.IsInbound(newEvent["activityType"].ToString());
            LoHi5Tuple loHi = createLoHi5TupleFrom(newEvent);
            string loGW = derivePrivateGateway(loHi.LoIPV4LongVal, hostname, activeNics);
            string hiGW = derivePrivateGateway(loHi.HiIPV4LongVal, hostname, activeNics);
            IpV4Addr loIp = createIpAddr(loHi.LoAddrStr, (uint)loHi.LoIPV4LongVal, loGW);
            IpV4Addr hiIp = createIpAddr(loHi.HiAddrStr, (uint)loHi.HiIPV4LongVal, hiGW);
            IdGenerator idgen = new IdGenerator();
            string connId = idgen.GenKeyForFive_Tuple_Conn(context, loHi.LoAddrStr, loHi.LoIPV4LongVal, loGW, loHi.LoIPPortInt, loHi.HiAddrStr, loHi.HiIPV4LongVal, hiGW, loHi.HiIPPortInt, loHi.Protocol.ToUpper());
            ProcessConnIncrData pci = new ProcessConnIncrData();
            pci.ConnId = connId;
            pci.LocalIpPrivateGateway = loGW;
            pci.RemoteIpPrivateGateway = hiGW;

            pci.PID = Convert.ToInt32(newEvent["PID"].ToString());
            pci.PidHash = _pidhash;
            pci.SourcePort = Convert.ToInt32(newEvent["srcPort"]);
            pci.DestinationPort = Convert.ToInt32(newEvent["destPort"]);
            if (inbound)
            {
                pci.LocalIpAddr = Converters.ConvertIpToLong(newEvent["destIp"].ToString());  //destIpAddr
                pci.LocalPort = Convert.ToInt32(newEvent["destPort"]); // destPort
                pci.RemoteIpAddr = Converters.ConvertIpToLong(newEvent["srcIp"].ToString());
                pci.RemotePort = Convert.ToInt32(newEvent["srcPort"].ToString());
            }
            else
            {
                pci.LocalIpAddr = Converters.ConvertIpToLong(newEvent["srcIp"].ToString());
                pci.LocalPort = Convert.ToInt32(newEvent["srcPort"].ToString()); ;
                pci.RemoteIpAddr = Converters.ConvertIpToLong(newEvent["destIp"].ToString());
                pci.RemotePort = Convert.ToInt32(newEvent["destPort"]);
            }
            pci.Protocol = getProtocol(loHi);
            pci.FirstSeenMs = Int64.Parse(newEvent["firstSeen"].ToString());
            pci.LastSeenMs = Int64.Parse(newEvent["lastSeen"].ToString());
            pci.EventCount = Int32.Parse(newEvent["eventCount"].ToString());
            pci.PacketSize = Int32.Parse(newEvent["packetSize"].ToString());
            pci.IncrType = "10sec";
            if (pci.Protocol == "TCP")
            {
                pci.InitialSeq = Convert.ToInt32(newEvent["initialSeqNum"].ToString());
            }
            pci.IpEvent = newEvent["activityType"].ToString();
            return pci;
        }

        internal static IpV4Addr createIpAddr(string ip, uint ipLong, string gw)
        {
            IdGenerator idgen = new IdGenerator();
            string hash = idgen.GenKeyForIPV4_Address(context, ip.ToString(), gw, ipLong);
            IpV4Addr ipv4Addr = new IpV4Addr();
            ipv4Addr.Hash = hash;
            ipv4Addr.IpAddr = ipLong;
            if (gw != null)
            {
                ipv4Addr.PrivateGateway = gw;
            }
            return ipv4Addr;
        }

        private static LoHi5Tuple createLoHi5TupleFrom(EventBean newEvent)
        {
            return new LoHi5Tuple(Converters.ConvertIpToLong(newEvent["srcIp"].ToString()), Converters.ConvertIpToLong(newEvent["destIp"].ToString()), Convert.ToInt32(newEvent["srcPort"].ToString()), Convert.ToInt32(newEvent["destPort"]), newEvent["protocol"].ToString());
        }

        private static string getProtocol(LoHi5Tuple loHi)
        {
            return (loHi.Protocol.Equals("TCP", StringComparison.CurrentCultureIgnoreCase)) ? "TCP" : "UDP";
        }

        private static string derivePrivateGateway(long ipAddr, string hostId, List<NIC> activeNics)
        {
            String pg = "";
            if ((ipAddr >> 24) == 127)
            {
                pg = hostId;
            }
            else
            {
                try
                {
                    pg = activeNics.Where(n => n.IPAddrAsLong == ipAddr).FirstOrDefault().GW;
                }
                catch (Exception ex)
                {
                }
            }
            return pg;
        }
    }
}
