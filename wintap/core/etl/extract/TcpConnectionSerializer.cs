/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using com.espertech.esper.client;
using com.espertech.esper.common.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.shared;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Timers;

namespace gov.llnl.wintap.core.etl.extract
{
    internal class TcpConnectionSerializer : Serializer
    {
        private System.Timers.Timer networkEventTimer;  // guard against a stalled network event stream
        private List<NIC> activeNics;

        internal TcpConnectionSerializer(string[] queries) : base(queries)
        {
            activeNics = Utilities.GetActiveNICs();
            networkEventTimer = new System.Timers.Timer { Interval = 60000 };
            networkEventTimer.Elapsed += NetworkEventTimer_Elapsed;
        }

        private void NetworkEventTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            WintapLogger.Log.Append(NetworkSerializerContract.InactivityMessage, LogLevel.Info);
        }

        protected override void HandleSensorEvent(EventBean sensorEvent)
        {
            try
            {
                base.HandleSensorEvent(sensorEvent);
                networkEventTimer.Stop();
                networkEventTimer.Start();
                string tmpPidHash = sensorEvent["PidHash"]?.ToString() ??  "fixmepid";
                ProcessConnIncrData pci = transform.Transformer.CreateProcessConn(sensorEvent, tmpPidHash, activeNics);
                pci.Hostname = HostSerializer.Instance.HostId.Hostname;
                pci.MessageType = "PROCESS_CONN_INCR";
                long maxPktSize = 0;
                Int64.TryParse(sensorEvent["maxPacketSize"].ToString(), out maxPktSize);
                long minPktSize = 0;
                Int64.TryParse(sensorEvent["minPacketSize"].ToString(), out minPktSize);
                long pktSizeSquared = 0;
                Int64.TryParse(sensorEvent["packetSizeSquared"].ToString(), out pktSizeSquared);
                pci.MinPacketSize = minPktSize;
                pci.MaxPacketSize = maxPktSize;
                pci.PacketSizeSquared = pktSizeSquared;
                pci.EventTime = GetUnixNowTime();
                pci.ActivityType = sensorEvent["activityType"].ToString();
                dynamic flatMsg = (ExpandoObject)pci.ToDynamic();
                flatMsg.ProcessName = sensorEvent["ProcessName"].ToString();
                flatMsg.ActivityType = pci.IpEvent;
                flatMsg.AgentId = NetworkSerializerContract.GetAgentId(sensorEvent["AgentId"]);

                // adding for convenience
                flatMsg.SourceIpAddressString = sensorEvent["srcIp"].ToString();
                flatMsg.DestinationIpAddressString = sensorEvent["destIp"].ToString();

                this.Save(flatMsg);
                sensorEvent = null;
                flatMsg = null;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error creating TcpConnection object on pid: " + sensorEvent["PID"] + ",  exception: " + ex.ToString(), LogLevel.Info);
            }
        }
    }
}
