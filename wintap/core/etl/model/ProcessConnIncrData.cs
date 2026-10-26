/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

namespace gov.llnl.wintap.core.etl.models
{
    public class ProcessConnIncrData : SensorData
    {
        /// <summary>
        ///  Hash value in uppercase.
        /// </summary>
        public string ConnId { get; set; }

        public string PidHash { get; set; }

        // Directed producer tuple provenance. Local/Remote ports are host-relative;
        // these preserve direction even when one process owns both socket ends.
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }

        public long MinPacketSize { get; set; }

        public long MaxPacketSize { get; set; }

        public long PacketSizeSquared { get; set; }

        /// <summary>
        /// Hash value in uppercase. 
        /// </summary>
        //public string LocalIpHash { get; set; }
        /// <summary>
        /// IP address as a long(?)
        /// </summary>
        public long LocalIpAddr { get; set; }
        /// <summary>
        ///  Value used to disambiguate localhost and non-routable values
        /// </summary>
        public string LocalIpPrivateGateway { get; set; }

        /// <summary>
        /// Port related to the local IP
        /// </summary>
        public int LocalPort { get; set; }

        /// <summary>
        /// Hash value in uppercase. 
        /// </summary>
        //public string RemoteIpHash { get; set; }
        /// <summary>
        /// IP address as a long(?)
        /// </summary>
        public long RemoteIpAddr { get; set; }
        /// <summary>
        ///  Value used to disambiguate localhost and non-routable values
        /// </summary>
        public string RemoteIpPrivateGateway { get; set; }

        /// <summary>
        /// Port related to the remote IP 
        /// </summary>
        public int RemotePort { get; set; }
        /// <summary>
        /// TCP or UDP 
        /// </summary>
        public string Protocol { get; set; }

        /// <summary>
        /// Initial TCP sequence number for the session
        /// </summary>
        public int InitialSeq { get; set; }
        /// <summary>
        ///  Connect/accept/send/receive/disconnect/etc
        /// </summary>
        public string IpEvent { get; set; }
        /// <summary>
        /// Total size of packets. 
        /// </summary>
        public int PacketSize { get; set; }

        /// <summary>
        /// Increment type code: 30sec, 5min, 1hr, etc. No validation is done or implied. Sensors can use anything, just be consistent.
        /// </summary>
        public string IncrType { get; set; }

        /// <summary>
        /// Number of events
        /// </summary>
        public int EventCount { get; set; }

        /// <summary>
        /// First event timestamp in the increment
        /// </summary>
        public long FirstSeenMs { get; set; }

        public long LastSeenMs { get; set; }

    }
}
