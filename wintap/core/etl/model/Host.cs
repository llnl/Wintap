/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */


using System.Collections.Generic;
using System.Dynamic;

namespace gov.llnl.wintap.core.etl.models
{
    public class HostData : SensorData
    {
        public string AgentId { get; set; }

        /// <summary>
        /// Hardware architecture
        /// </summary>
        public string Arch { get; set; }

        public int ProcessorCount { get; set; }

        public long ProcessorSpeed { get; set; }

        public bool HasBattery { get; set; }

        public string Domain { get; set; }

        public string DomainRole { get; set; }

        public long LastBoot { get; set; }

        public string OS { get; set; }

        public string OSVersion { get; set; }

        public string WintapVersion { get; set; }

        public string ETLVersion { get; set; }

        public string Collectors { get; set; }

        /// <summary>Versioned effective startup evidence; null on legacy/uninstrumented records.</summary>
        public string RuntimeCapabilitiesJson { get; set; }

    }
}
