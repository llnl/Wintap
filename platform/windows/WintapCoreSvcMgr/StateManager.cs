/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */


using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using gov.llnl.wintap.core.infrastructure;
using Newtonsoft.Json;

namespace gov.llnl.wintap.core.shared
{
    /// <summary>
    /// State cache for system attributes
    /// </summary>
    public sealed class StateManager
    {
        private static readonly StateManager state = new StateManager();

        public static Guid AgentId { get; private set; }

        /// <summary>
        /// The enablement state for all wintap event providers
        /// </summary>
        public static Dictionary<string, bool> WintapSettings { get; internal set; }

       

        /// <summary>
        /// Last boot time as reported by WMI
        /// </summary>
        public static DateTime MachineBootTime { get; set; }

        public static int WintapPID { get; set; }


        private StateManager()
        {
            WintapLogger.Log.Append($"StateManager is starting", LogLevel.Info);
            MachineBootTime = getBootTime();

            WintapLogger.Log.Append($"StateManager is getting AgentId", LogLevel.Info);
            string runtimeRoot = Environment.GetEnvironmentVariable("WINTAP_RUNTIME_ROOT");
            if (string.IsNullOrWhiteSpace(runtimeRoot))
                runtimeRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Wintap", "runtime");
            var identity = AgentIdentity.LoadOrCreate(
                Path.Combine(runtimeRoot, "wintapstate.json"), Environment.MachineName, AgentIdentity.ReadMachineId(),
                Path.Combine(Environment.CurrentDirectory, "wintapstate.json"));
            AgentId = identity.AgentId;
            WintapLogger.Log.Append($"Agent identity: {identity.Reason}; AgentId={AgentId}", LogLevel.Info);
            WintapLogger.Log.Append($"StateManager is initialized.", LogLevel.Info);
        }

        private DateTime getBootTime()
        {
            try
            {
                var uptimeMs = Environment.TickCount64;
                var uptime = TimeSpan.FromMilliseconds(uptimeMs);
                return DateTime.Now.Subtract(uptime);
            }
            catch (Exception ex)
            {
                // Fallback to WMI like in Program.cs
                try
                {
                    SelectQuery query = new SelectQuery(@"SELECT LastBootUpTime FROM Win32_OperatingSystem WHERE Primary='true'");
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        return ManagementDateTimeConverter.ToDateTime(mo.Properties["LastBootUpTime"].Value.ToString());
                    }
                }
                catch
                {
                    // Last resort fallback
                    return DateTime.Now.AddHours(-1);
                }
                return DateTime.Now.AddHours(-1);
            }
        }

        public static StateManager State
        {
            get
            {
                return state;
            }
        }

    }

    public class DiskVolume
    {
        public int VolumeNumber { get; set; }
        public char VolumeLetter { get; set; }
        public string VolumeLabel { get; set; }
        public string FileSystem { get; set; }
        public string VolumeType { get; set; }
    }

    public class WintapState
    {
        public string AgentId { get; set; }
    }
}
