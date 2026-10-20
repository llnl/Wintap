/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Xml;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.etl.model;
using gov.llnl.wintap.core.infrastructure;
using Newtonsoft.Json;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Runtime.InteropServices;
using gov.llnl.wintap.core.shared;

namespace gov.llnl.wintap.core.etl.shared
{
    internal static class Utilities
    {

        internal static List<MacIpV4Record> GetMacIps()
        {
            List<MacIpV4Record> netCollection = new List<MacIpV4Record>();
            foreach (NIC nic in Utilities.GetActiveNICs())
            {
                MacIpV4Record macIP = new MacIpV4Record();
                IpV4Addr ip = gov.llnl.wintap.core.etl.transform.Transformer.createIpAddr(nic.IPAddess, Converters.ConvertIpToLong(nic.IPAddess), nic.GW);
                macIP.Mac = nic.MAC;
                macIP.IpAddr = ip.IpAddr;
                macIP.Hash = ip.Hash;
                macIP.PrivateGateway = ip.PrivateGateway;
                macIP.EventTime = ((System.DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
                macIP.AgentId = GetAgentId();
                if (netCollection.Where(n => n.Hash == macIP.Hash).Count() == 0)
                {
                    netCollection.Add(macIP);
                    WintapLogger.Log.Append("Adding NIC info object: " + nic.IPAddess, LogLevel.Info);
                }
            }
            return netCollection;
        }

        internal static string GetAgentId()
        {
            Guid agentId = new Guid();
            const string registryPath = @"Software\Wintap";
            const string registryKey = "AgentId";
            try
            {
                return StateManager.AgentId.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accessing Wintap AgentId: {ex.Message}");
            }

            return agentId.ToString();
        }

        /// <summary>
        /// Converts a Windows .NET DateTime to Unix epoch time
        /// </summary>
        /// <param name="dotNetTime"></param>
        /// <returns></returns>
        static internal long ToUnixTime(DateTime dotNetTime)
        {
            return ((System.DateTimeOffset)DateTime.FromFileTimeUtc(dotNetTime.ToFileTimeUtc())).ToUnixTimeSeconds();
        }

        internal static DateTime FromUnixTime2(long unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTime;
        }

        internal static ETLConfig GetETLConfig()
        {
            ETLConfig config = new ETLConfig();
            config.LogLevel = "Normal";
            config.SensorProfile = "Quality";
            config.WriteToParquet = true;
            config.SerializationIntervalSec = 60;
            config.FileSerializationIntervalSec = 5;
            config.FileSerializationHighWaterEvents = 5000;
            config.UploadIntervalSec = 300;
            config.RawSensorMaxCacheSizeBytes = 256000000;
            try
            {
                string etlConfig = GetETLConfigPath();
                LogStartupConfigurationMessage("ETLConfig path: " + etlConfig, LogLevel.Info);
                if (File.Exists(etlConfig))
                {
                    LogStartupConfigurationMessage("Loading ETLConfig from: " + etlConfig, LogLevel.Info);
                    config = JsonConvert.DeserializeObject<ETLConfig>(File.ReadAllText(etlConfig));
                    if (config != null && !string.IsNullOrEmpty(config.DataRootPath))
                    {
                        Env.SetDataRoot(config.DataRootPath);
                    }
                }
                else
                {
                    LogStartupConfigurationMessage("ETLConfig.json not found at: " + etlConfig + "; using default values", LogLevel.Warn);
                }
            }
            catch (Exception ex)
            {
                LogStartupConfigurationMessage("Could not read ETLConfig from disk, using default values: " + ex.Message, LogLevel.Warn);
            }

            if (int.TryParse(ConfigManager.GetValue<string>("WINTAP_ETL_SERIALIZATION_INTERVAL_SEC"), out int serSec) && serSec > 0)
            {
                config.SerializationIntervalSec = serSec;
                LogStartupConfigurationMessage($"ETLConfig override: SerializationIntervalSec={serSec} (WINTAP_ETL_SERIALIZATION_INTERVAL_SEC)", LogLevel.Info);
            }
        
            if (int.TryParse(ConfigManager.GetValue<string>("WINTAP_ETL_UPLOAD_INTERVAL_SEC"), out int upSec) && upSec > 0)
            {
                config.UploadIntervalSec = upSec;
                LogStartupConfigurationMessage($"ETLConfig override: UploadIntervalSec={upSec} (WINTAP_ETL_UPLOAD_INTERVAL_SEC)", LogLevel.Info);
            }

            if (long.TryParse(ConfigManager.GetValue<string>("WINTAP_ETL_RAW_SENSOR_MAX_CACHE_BYTES"), out long rawSensorMaxCacheBytes) && rawSensorMaxCacheBytes > 0)
            {
                config.RawSensorMaxCacheSizeBytes = rawSensorMaxCacheBytes;
                LogStartupConfigurationMessage($"ETLConfig override: RawSensorMaxCacheSizeBytes={rawSensorMaxCacheBytes} (WINTAP_ETL_RAW_SENSOR_MAX_CACHE_BYTES)", LogLevel.Info);
            }

            if (config.RawSensorMaxCacheSizeBytes <= 0)
            {
                config.RawSensorMaxCacheSizeBytes = 256000000;
            }

            if (!config.FileSerializationIntervalSec.HasValue)
            {
                config.FileSerializationIntervalSec = 5;
            }

            if (!config.FileSerializationHighWaterEvents.HasValue)
            {
                config.FileSerializationHighWaterEvents = 5000;
            }

            return config;
        }

        internal static void LogStartupConfigurationMessage(string message, LogLevel level = LogLevel.Info)
        {
            WintapLogger.Log.Append(message, level);
            Console.WriteLine($"{Env.AppName} startup config [{level}]: {message}");
        }

        internal static string GetETLConfigPath()
        {
            string assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            return Path.GetFullPath(Path.Combine(assemblyDirectory, "ETLConfig.json"));
        }

        internal static List<NIC> GetActiveNICs()
        {
            List<NIC> nicList = new List<NIC>();
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in nics)
                {
                    if (adapter.Supports(NetworkInterfaceComponent.IPv4) && adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        IPInterfaceProperties ipInfo = adapter.GetIPProperties();
                        NIC newNic = new NIC();
                        // Note: Linux doesn't support the "i.IsDnsEligible" method. Just restrict to NOT loopback
                        foreach (UnicastIPAddressInformation unicast in ipInfo.UnicastAddresses.Where(i => i.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))                        {
                            try
                            {
                                newNic.MAC = adapter.GetPhysicalAddress().ToString();
                                newNic.IPAddess = unicast.Address.MapToIPv4().ToString();
                                newNic.GW = ipInfo.GatewayAddresses[0].Address.MapToIPv4().ToString();  // active pg:dotted-quad of gateway
                                newNic.IPAddrAsLong = Converters.ConvertIpToLong(newNic.IPAddess);
                                nicList.Add(newNic);
                            }
                            catch (Exception ex)             {
                                WintapLogger.Log.Append("Windows specific DLL? Could not enumerate network interfaces using .net api: " + ex.Message, LogLevel.Debug);
                            }

                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Could not enumerate network interfaces using .net api: " + ex.Message, LogLevel.Debug);
            }

            if (nicList.Count == 0)
            {
                WintapLogger.Log.Append("No NIC found", LogLevel.Info);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    WintapLogger.Log.Append("Attempting to get NIC info from WMI...", LogLevel.Info);
                    nicList = getNICsFromWMI();
                }
            }
            return nicList;
        }

        private static List<NIC> getNICsFromWMI()
        {
            WintapLogger.Log.Append("Attempting alternate method for NIC retrieval using WMI ", LogLevel.Info);
            List<NIC> nicList = new List<NIC>();
            NIC nic = new NIC();
            string mac = null;
            string ip = null;
            string gw = null;
            long ipAddrLong = 0;
            try
            {
                ManagementObjectSearcher mos = new ManagementObjectSearcher("select * from Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'True'");
                foreach (ManagementObject mo in mos.Get())
                {
                    try
                    {
                        mac = mo["MACAddress"].ToString();
                        foreach (PropertyData pd in mo.Properties)
                        {
                            if (pd.Name == "IPAddress")
                            {
                                string[] addresses = (string[])pd.Value;
                                ip = addresses[0];
                            }
                            if (pd.Name == "DefaultIPGateway")
                            {
                                string[] gateways = (string[])pd.Value;
                                gw = gateways[0];
                            }
                        }
                    }
                    catch (Exception ex) { }
                    if (String.IsNullOrEmpty(gw) || String.IsNullOrEmpty(ip) || String.IsNullOrEmpty(mac))
                    {

                    }
                    else
                    {
                        nic.GW = gw;
                        nic.IPAddess = ip;
                        nic.MAC = mac;
                        nic.IPAddrAsLong = Converters.ConvertIpToLong(ip);
                        nicList.Add(nic);
                    }

                }

            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error enumerating NICs: from WMI " + ex.Message, LogLevel.Debug);
            }
            return nicList;
        }

        internal static string GetFileStorePath(string className)
        {
            string progData = Paths.EsperStagingPath;
            className = className.ToLower();
            string fullPath = Path.Combine(progData, className);
            return fullPath;
        }

        internal static void LogEvent(int eventID, string v, EventLogEntryType eventType)
        {
            EventLog appLog = new EventLog("Application", ".", "WintapETL");
            appLog.WriteEntry(v, (System.Diagnostics.EventLogEntryType)EventLogEntryType.Warning, eventID);
        }
    }

    internal class NIC
    {
        internal string IPAddess { get; set; }
        internal long IPAddrAsLong { get; set; }
        internal string MAC { get; set; }
        internal string GW { get; set; }
    }

    internal class Computer
    {
        private static Computer computer;

        internal static Computer Get()
        {
            if (computer == null)
            {
                computer = new Computer();
                computer.ProcessorCount = GetProcessorCount();
                computer.ProcessorSpeed = GetCurrentCPUSpeed();
                computer.Name = Environment.MachineName;
                computer.Domain = GetDomain();
                computer.DomainRole = GetDomainRole();
                computer.HasBattery = getHasBattery();
                computer.LastBoot = getLastBoot();
                computer.LastBootDateTime = GetLastBootAsDateTimeUTC();
                computer.OSName = GetOS();
                computer.OSVersion = Environment.OSVersion.VersionString;

            }
            return computer;
        }
        internal string Name { get; set; }
        internal string OSName { get; set; }
        internal string OSVersion { get; set; }
        internal bool HasBattery { get; set; }
        internal int ProcessorCount { get; set; }
        internal long ProcessorSpeed { get; set; }
        internal string Domain { get; set; }
        internal string DomainRole { get; set; }
        internal long LastBoot { get; set; }
        internal DateTime LastBootDateTime { get; set; }

        private static long getLastBoot()
        {
            long lastBoot = 0;
            try
            {
                SelectQuery query = new SelectQuery(@"SELECT LastBootUpTime FROM Win32_OperatingSystem WHERE Primary='true'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject mo in searcher.Get())
                {
                    DateTime lastbootDT = ManagementDateTimeConverter.ToDateTime(mo.Properties["LastBootUpTime"].Value.ToString());
                    lastBoot = ((System.DateTimeOffset)lastbootDT).ToUnixTimeSeconds();
                    break;
                }
            }
            catch (Exception ex)
            {

            }
            return lastBoot;
        }

        internal static DateTime GetLastBootAsDateTimeUTC()
        {
            DateTime lastBootDT = DateTime.Now;

            // Get the system uptime in milliseconds
            long uptimeMillis = Environment.TickCount64;

            // Convert milliseconds to a TimeSpan
            TimeSpan uptime = TimeSpan.FromMilliseconds(uptimeMillis);
            lastBootDT = DateTime.Now.Subtract(uptime);

            return lastBootDT.ToUniversalTime();
        }

        private static string GetDomain()
        {
            string domain = "NA";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                ManagementObjectCollection moc = searcher.Get();
                foreach (ManagementObject mo in moc)
                {
                    domain = mo.Properties["Domain"].Value.ToString();
                }
            }
            catch (Exception ex) { }
            return domain;
        }

        private static string GetDomainRole()
        {
            string role = "NA";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                ManagementObjectCollection moc = searcher.Get();
                foreach (ManagementObject mo in moc)
                {
                    int rolenum = Convert.ToInt32(mo.Properties["DomainRole"].Value.ToString());
                    if (rolenum == 0)
                    {
                        role = "Standalone Workstation";
                    }
                    else if (rolenum == 1)
                    {
                        role = "Member Workstation";
                    }
                    else if (rolenum == 2)
                    {
                        role = "Standalone Server";
                    }
                    else if (rolenum == 3)
                    {
                        role = "Member Server";
                    }
                    else if (rolenum == 4)
                    {
                        role = "Backup Domain Controller";
                    }
                    else if (rolenum == 5)
                    {
                        role = "Primary Domain Controller";
                    }
                }
            }
            catch (Exception ex) { }
            return role;
        }

        private static long GetCurrentCPUSpeed()
        {
            long speed = 0;
            try
            {
                ObjectQuery wql = new ObjectQuery("SELECT * FROM Win32_Processor");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wql);
                ManagementObjectCollection results = searcher.Get();
                foreach (ManagementObject mo in results)
                {
                    speed = Convert.ToInt64(mo.Properties["CurrentClockSpeed"].Value.ToString());
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error getting Processor Speed: " + ex.Message, LogLevel.Info);
            }
            return speed * 1000000;
        }

        private static int GetProcessorCount()
        {
            int procCount = 0;
            try
            {
                procCount = Environment.ProcessorCount;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error getting processor count: " + ex.Message, LogLevel.Info);
            }
            return procCount;
        }

        private static string GetOS()
        {
            string osName = "NA";
            try
            {
                RegistryKey productKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                osName = productKey.GetValue("ProductName").ToString();
            }
            catch (Exception ex)
            {
            }
            return osName;
        }

        private static bool getHasBattery()
        {
            bool mobile = false;
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Battery");
                ManagementObjectCollection moc = searcher.Get();
                if (moc.Count > 0)
                {
                    mobile = true;
                }
            }
            catch (Exception ex)
            {
            }
            return mobile;
        }
    }
}
