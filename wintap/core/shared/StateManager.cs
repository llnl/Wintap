/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */


using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Collections.Concurrent;
using gov.llnl.wintap.core.infrastructure;
using System.Net.NetworkInformation;
using System.IO;
using Newtonsoft.Json;
using System.Runtime.InteropServices;
using com.espertech.esper.runtime.client;
#if WINDOWS
using gov.llnl.wintap.platform.windows.infrastructure;
#endif

namespace gov.llnl.wintap.core.shared
{
    /// <summary>
    /// State cache for system attributes
    /// </summary>
    public sealed class StateManager
    {
        private static readonly StateManager state = new StateManager();

        public static Guid AgentId { get; private set; }
        public static bool UserBusy { get; set; }
        public static string ActiveUser { get; set; }
        public enum UserStateEnum { LoggedOut, LoggedIn, ScreenLock, ScreenUnlock };
        public static string UserState { get; set; }
        /// <summary>
        /// The ProcessID with the most recent focus change
        /// </summary>
        public static int PidFocus { get; set; }
        public static bool OnBatteryPower { get; set; }
        public static DateTime LastUserActivity { get; set; }
        public readonly TimeSpan MaxUserInactivity = new TimeSpan(0, 0, 5, 0, 0);

        public static string ProcessTreeJSON { get; set; }

        /// <summary>
        /// True is Windows Performance Monitor reports any dropped events for the NT Kernel Logger since wintap last started.
        /// </summary>
        public static bool DroppedEventsDetected { get; set; }

        /// <summary>
        /// Identifies a contiguous data collect block
        /// </summary>
        public static Guid SessionId { get; set; }

        /// <summary>
        /// The enablement state for all wintap event providers
        /// </summary>
        public static Dictionary<string, bool> WintapSettings { get; internal set; }

        /// <summary>
        /// A list of physical disk drive number to logical drive letter mappings.  
        /// </summary>
        public List<DiskVolume> DriveMap { get; set; }

        /// <summary>
        /// Last boot time as reported by WMI
        /// </summary>
        public static DateTime MachineBootTime { get; set; }

        public static int WintapPID { get; set; }

        //  debug for missing process events
        public static ConcurrentBag<string> SentProcessList = new ConcurrentBag<string>();

        /// <summary>
        /// Supports idle timeout and reset for Workbench sessions
        /// </summary>
        public static DateTime LastWorkbenchActivity { get; set; }

        private StateManager()
        {
            WintapLogger.Log.Append($"StateManager is starting", LogLevel.Info);
            LastWorkbenchActivity = DateTime.Now;
            WintapLogger.Log.Append($"Getting {Env.AppName} settings from config", LogLevel.Info);
            WintapSettings = getWintapSettings();
            SessionId = Guid.NewGuid();

            WintapLogger.Log.Append($"StateManager is getting AgentId", LogLevel.Info);
            string machineId = AgentIdentity.ReadMachineId();
            if (string.IsNullOrWhiteSpace(machineId))
                WintapLogger.Log.Append("Agent identity uses hostname-only binding: machine ID unavailable.", LogLevel.Warn);
            var identity = AgentIdentity.LoadOrCreate(
                Path.Combine(Env.FileRuntimeRoot, "wintapstate.json"), Environment.MachineName, machineId,
                Path.Combine(Environment.CurrentDirectory, "wintapstate.json"));
            AgentId = identity.AgentId;
            WintapLogger.Log.Append($"Agent identity: {identity.Reason}; AgentId={AgentId}; process identity={ProcessIdentity.Version}", LogLevel.Info);
            WintapLogger.Log.Append($"StateManager is refreshing active user info", LogLevel.Info);
            ActiveUser = refreshActiveUser();
            WintapLogger.Log.Append($"StateManager has active user: {ActiveUser}", LogLevel.Info);
            OnBatteryPower = false;
            UserBusy = false;
            WintapPID = System.Diagnostics.Process.GetCurrentProcess().Id;
            WintapLogger.Log.Append($"StateManager has found {Env.AppName} pid: {WintapPID}", LogLevel.Info);
            System.Timers.Timer stateRefresh = new System.Timers.Timer();
            stateRefresh.Interval = 60000;
            stateRefresh.Enabled = true;
            stateRefresh.AutoReset = true;
            stateRefresh.Elapsed += StateRefresh_Elapsed;
            stateRefresh.Start();

            // sub to SessionChange and set ActiveUser
            WintapLogger.Log.Append($"StateManager is registering for user change notifications...", LogLevel.Info);
            try
            {
                EPStatement userChangeQuery = EventChannel.CompileDeploy(
                    "SELECT * FROM WintapMessage WHERE CAST(MessageType, string) = 'SessionChange'", "StateManagerUserChangeNotify").Statements[0];
                //TODO :  userChangeQuery.Events += UserChangeQuery_Events;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"StateManager encountered an error setting up user change notifications: {ex.Message}", LogLevel.Info);
            }
            WintapLogger.Log.Append($"StateManager has hooked user change event notification", LogLevel.Info);

#if WINDOWS
            {
                DriveMap = WindowsStateManager.RefreshDriveMap();
            }
#endif
            MachineBootTime = refreshLastBoot();

            WintapLogger.Log.Append($"StateManager is initialized.", LogLevel.Info);
        }

        private Dictionary<string, bool> getWintapSettings()
        {
            Dictionary<string, bool> settings = new Dictionary<string, bool>();
            try
            {
                settings["Tcp"] = Properties.Settings.Default.TcpSensor;
                settings["Udp"] = Properties.Settings.Default.UdpSensor;
                settings["ImageLoad"] = Properties.Settings.Default.ImageLoadSensor;
                settings["File"] = Properties.Settings.Default.FileSensor;
                settings["Registry"] = Properties.Settings.Default.RegistrySensor;
                settings["PowerShell"] = Properties.Settings.Default.PowerShellSensor;
                settings["MemoryMap"] = Properties.Settings.Default.MemoryMapSensor;
                settings["ApiCall"] = Properties.Settings.Default.ApiCallSensor;
                settings["DeveloperMode"] = false;
                if (Properties.Settings.Default.Profile.ToUpper() == "DEVELOPER")
                {
                    settings["DeveloperMode"] = true;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"StateManager: ERROR reading event provider enablement state, could not build collectorSettings object: {ex.Message}", LogLevel.Info);
            }
            return settings;
        }

        internal static void SetWintapSettings(Dictionary<string, bool> settings)
        {
            Dictionary<string, string> translatedSettings = new Dictionary<string, string>();
            foreach (KeyValuePair<string, bool> kvp in settings)
            {

                if (kvp.Key == "Tcp")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.TcpSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "Udp")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.UdpSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "ImageLoad")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.ImageLoadSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "File")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.FileSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "Registry")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.RegistrySensor), kvp.Value.ToString());
                }
                if (kvp.Key == "PowerShell")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.PowerShellSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "MemoryMap")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.MemoryMapSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "ApiCall")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.ApiCallSensor), kvp.Value.ToString());
                }
                if (kvp.Key == "EnableWorkbench")
                {
                    translatedSettings.Add(nameof(Properties.Settings.Default.EnableWorkbench), kvp.Value.ToString());
                }
                if (kvp.Key == "DeveloperMode")
                {
                    string settingName = "Profile";
                    string settingValue = "Production";
                    if (kvp.Value == true)
                    {
                        settingValue = "Developer";
                    }
                    translatedSettings.Add(settingName, settingValue);
                }
            }
            saveSettings(translatedSettings);
            Utilities.RestartWintap($"{Env.AppName} settings change requested.");
        }

        private static void saveSettings(Dictionary<string, string> settingsToUpdate)
        {
            string appPath = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string configFile = System.IO.Path.Combine(appPath, "Wintap.dll.config");
            try
            {
                System.Xml.XmlDocument xmlDoc = new System.Xml.XmlDocument();
                xmlDoc.Load(configFile);
                System.Xml.XmlNode userSettingsNode = xmlDoc.SelectSingleNode("//userSettings");
                if (userSettingsNode != null)
                {
                    foreach (var settingToUpdate in settingsToUpdate)
                    {
                        string settingName = settingToUpdate.Key;
                        string settingValue = settingToUpdate.Value.ToString();
                        System.Xml.XmlNode settingNode = userSettingsNode.SelectSingleNode($"//setting[@name='{settingName}']");
                        if (settingNode != null)
                        {
                            settingNode.SelectSingleNode("value").InnerText = settingValue;
                        }
                        else
                        {
                            WintapLogger.Log.Append($"Setting node '{settingName}' not found in app.config", LogLevel.Info);
                        }
                    }
                    xmlDoc.Save(configFile);
                }
                else
                {
                    WintapLogger.Log.Append("userSettings section not found in app.config", LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error modifying app.config: " + ex.Message, LogLevel.Info);
            }
        }

        public static StateManager State
        {
            get
            {
                return state;
            }
        }

        internal static DateTime refreshLastBoot()
        {
            DateTime lastBoot = DateTime.Now;
#if WINDOWS
            lastBoot = WindowsStateManager.GetLastBootTime();
#endif
            return lastBoot;
        }

        private void StateRefresh_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (DateTime.Now.Subtract(LastUserActivity) > MaxUserInactivity)
            {
                UserBusy = false;
            }
            OnBatteryPower = refreshBatteryState();
        }


        private string refreshActiveUser()
        {
            ActiveUser = "NA";
#if WINDOWS
            ActiveUser = WindowsStateManager.RefreshActiveUser();
#endif
            return ActiveUser;
        }

        private bool refreshBatteryState()
        {
            OnBatteryPower = false;
#if WINDOWS
            OnBatteryPower = WindowsStateManager.RefreshBatteryState();
#endif
            return OnBatteryPower;
        }

        internal static uint GetCPUSpeed(int cpuNumber)
        {
            using (ManagementObject Mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
            {
                uint abreviatedSpeed = Convert.ToUInt32(Mo["CurrentClockSpeed"].ToString());
                uint speed = abreviatedSpeed * 1000000;
                return speed;
            }
        }

        public static string GetLocalIpAddress()
        {
            string localIp = "NA";
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in nics)
                {
                    if (adapter.Supports(NetworkInterfaceComponent.IPv4) && adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        IPInterfaceProperties ipInfo = adapter.GetIPProperties();
                        foreach (UnicastIPAddressInformation unicast in ipInfo.UnicastAddresses.Where(i => i.IsDnsEligible == true))
                        {
                            return unicast.Address.MapToIPv4().ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("ERROR retrieving local IP address from .NET provider: " + ex.Message, LogLevel.Info);
            }
            if (localIp == "NA")
            {
                localIp = getLocalIpAddressFromWMI();
            }
            WintapLogger.Log.Append("Retrieved local IP address: " + localIp, LogLevel.Info);
            return localIp;
        }

        private static string getLocalIpAddressFromWMI()
        {
            string localIp = "NA";
            WintapLogger.Log.Append("Attempting to get local IP address from WMI...", LogLevel.Info);
            try
            {
                ManagementObjectSearcher mos = new ManagementObjectSearcher("select * from Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'True'");
                foreach (ManagementObject mo in mos.Get())
                {
                    try
                    {
                        foreach (PropertyData pd in mo.Properties)
                        {
                            if (pd.Name == "IPAddress")
                            {
                                string[] addresses = (string[])pd.Value;
                                localIp = addresses[0];
                            }
                        }
                    }
                    catch (Exception ex1) { }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error enumerating NICs: from WMI " + ex.Message, LogLevel.Info);
            }
            return localIp; ;
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
