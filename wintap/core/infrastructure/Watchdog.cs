/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.collect.models;

using gov.llnl.wintap.core.shared;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Timers;

namespace gov.llnl.wintap.core.infrastructure
{
    /// <summary>
    /// Monitors Wintap system utlization and imposes utilization limits.
    /// </summary>
    class Watchdog
    {

        /// <summary>
        /// Indicates that Wintap is in process of a restart due to a performance breach
        /// </summary>
        internal static bool PerformanceBreach;

        /// <summary>
        /// Fired when Wintap crosses CPU/Memory performance boundaries.  
        /// </summary>
        public event EventHandler ThrottleEvent;

        protected virtual void OnThrottle(EventArgs e)
        {
            if (ThrottleEvent != null)
            {
                ThrottleEvent(this, e);
            }
        }

        private WintapLogger log;
        private bool runMethodRunning;
        private bool wintapRunning;
        private TimeSpan workbenchIdleTimeout;

        protected internal Watchdog()
        {
            PerformanceBreach = false;
            workbenchIdleTimeout = new TimeSpan(0, 20, 0);
        }

        protected internal void Start()
        {
            wintapRunning = true;
            runMethodRunning = false;
            WintapLogger.Log.Append("Runtime profile: " + WintapProfile.Name, LogLevel.Info);
            WintapLogger.Log.Append("Max Memory: " + WintapProfile.MaxMem, LogLevel.Info);
            if (WintapProfile.Name != WintapProfile.ProfileEnum.Developer)
            {
                WintapLogger.Log.Append("Max CPU: " + WintapProfile.MaxCPU, LogLevel.Info);
            }

            // todo  refactor for multiplatform or remove
            BackgroundWorker perfCheckWorker = new BackgroundWorker();
            perfCheckWorker.DoWork += Watchdog_DoWork;
            perfCheckWorker.RunWorkerCompleted += Watchdog_RunWorkCompleted;
            //perfCheckWorker.RunWorkerAsync();
        }


        protected internal void Stop()
        {
            wintapRunning = false;
        }

        private void Watchdog_RunWorkCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (wintapRunning)
            {
                BackgroundWorker watchdog = new BackgroundWorker();
                watchdog.DoWork += Watchdog_DoWork;
                watchdog.RunWorkerCompleted += Watchdog_RunWorkCompleted;
                watchdog.RunWorkerAsync(e.Result);
            }
        }

        /// <summary>
        ///  Restarts Wintap if it starts to consume to much CPU or memory
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Watchdog_DoWork(object sender, DoWorkEventArgs e)
        {
            System.Threading.Thread.Sleep(WintapProfile.SampleInterval);
            try
            {
                float cpu = getCpu();
                long mem = getMem();
                WintapLogger.Log.Append($"{Env.AppName} usage stats.  CPU: " + cpu + " MEM: " + mem, LogLevel.Info);
                if (WintapProfile.Name == WintapProfile.ProfileEnum.Production && (cpu > WintapProfile.MaxCPU || mem > WintapProfile.MaxMem))
                {
                    WintapProfile.BreachCount++;
                }
                else if (WintapProfile.Name == WintapProfile.ProfileEnum.Developer && mem > WintapProfile.MaxMem)
                {
                    WintapProfile.BreachCount++;
                }
                else { WintapProfile.BreachCount = 0; }
                if (WintapProfile.BreachCount >= WintapProfile.MaxBreachCount)
                {
                    string alertMsg = $"{Env.AppName} has exceeded maximum performance thresholds. cpu: " + cpu + "  memory: " + mem + "  hitcount: " + WintapProfile.BreachCount;
                    WintapLogger.Log.Append(alertMsg, LogLevel.Info);
                    sendWintapAlert(WintapMessage.WintapAlertData.AlertNameEnum.SYSTEM_UTILIZATION, alertMsg);
                    Utilities.RestartWintap(alertMsg);
                }
                if (Properties.Settings.Default.EnableWorkbench)
                {
                    if (DateTime.Now.Subtract(StateManager.LastWorkbenchActivity) > workbenchIdleTimeout)
                    {
                        WintapLogger.Log.Append("Workbench idle time threshold exceeded, disabling workbench...", LogLevel.Info);
                        sendWintapAlert(WintapMessage.WintapAlertData.AlertNameEnum.OTHER, "Workbench idle timeout expired");
                        Dictionary<string, bool> disableWorkbenchSetting = new Dictionary<string, bool>();
                        disableWorkbenchSetting.Add("EnableWorkbench", false);
                        StateManager.SetWintapSettings(disableWorkbenchSetting);
                    }
                }
            }
            catch (Exception ex)
            {
                logEvent(103, "Top level error in watchdog: " + ex.Message + "  Performance protection is NOT running.");
            }
        }

        private void sendWintapAlert(WintapMessage.WintapAlertData.AlertNameEnum alertType, string description)
        {
            StateManager.DroppedEventsDetected = true;
            WintapMessage alertMsg = new WintapMessage(DateTime.UtcNow, System.Diagnostics.Process.GetCurrentProcess().Id, WintapMessage.MessageTypeEnum.WintapAlert);
            alertMsg.WintapAlert = new WintapMessage.WintapAlertData();
            alertMsg.WintapAlert.AlertName = alertType;
            alertMsg.WintapAlert.AlertDescription = description;
            EventChannel.Send(alertMsg);
            WintapLogger.Log.Append(alertMsg.WintapAlert.AlertDescription, LogLevel.Info);
        }

        private long getMem()
        {
            Process thisProc = Process.GetCurrentProcess();
            return thisProc.PrivateMemorySize64;
        }

        private float getCpu()
        {
            Process thisProc = Process.GetCurrentProcess();
            PerformanceCounter procCounter = new PerformanceCounter("Process", "% Processor Time", thisProc.ProcessName);
            procCounter.NextValue();
            System.Threading.Thread.Sleep(250);
            float val = procCounter.NextValue() / Environment.ProcessorCount;
            procCounter.Close();
            procCounter.Dispose();
            return val;
        }

        private void logEvent(int eventID, string v)
        {
            WintapLogger.Log.Append(v, LogLevel.Info);
            EventLog appLog = new EventLog("Application", ".", "Wintap");
            appLog.WriteEntry(v, (System.Diagnostics.EventLogEntryType)EventLogEntryType.Warning, eventID);

        }

        //  monitor the runtime of a plugin's 'Run' method, restart Wintap if the plugin hangs
        protected internal void ProtectedRun(Runnable runnable)
        {
            WintapLogger.Log.Append("Watchdog is attempting a protected run of: " + runnable.RunPlugin.Metadata.Name, LogLevel.Info);
            TimeSpan runTTL = new TimeSpan(0, 2, 0);  // max protectedRun duration, todo: config
            runTTL = runnable.MaxTTL;
            runMethodRunning = true;
            BackgroundWorker runWorker = new BackgroundWorker();
            runWorker.WorkerSupportsCancellation = true;
            runWorker.DoWork += RunWorker_DoWork;
            runWorker.RunWorkerCompleted += RunWorker_RunWorkerCompleted;
            runWorker.RunWorkerAsync(runnable);
            TimeSpan executeTime = new TimeSpan();
            while (runMethodRunning)
            {
                WintapLogger.Log.Append("Runnable invoked.  Waiting on " + runnable.RunPlugin.Metadata.Name, LogLevel.Info);
                executeTime = executeTime.Add(TimeSpan.FromSeconds(1));
                if (executeTime > runTTL)
                {
                    logEvent(104, "Watchdog timeout exceeded on runnable: " + runnable.RunPlugin.Metadata.Name);
                    Utilities.RestartWintap("Watchdog timeout exceeded on runnable: " + runnable.RunPlugin.Metadata.Name);
                    throw new Exception("WATCH_DOG_TIMEOUT_EXCEEDED");
                }
                System.Threading.Thread.Sleep(1000);
            }
            WintapLogger.Log.Append("Watchdog has completed protected run, run time: " + executeTime, LogLevel.Info);
        }

        private void RunWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            WintapLogger.Log.Append("Protected run complete", LogLevel.Info);
            runMethodRunning = false;
        }

        private void RunWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            runMethodRunning = true;
            Runnable runnable = (Runnable)e.Argument;
            try
            {
                runnable.RunPlugin.Value.Run();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("WARN:  problem with runnable: " + ex.Message, LogLevel.Info);
            }
        }
    }

    /// <summary>
    /// Stores Wintap performance evaluation criteria
    /// </summary>
    internal static class WintapProfile
    {
        internal enum ProfileEnum { Minimal, Production, Developer };
        internal static ProfileEnum Name { get; set; }

        internal static int MaxCPU { get; set; }
        internal static long MaxMem { get; set; }
        internal static int MaxEventCount { get; set; }
        internal static int BreachCount { get; set; }
        internal static int MaxBreachCount { get; set; }
        internal static TimeSpan SampleInterval { get; set; }

        static WintapProfile()
        {
            BreachCount = 0;
            MaxMem = 700000000;
            MaxCPU = 20;
            MaxBreachCount = 2;
            MaxEventCount = 1000;
            SampleInterval = new TimeSpan(0, 0, 45);
            Name = ProfileEnum.Minimal;
            if (Properties.Settings.Default.Profile.ToUpper() == "PRODUCTION")
            {
                Name = ProfileEnum.Production;
                MaxMem = 700000000;
                MaxCPU = 20;
                MaxEventCount = 400;
                MaxBreachCount = 3;
            }
            else if (Properties.Settings.Default.Profile.ToUpper() == "DEVELOPER")
            {
                MaxMem = 950000000;
                Name = ProfileEnum.Developer;
            }
        }
    }
}
