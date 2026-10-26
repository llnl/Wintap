/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */


using gov.llnl.wintap.core.infrastructure;
using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace gov.llnl.wintap
{
    internal static class WintapController
    {
        internal static TimeSpan svcTimeout = new TimeSpan(0, 0, 0, 20);

        internal static bool GetSvcStartMode()
        {
            bool setToAuto = false;
            try
            {
                ServiceController sc = new ServiceController("Wintap");
                if (sc.StartType == ServiceStartMode.Automatic)
                {
                    setToAuto = true;
                }
            }
            catch(Exception ex)
            {
                WintapLogger.Log.Append("ERROR getting Wintap service start type: " + ex.Message, LogLevel.Info);
            }
            WintapLogger.Log.Append("Returning service set to AUTOMATIC: " + setToAuto, LogLevel.Info);
            return setToAuto;
        }

        internal static void SetSvcStartMode()
        {
            try
            {
                WintapLogger.Log.Append("Attempting to set Wintap service start type.", LogLevel.Info   );
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Path.Combine(Environment.SystemDirectory, "sc.exe");
                psi.Arguments = "config wintap start=auto";
                System.Diagnostics.Process p = new System.Diagnostics.Process();
                p.StartInfo = psi;
                p.Start();
                
            }
            catch(Exception ex)
            {
                WintapLogger.Log.Append("ERROR setting Wintap service start type: " + ex.Message, LogLevel.Info);
            }
            WintapLogger.Log.Append("Service start type complete", LogLevel.Info);
        }

        /// <summary>
        /// Returns true is Wintap service is currently RUNNING
        /// </summary>
        /// <returns></returns>
        internal static bool GetWintapSvcState()
        {
            bool wintapRunning = false;
            try
            {
                ServiceController sc = new ServiceController("Wintap");
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    wintapRunning = true;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("ERROR getting Wintap service state: " + ex.Message, LogLevel.Info);
            }
            WintapLogger.Log.Append("Wintap service controller QUERY method complete, returning RUNNING state to caller: " + wintapRunning, LogLevel.Info);
            return wintapRunning;
        }

        internal static bool StartWintap()
        {
            bool reqSucceeded = false;
            try
            {
                ServiceController sc = new ServiceController("Wintap");
                if (sc.Status == ServiceControllerStatus.Stopped)
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, svcTimeout);
                    reqSucceeded = true;
                    WintapLogger.Log.Append("Wintap start request complete.  New state: " + sc.Status, LogLevel.Info);
                }
            }
            catch(Exception ex)
            {
                WintapLogger.Log.Append("ERROR starting Wintap: " + ex.Message, LogLevel.Info);
            }
            WintapLogger.Log.Append("Wintap service controller START method complete, returning RUNNING state to caller: " + reqSucceeded, LogLevel.Info);
            return reqSucceeded;
        }

        internal static bool StopWintap()
        {
            bool stopReqSucceeded = true;
            try
            {
                ServiceController sc = new ServiceController("Wintap");
                if (sc.Status != ServiceControllerStatus.Stopped)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, svcTimeout);
                    stopReqSucceeded = true;
                }
                else
                {
                    WintapLogger.Log.Append("Wintap was already in a STOPPED state", LogLevel.Info);
                }
            }
            catch(Exception ex)
            {
                WintapLogger.Log.Append("ERROR attempting to shutdown Wintap: " + ex.Message, LogLevel.Info);
                try
                {
                    System.Diagnostics.Process[] allWintaps = System.Diagnostics.Process.GetProcessesByName("wintap.exe");
                    for(int i = 0; i < allWintaps.Length; i++)
                    {
                        WintapLogger.Log.Append("attempting to terminate wintap process with PID: " + allWintaps[i].Id, LogLevel.Info);
                        allWintaps[i].Kill();
                    }
                    WintapLogger.Log.Append("Wintap process termination complete.", LogLevel.Info);
                }
                catch(Exception ex2)
                {
                    WintapLogger.Log.Append("Error terminating Wintap: " + ex2.Message, LogLevel.Info);
                    stopReqSucceeded = false;
                }
            }
            WintapLogger.Log.Append("Wintap service controller STOP method complete, returning STOP state to caller: " + stopReqSucceeded, LogLevel.Info);
            return stopReqSucceeded;
        }
    }
}
