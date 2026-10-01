/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using System.Collections.Generic;
using System;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.linux.collect;

namespace gov.llnl.wintap.platform.linux.infrastructure
{
    /// <summary>
    /// Linux subscription manager - coordinates platform-specific sensors
    /// 
    /// </summary>
    public class LinuxSubscriptionManager
    {
        internal List<BaseSensor> Start()
        {
            WintapLogger.Log.Append("═══════════════════════════════════════════", LogLevel.Info);
            WintapLogger.Log.Append("LinuxSubscriptionManager.Start() called", LogLevel.Info);
            WintapLogger.Log.Append("═══════════════════════════════════════════", LogLevel.Info);

            List<BaseSensor> baseSensors = new List<BaseSensor>();

            bool IsEnabled(string sensorKey)
            {
                // Sensor keys are config properties (Execve, Clone, Exit, Network, FileOps, SELinux, ProcessRundown).
                // Defaults live in ConfigRoot, so a missing key still yields a sensible behavior.
                string compactEnvName = $"WINTAP_ENABLE_{sensorKey.ToUpperInvariant()}_SENSOR";
                string? enableEnv = Environment.GetEnvironmentVariable(compactEnvName);
                if (string.IsNullOrWhiteSpace(enableEnv) && sensorKey == "ProcessRundown")
                {
                    enableEnv = Environment.GetEnvironmentVariable("WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR");
                }

                if (!string.IsNullOrWhiteSpace(enableEnv))
                {
                    return enableEnv.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                           enableEnv.Equals("true", StringComparison.OrdinalIgnoreCase);
                }

                return ConfigManager.GetValue<bool>(sensorKey);
            }

            void TryStart(BaseSensor sensor)
            {
                if (sensor.Start())
                {
                    baseSensors.Add(sensor);
                    WintapLogger.Log.Append($"{sensor.SensorName} sensor registered", LogLevel.Info);
                }
                else
                {
                    WintapLogger.Log.Append($"{sensor.SensorName} sensor failed to start and will not be registered", LogLevel.Warn);
                }
            }

            if (IsEnabled("Execve"))
            {
                ExecveSensor execveSensor = new ExecveSensor();
                TryStart(execveSensor);
            }
            else
            {
                WintapLogger.Log.Append("ExecveSensor disabled by config (Execve=false)", LogLevel.Warn);
            }

            if (IsEnabled("Clone"))
            {
                CloneSensor cloneSensor = new CloneSensor();
                TryStart(cloneSensor);
            }
            else
            {
                WintapLogger.Log.Append("CloneSensor disabled by config (Clone=false)", LogLevel.Warn);
            }

            if (IsEnabled("Exit"))
            {
                ExitSensor exitSensor = new ExitSensor();
                TryStart(exitSensor);
            }
            else
            {
                WintapLogger.Log.Append("ExitSensor disabled by config (Exit=false)", LogLevel.Warn);
            }

            if (IsEnabled("Network"))
            {
                NetworkSensor networkSensor = new NetworkSensor();
                TryStart(networkSensor);
            }
            else
            {
                WintapLogger.Log.Append("NetworkSensor disabled by config (Network=false)", LogLevel.Warn);
            }

            if (IsEnabled("FileOps"))
            {
                FileOpsSensor fileOpsSensor = new FileOpsSensor();
                TryStart(fileOpsSensor);
            }
            else
            {
                WintapLogger.Log.Append("FileOpsSensor disabled by config (FileOps=false)", LogLevel.Warn);
            }

            if (IsEnabled("SELinux"))
            {
                SELinuxSensor selinuxSensor = new SELinuxSensor();
                TryStart(selinuxSensor);
            }
            else
            {
                WintapLogger.Log.Append("SELinuxSensor disabled by config (SELinux=false)", LogLevel.Warn);
            }

            if (IsEnabled("ProcessRundown"))
            {
                ProcessRundownSensor processRundownSensor = new ProcessRundownSensor();
                TryStart(processRundownSensor);
            }
            else
            {
                WintapLogger.Log.Append("ProcessRundownSensor disabled by config (ProcessRundown=false)", LogLevel.Warn);
            }

            return baseSensors;
        }

        internal void Stop()
        {
            WintapLogger.Log.Append("LinuxSubscriptionManager is shutting down", LogLevel.Info);
            //  perform any platform-wide sensor shutdown activities (if any...)

            WintapLogger.Log.Append("LinuxSubscriptionManager is shutdown", LogLevel.Info);
        }
    }
}
