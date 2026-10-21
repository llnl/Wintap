using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.windows.collect.etw;
using gov.llnl.wintap.platform.windows.collect.etw.helpers;
using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace gov.llnl.wintap.platform.windows.infrastructure
{
    internal sealed class CollectorStartupEntry
    {
        internal CollectorStartupEntry(
            string name,
            BaseWindowsSensor sensor,
            KernelTraceEventParser.Keywords flags)
        {
            Name = name;
            Sensor = sensor;
            Flags = flags;
        }

        internal string Name { get; }
        internal BaseWindowsSensor Sensor { get; }
        internal KernelTraceEventParser.Keywords Flags { get; }
    }

    internal sealed class CollectorStartupPlan
    {
        internal static readonly string[] OrderedPhases =
        {
            "EnableKernelProvider",
            "InitializeProcessSnapshot",
            "StartProcessSensor",
            "StartSharedKernelSensors",
            "StartKernelConsumer",
            "StartIndependentSensors"
        };

        internal CollectorStartupPlan(
            KernelTraceEventParser.Keywords finalKernelFlags,
            IReadOnlyList<CollectorStartupEntry> sharedKernelSensors,
            IReadOnlyList<CollectorStartupEntry> independentSensors)
        {
            FinalKernelFlags = finalKernelFlags;
            SharedKernelSensors = sharedKernelSensors;
            IndependentSensors = independentSensors;
            StartupPhases = OrderedPhases;
        }

        internal KernelTraceEventParser.Keywords FinalKernelFlags { get; }
        internal IReadOnlyList<CollectorStartupEntry> SharedKernelSensors { get; }
        internal IReadOnlyList<CollectorStartupEntry> IndependentSensors { get; }
        internal IReadOnlyList<string> StartupPhases { get; }
    }

    internal class WindowsSubscriptionManager
    {
        private Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords kernelFlags;
        private readonly ManualResetEventSlim kernelConsumerReady = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim kernelConsumerFailed = new ManualResetEventSlim(false);
        private KernelSession kernelSession;
        private ETWTraceEventSource kernelSource;
        private string kernelConsumerFailure;

        internal WindowsSubscriptionManager() { }

        internal List<BaseWindowsSensor> Start()
        {
            List<BaseWindowsSensor> baseSensors = new List<BaseWindowsSensor>();
            bool enableBootProcessTrace = Properties.Settings.Default.EnableBootProcessTrace;
            string bootReplayPath = BootProcessTraceHelper.InspectCleanupArmAndGetReplayPath(
                enableBootProcessTrace,
                (message, level) => WintapLogger.Log.Append(message, level));
            WindowsProcessSensor pc = new WindowsProcessSensor();
            List<CollectorStartupEntry> configuredSensors = DiscoverConfiguredModeledSensors();
            CollectorStartupPlan startupPlan = CreateStartupPlan(configuredSensors);
            kernelFlags = startupPlan.FinalKernelFlags;

            foreach (CollectorStartupEntry entry in startupPlan.SharedKernelSensors)
            {
                WintapLogger.Log.Append("Found Kernel trace flags on " + entry.Name + " flags: " + entry.Flags, LogLevel.Info);
            }

            // Enable the shared kernel provider once with the complete final mask before snapshot/replay.
            kernelConsumerReady.Reset();
            kernelConsumerFailed.Reset();
            kernelConsumerFailure = null;
            try
            {
                kernelSession = KernelSession.Instance;
                kernelSession.EtwSession.EnableKernelProvider(kernelFlags);
                WintapLogger.Log.Append("Live kernel capture enabled before snapshot/replay with flags: " + kernelFlags, LogLevel.Info);
            }
            catch (Exception ex)
            {
                kernelConsumerFailure = "Failed to enable shared kernel provider with final flags " + kernelFlags + ": " + ex.Message;
                kernelConsumerFailed.Set();
            }

            if (!kernelConsumerFailed.IsSet)
            {
                // start unified process sensor first for process attribution
                pc.InitializeSnapshotRefresh();
                if (enableBootProcessTrace && bootReplayPath == null && pc.LastRefreshRebuiltFromSnapshot)
                {
                    WintapLogger.Log.Append(
                        "SENSOR HEALTH: boot process trace was expected but absent; early-boot process lineage may be incomplete",
                        LogLevel.Warn);
                }
                WintapLogger.Log.Append("Starting Windows process sensor", LogLevel.Info);
                pc.Start();
                WintapLogger.Log.Append("Windows process sensor started", LogLevel.Info);
                if (bootReplayPath != null)
                {
                    pc.ReplayBootTrace(bootReplayPath);
                }
                pc.TryLogExplorerProcessLineageValidation();
                baseSensors.Add(pc);

                foreach (CollectorStartupEntry entry in startupPlan.SharedKernelSensors)
                {
                    TryStartSensor(entry.Name, entry.Sensor, baseSensors);
                }

                WintapLogger.Log.Append("Creating Kernel event listening thread (ETW)...", LogLevel.Info);
                try
                {
                    // Process() blocks for the lifetime of the ETW session. A
                    // thread-pool worker can remain queued past the readiness
                    // deadline while serializers and loggers occupy pool threads.
                    var kernelConsumerThread = new System.Threading.Thread(
                        () => etwKernelModeListeningThread_DoWork(null, null))
                    {
                        IsBackground = true,
                        Name = "Wintap kernel ETW consumer"
                    };
                    kernelConsumerThread.Start();
                }
                catch (Exception ex)
                {
                    kernelConsumerFailure = ex.Message;
                    kernelConsumerFailed.Set();
                }
            }

            int readinessResult = WaitHandle.WaitAny(
                new[] { kernelConsumerFailed.WaitHandle, kernelConsumerReady.WaitHandle },
                TimeSpan.FromSeconds(5));
            if (readinessResult == 1)
            {
                foreach (CollectorStartupEntry entry in startupPlan.IndependentSensors)
                {
                    TryStartSensor(entry.Name, entry.Sensor, baseSensors);
                }

                WintapLogger.Log.Append("Done loading modelled sensors", LogLevel.Info);
                WintapLogger.Log.Append("loading unmodelled sensors", LogLevel.Info);
                foreach (string genericProvider in Properties.Settings.Default.GenericProviders)
                {
                    WintapLogger.Log.Append("Found generic etw provider in config: " + genericProvider, LogLevel.Info);
                    System.Threading.Thread.Sleep(1000);
                    GenericSensor genericSensor = new GenericSensor() { SensorName = genericProvider, EtwProviderId = genericProvider };
                    TryStartSensor(genericProvider, genericSensor, baseSensors);
                }
                WintapLogger.Log.Append("Done loading unmodelled sensors", LogLevel.Info);
            }
            else
            {
                var skippedSensors = new List<string>();
                foreach (CollectorStartupEntry entry in startupPlan.IndependentSensors)
                {
                    skippedSensors.Add(entry.Name);
                }
                foreach (string genericProvider in Properties.Settings.Default.GenericProviders)
                {
                    skippedSensors.Add(genericProvider);
                }

                string reason = readinessResult == 0
                    ? kernelConsumerFailure ?? "kernel consumer startup failed"
                    : "kernel consumer readiness timed out after five seconds";
                WintapLogger.Log.Append(
                    "Kernel Process consumer was not ready; skipped independent sensors [" +
                    string.Join(", ", skippedSensors) + "]: " + reason,
                    LogLevel.Error);
            }

            return baseSensors;
        }

        internal void Stop()
        {
            try
            {
                if (Properties.Settings.Default.EnableBootProcessTrace)
                {
                    BootProcessTraceHelper.ArmForNextBoot((message, level) => WintapLogger.Log.Append(message, level));
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error re-arming boot Process trace during shutdown: " + ex.Message, LogLevel.Error);
            }

            try
            {
                kernelSession?.EtwSession.Stop();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error stopping shared kernel ETW session: " + ex.Message, LogLevel.Error);
            }

            try
            {
                if (kernelSource != null)
                {
                    WintapLogger.Log.Append("Shared kernel ETW EventsLost at shutdown: " + kernelSource.EventsLost, LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error reading shared kernel ETW EventsLost at shutdown: " + ex.Message, LogLevel.Error);
            }
        }

        /// <summary>
        /// ETW listening thread for the NT Kernel Mode Logger
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void etwKernelModeListeningThread_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                WintapLogger.Log.Append("starting kernel mode ETW event handler", LogLevel.Info);
                //TraceEventSession  kernelSession = new TraceEventSession("NT Kernel Logger", TraceEventSessionOptions.Create);
                //kernelSession.BufferSizeMB = 250;
                //if (Properties.Settings.Default.Profile.ToUpper() == "DEVELOPER")
                //{
                //    kernelSession.BufferSizeMB = 500;
                //}
                kernelSession.Start();
                kernelSource = KernelSource.Instance.EtwSource;
                kernelConsumerReady.Set();
                kernelSource.Process();  // this is a blocking call!
                kernelConsumerFailure = "kernel event processing returned unexpectedly";
                kernelConsumerFailed.Set();
                WintapLogger.Log.Append("CRITICAL ERROR: Kernel mode etw listening thread has stopped", LogLevel.Info);
            }
            catch (Exception ex)
            {
                if (!kernelConsumerReady.IsSet)
                {
                    kernelConsumerFailure = ex.Message;
                }
                else
                {
                    WintapLogger.Log.Append("ERROR: Kernel mode ETW consumer stopped: " + ex.Message, LogLevel.Error);
                }
                kernelConsumerFailed.Set();
            }

        }

        private static void TryStartSensor(string sensorName, BaseWindowsSensor sensor, List<BaseWindowsSensor> baseSensors)
        {
            try
            {
                if (sensor.Start())
                {
                    baseSensors.Add(sensor);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append(sensorName + " problem starting sensor: " + ex.Message, LogLevel.Warn);
            }
        }

        private static List<CollectorStartupEntry> DiscoverConfiguredModeledSensors()
        {
            var configuredSensors = new List<CollectorStartupEntry>();
            string nameSpace = "gov.llnl.wintap.platform.windows.collect.etw";
            foreach (SettingsProperty sp in Properties.Settings.Default.Properties)
            {
                if (sp.Name.EndsWith("Sensor") && Properties.Settings.Default[sp.Name].ToString() == "True")
                {
                    System.Threading.Thread.Sleep(500);  // without this you will sometimes get an exception from TraceEventSession
                    string sensorName = nameSpace + "." + sp.Name;
                    WintapLogger.Log.Append("Attempting to load sensor with name: " + sensorName, LogLevel.Info);
                    try
                    {
                        Type type = Type.GetType(sensorName);
                        BaseWindowsSensor instance = (BaseWindowsSensor)Activator.CreateInstance(type, null);
                        configuredSensors.Add(CreateCollectorEntry(sensorName, instance));
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append(sp.Name + " problem loading sensor: " + ex.Message, LogLevel.Warn);
                    }
                }
            }

            return configuredSensors;
        }

        internal static CollectorStartupEntry CreateCollectorEntry(string name, BaseWindowsSensor sensor)
        {
            return new CollectorStartupEntry(name, sensor, GetKernelTraceFlags(sensor));
        }

        internal static KernelTraceEventParser.Keywords GetKernelTraceFlags(BaseWindowsSensor sensor)
        {
            return sensor is EtwProviderCollector collector
                ? collector.KernelTraceEventFlags
                : KernelTraceEventParser.Keywords.None;
        }

        internal static bool IsSharedKernelSensor(BaseWindowsSensor sensor)
        {
            return GetKernelTraceFlags(sensor) != KernelTraceEventParser.Keywords.None;
        }

        internal static KernelTraceEventParser.Keywords ComputeFinalKernelFlags(IEnumerable<KernelTraceEventParser.Keywords> sharedKernelSensorFlags)
        {
            KernelTraceEventParser.Keywords finalFlags = KernelTraceEventParser.Keywords.Process;
            if (sharedKernelSensorFlags == null)
            {
                return finalFlags;
            }

            foreach (KernelTraceEventParser.Keywords flags in sharedKernelSensorFlags)
            {
                finalFlags |= flags;
            }

            return finalFlags;
        }

        internal static CollectorStartupPlan CreateStartupPlan(IEnumerable<CollectorStartupEntry> configuredSensors)
        {
            var sharedKernelSensors = new List<CollectorStartupEntry>();
            var independentSensors = new List<CollectorStartupEntry>();
            foreach (CollectorStartupEntry entry in configuredSensors ?? Array.Empty<CollectorStartupEntry>())
            {
                if (entry.Flags != KernelTraceEventParser.Keywords.None)
                {
                    sharedKernelSensors.Add(entry);
                }
                else
                {
                    independentSensors.Add(entry);
                }
            }

            return new CollectorStartupPlan(
                ComputeFinalKernelFlags(sharedKernelSensors.ConvertAll(entry => entry.Flags)),
                sharedKernelSensors,
                independentSensors);
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // HELPER METHODS
        // ═══════════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Executes the database recovery process via WintapCoreSvcMgr.exe.
        /// Ensures process tree database integrity on startup.
        /// </summary>
        /// <returns>True if recovery completed successfully, false otherwise.</returns>
        bool CallDatabaseRecovery()
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "WintapCoreSvcMgr.exe",
                    Arguments = "RECOVER_DATABASE",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError = true
                };

                System.Diagnostics.Process wintapSvcMgr = new System.Diagnostics.Process();
                wintapSvcMgr.StartInfo = processInfo;
                wintapSvcMgr.Start();
                wintapSvcMgr.WaitForExit();

                // Wait for process to fully exit
                while (System.Diagnostics.Process.GetProcessesByName("WintapCoreSvcMgr").Length > 0)
                {
                    System.Threading.Thread.Sleep(100);
                }

                if (wintapSvcMgr.ExitCode == 0)
                {
                    WintapLogger.Log.Append("Database recovery completed successfully", LogLevel.Info);
                    return true;
                }
                else
                {
                    var error = wintapSvcMgr.StandardError.ReadToEnd();
                    WintapLogger.Log.Append($"Database recovery failed: {error}", LogLevel.Error);
                    return false;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error calling database recovery: {ex.Message}", LogLevel.Error);
                return false;
            }
        }
    }
}
