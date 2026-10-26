/*
 * Copyright (c) 2016, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.collect;

#if WINDOWS
using gov.llnl.wintap.platform.windows.collect.shared;
using gov.llnl.wintap.platform.windows.infrastructure;
#endif

#if LINUX
using gov.llnl.wintap.platform.linux.infrastructure;
#endif

#if MACOS
using gov.llnl.wintap.platform.macos.infrastructure;
#endif

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace gov.llnl.wintap.core.infrastructure
{

    public class SubscriptionManager
    {
        private List<BaseSensor> macCollectors;

#if WINDOWS
        private List<EtwProviderCollector> etwCollectors;
        private List<BaseWindowsSensor> winCollectors;
        private WindowsSubscriptionManager winSubMgr;
#endif

#if LINUX
        private List<BaseSensor> linuxCollectors;
        private LinuxSubscriptionManager linuxSubMgr;
#endif

#if MACOS
        private MacSubscriptionManager macSubMgr;
#endif

        internal SubscriptionManager()
        {
#if WINDOWS
            winCollectors = new List<BaseWindowsSensor>();
            etwCollectors = new List<EtwProviderCollector>();
            winSubMgr = new WindowsSubscriptionManager();
#endif

#if LINUX
            linuxCollectors = new List<BaseSensor>();
            linuxSubMgr = new LinuxSubscriptionManager();
#endif

#if MACOS
            macSubMgr = new MacSubscriptionManager();
#endif

            macCollectors = new List<BaseSensor>();
        }

        internal void Start()
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
#if WINDOWS
                WintapLogger.Log.Append("Starting WindowsSubscriptionManager", LogLevel.Info);
                winCollectors = winSubMgr.Start();
#endif
            }

#if LINUX
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                linuxCollectors = linuxSubMgr.Start();
            }
#endif
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
#if MACOS
                // macOS stuff
#endif
            }
            WintapLogger.Log.Append("Done loading collectors", LogLevel.Info);
        }

#if WINDOWS
        // Membership confirms successful subscription startup, not consumer liveness.
        internal bool HasStartedProcessAndFileCollectors =>
            winCollectors != null &&
            winCollectors.Exists(c => c is gov.llnl.wintap.platform.windows.collect.etw.WindowsProcessSensor) &&
            winCollectors.Exists(c => c is gov.llnl.wintap.platform.windows.collect.etw.FileSensor);
#endif

        internal void Stop()
        {
            WintapLogger.Log.Append("Serializer shutting down. ", LogLevel.Info);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
#if WINDOWS
        foreach (BaseWindowsSensor collector in winCollectors)
        {
            collector.Stop();
        }
#endif
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
#if LINUX
        // File/network Stop can still emit while pollers/senders drain. Keep
        // Linux process evidence alive through that phase, rather than stopping
        // in startup order and creating shutdown-only attribution orphans.
        foreach (BaseSensor collector in SensorShutdownOrder.DependentsBeforeIdentity(
            linuxCollectors, collector =>
                collector is gov.llnl.wintap.platform.linux.collect.ExecveSensor ||
                collector is gov.llnl.wintap.platform.linux.collect.CloneSensor ||
                collector is gov.llnl.wintap.platform.linux.collect.ExitSensor ||
                collector is gov.llnl.wintap.platform.linux.collect.ProcessRundownSensor))
        {
            collector.Stop();
        }
#endif
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
#if MACOS
                foreach (BaseSensor collector in macCollectors)
                {
                    collector.Stop();
                }
#endif
            }

            WintapLogger.Log.Append("Serializer shutdown", LogLevel.Info);
        }
    }
}
