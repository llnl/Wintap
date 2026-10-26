using DuckDB.NET.Data;

using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.infrastructure.health;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.Properties;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap
{
    // ═══════════════════════════════════════════════════════════════════════════
    // SERVICE INFRASTRUCTURE
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Provides global access to the dependency injection service provider.
    /// Used by components that need DI services outside the normal injection flow.
    /// </summary>
    public static class ServiceProviderAccessor
    {
        public static IServiceProvider Services { get; set; }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN SERVICE IMPLEMENTATION
    // ═══════════════════════════════════════════════════════════════════════════

    public partial class WinTapSvc : BackgroundService
    {
        // ─── Instance Fields ───────────────────────────────────────────────────
        private readonly ILogger<WinTapSvc> _logger;
        private PluginManager pluginMgr;
        private SubscriptionManager subscriptionMgr;
#if WINDOWS
        private readonly object fileValidationLock = new object();
        private bool fileValidationStopping;
        private platform.windows.infrastructure.FileAttributionValidation fileValidation;
#endif

        // ─── Static Initialization ─────────────────────────────────────────────
        static WinTapSvc()
        {
            // Ensure WintapLogger is initialized before any static constructors
            try
            {
                WintapLogger.Log.Init();
                //WintapLogger.Log.Append("WintapLogger static initialization complete",
                //    LogLevel.Info, true, EventLogEntryType.SuccessAudit, 100);
            }
            catch (Exception ex)
            {
                // Can't use WintapLogger here since initialization failed
                Console.WriteLine($"Failed to initialize WintapLogger: {ex}");
                throw;
            }
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // SERVICE LIFECYCLE
        // ═══════════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Initializes a new instance of the WinTapSvc service.
        /// </summary>
        public WinTapSvc(ILoggerFactory loggerFactory)
        {
            try
            {
                _logger = loggerFactory.CreateLogger<WinTapSvc>();
                WintapLogger.Log.Append("WinTapSvc constructor starting", LogLevel.Info);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in WinTapSvc constructor: {ex}");
                throw;
            }
        }

        /// <summary>
        /// Main service execution loop. Starts initialization asynchronously
        /// and keeps service alive until cancellation is requested.
        /// </summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                WintapLogger.Log.Append("WinTapSvc ExecuteAsync starting", LogLevel.Info);

                // Start initialization asynchronously (no longer using BackgroundWorker)
                _ = Task.Run(async () => await StartupWorkerAsync(), stoppingToken);
                WintapLogger.Log.Append("Started async startup task", LogLevel.Info);

                // Keep service running until stop is requested
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(1000, stoppingToken);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error in ExecuteAsync: {ex}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Handles graceful shutdown of all Wintap components.
        /// </summary>
        public override async Task StopAsync(CancellationToken cancellationToken)
        {
#if WINDOWS
            platform.windows.infrastructure.FileAttributionValidation validation;
            lock (fileValidationLock)
            {
                fileValidationStopping = true;
                validation = fileValidation;
                validation?.Cancel();
            }
            if (validation != null) await validation.JoinAsync();
#endif
            WintapLogger.Log.Append("Stop command received. Attempting to shutdown plugins",
                LogLevel.Info);
            AttributionTrace.RecordBoundary("service-stop-begin", "service");

            try
            {
                // Stop health monitoring first: suppresses liveness stall alarms while
                // components shut down and flushes the final window while the log is open.
#if !LINUX
                EventChannel.FlushPendingAttributionEvents();
#endif
                SensorHealthMonitor.Default.Stop();

                // The shutdown registry marker is Windows-only. Attempting it
                // on Linux aborts the surrounding shutdown sequence before
                // collectors and ETL can drain.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    using (var wintapKey = Registry.LocalMachine.CreateSubKey(Env.RegistryRootPath))
                    {
                        wintapKey.SetValue("LastRestart", DateTime.Now, RegistryValueKind.String);
                        wintapKey.SetValue("WatchdogRestart", Watchdog.PerformanceBreach, RegistryValueKind.DWord);
                        wintapKey.Flush();
                    }
                }

                // Shutdown plugins (now async)
                try
                {
                    if (pluginMgr != null)
                    {
                        WintapLogger.Log.Append("Shutting down plugin manager (async)...", LogLevel.Info);
                        await pluginMgr.UnregisterPluginsAsync();
                        WintapLogger.Log.Append("Plugin manager shutdown complete", LogLevel.Info);
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Exception in plugin shutdown: {ex.Message}",
                        LogLevel.Info);
                }

                // Stop data collectors
                AttributionTrace.RecordBoundary("collector-stop-begin", "service");
                if (subscriptionMgr != null)
                {
                    subscriptionMgr.Stop();
                }
                AttributionTrace.RecordBoundary("collector-stop-end", "service");

#if LINUX
                // Do not stop accepting attribution retries while data producers
                // can still emit during their shutdown. All producer callbacks
                // have now completed; use their final lifecycle evidence before
                // draining Esper windows and serializers.
                EventChannel.FlushPendingAttributionEvents();
                AttributionTrace.RecordBoundary("attribution-final-flush-end", "service");
#endif

                // Experimental isolation: sender/retry draining is not equivalent
                // to draining a live Esper time_batch/context. Current File/TCP/
                // UDP aggregations use ten-second windows. Keep their subscribers
                // alive for one full boundary after the last producer is stopped.
                // Default shutdown behavior is unchanged pending cross-platform QA.
                if (string.Equals(Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_DRAIN_BATCH_WINDOWS"),
                    "true", StringComparison.OrdinalIgnoreCase))
                {
                    WintapLogger.Log.Append("Experimental batch drain: producers stopped; awaiting 11s Esper boundary", LogLevel.Info);
                    await Task.Delay(TimeSpan.FromSeconds(11));
                    WintapLogger.Log.Append("Experimental batch drain: boundary wait complete; draining serializers", LogLevel.Info);
                }

                // All producers are now stopped. Drain serializer queues, wait
                // for parquet finalization, then perform the final cache merge.
                bool requireShutdownBarrier = EtlShutdownBarrier.Enabled(OperatingSystem.IsLinux(),
                    Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_ETL_SHUTDOWN_BARRIER"));
                bool etlComplete = pluginMgr == null || (requireShutdownBarrier
                    ? await pluginMgr.ShutdownEtlWithBarrierAsync(cancellationToken)
                    : pluginMgr.ShutdownEtl());
                if (!etlComplete)
                {
                    WintapLogger.Log.Append("ETL shutdown did not fully drain before its timeout.", LogLevel.Warn);
                }
                AttributionTrace.RecordBoundary("etl-shutdown-end", "service", complete: etlComplete);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error in shutdown: {ex.Message}", LogLevel.Info);
            }

            WintapLogger.Log.Append("Shutdown complete.", LogLevel.Info);
            AttributionTrace.Close();
            WintapLogger.Log.Close();

            await base.StopAsync(cancellationToken);
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // INITIALIZATION & STARTUP
        // ═══════════════════════════════════════════════════════════════════════════

        /// <summary>
        /// Async startup worker that handles all service initialization tasks.
        /// Runs asynchronously to prevent blocking the main service startup.
        /// </summary>
        private async Task StartupWorkerAsync()
        {
            try
            {
                WintapLogger.Log.Append("StartupWorker beginning initialization", LogLevel.Info);
                foreach (string key in new[] { "WINTAP_DISABLE_SENSORS", "WINTAP_DISABLE_ETL", "WINTAP_ENABLE_DIRECT_PARQUET",
                    "WINTAP_SKIP_PROCESS_RESOLVE", "WINTAP_SKIP_PARENT_PROCESS_RESOLVE", "WINTAP_SKIP_PROCESS_REGISTER",
                    "WINTAP_SKIP_ESPER_SEND", "WriteToParquet", "EnableBpfDiagMonitor" })
                    RuntimeCapabilities.Setting(key, ConfigManager.GetValue<bool>(key), ConfigManager.GetValueSource<bool>(key));
                foreach (string key in new[] { "SensorProfile" })
                    RuntimeCapabilities.Setting(key, ConfigManager.GetValue<string>(key), ConfigManager.GetValueSource<string>(key));
                RuntimeCapabilities.Setting("parquetCompression", core.etl.load.ParquetWriter.GetCompressionMethod().ToString(), "writer-effective");

                // ─── Platform-Specific Configuration ───────────────────────────
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    bool isDebugBuild = false;
#if DEBUG
                    isDebugBuild = true;
#endif
                    if (isDebugBuild)
                    {
                        WintapLogger.Log.Append($"DEBUG build detected, not setting NTFS permissions on {Env.AppName} data",
                            LogLevel.Warn);
                    }
                    else
                    {
                        WintapLogger.Log.Append($"Setting NTFS permissions on {Env.AppName}  data directory",
                            LogLevel.Info);
                        Utilities.SetDirectoryPermissions(
                            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Wintap"));
                    }
                }

                // ─── Agent Identification ──────────────────────────────────────
                WintapLogger.Log.Append($"{Env.AppName} Agent ID: {StateManager.AgentId}",LogLevel.Info);

                // ─── Initialize EventChannel with Process Resolver ─────────────
                WintapLogger.Log.Append("Initializing EventChannel with process resolver",LogLevel.Info);
                var processResolver = ServiceProviderAccessor.Services.GetService(typeof(IProcessResolver)) as IProcessResolver;
                EventChannel.Initialize(processResolver);

                // ─── Plugin Management ─────────────────────────────────────────
                WintapLogger.Log.Append("Loading plugin manager...", LogLevel.Info);
                pluginMgr = new PluginManager();

                // ─── Performance Monitoring ────────────────────────────────────
                WintapLogger.Log.Append("Creating performance monitor", LogLevel.Info);
                Watchdog watchdog = new Watchdog();

                // ─── Plugin Registration (NOW ASYNC) ───────────────────────────
                try
                {
                    WintapLogger.Log.Append("Attempting to register plugins (async)...", LogLevel.Info);
                    await pluginMgr.RegisterPluginsAsync(watchdog);
                    WintapLogger.Log.Append("Plugin registration complete", LogLevel.Info);
                }
                catch (ReflectionTypeLoadException ex)
                {
                    foreach (Exception loaderException in ex.LoaderExceptions)
                    {
                        WintapLogger.Log.Append($"Loader exception: {loaderException}",
                            LogLevel.Info);
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Problem loading plugin: {ex.Message}",
                        LogLevel.Warn);
                    WintapLogger.Log.Append($"Stack trace: {ex.StackTrace}", LogLevel.Debug);
                }

                // ─── DuckDB UI Server ──────────────────────────────────────────
                 string duckVal = ConfigManager.GetValue<string>("WINTAP_DISABLE_DUCKDB_UI");
                 bool duckDbUiDisabled = string.Equals(duckVal, "true", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(duckVal, "1", StringComparison.OrdinalIgnoreCase);
                if (duckDbUiDisabled)
                {
                    WintapLogger.Log.Append("DuckDB UI server disabled by WINTAP_DISABLE_DUCKDB_UI", LogLevel.Warn);
                }
                else try
                {
                    WintapLogger.Log.Append("Starting DuckDB UI server", LogLevel.Info);
                    var duckDBConnection = new DuckDBConnection("Data Source=:memory:");
                    duckDBConnection.Open();
                    var command = duckDBConnection.CreateCommand();
                    command.CommandText = "CALL start_ui_server()";
                    WintapLogger.Log.Append("Duck db command: " + command.CommandText,
                        LogLevel.Info);
                    var executeNonQuery = command.ExecuteNonQuery();
                    WintapLogger.Log.Append("DuckDB UI server started", LogLevel.Info);
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Could not start DuckDB UI: {ex.Message}",
                        LogLevel.Error);
                }

                // ─── Plugin Initialization Delay ───────────────────────────────
                // Allow plugins to initialize before starting collectors
                WintapLogger.Log.Append("Waiting for plugin initialization (5 seconds)...", LogLevel.Info);
                await Task.Delay(5000);

                bool requireEtlReady = EtlStartupReadiness.Enabled(OperatingSystem.IsLinux(),
                    ConfigManager.GetValue<string>("WINTAP_EXPERIMENT_ETL_READINESS"));
                RuntimeCapabilities.Setting("etlReadinessRequired", requireEtlReady, "startup-control");
                if (requireEtlReady)
                {
                    AttributionTrace.RecordQuery("etl-readiness-wait", "service", null, null);
                    try
                    {
                        await EtlStartupReadiness.RequireAsync(pluginMgr?.ETLReady, TimeSpan.FromSeconds(30));
                        AttributionTrace.RecordQuery("etl-readiness-passed", "service", null, null);
                        WintapLogger.Log.Append("ETL queries and callbacks ready before collector startup", LogLevel.Info);
                    }
                    catch (Exception ex)
                    {
                        AttributionTrace.RecordQuery("etl-readiness-blocked", "service", null, null, error: ex.ToString());
                        throw;
                    }
                }

                // ─── Collector Startup ─────────────────────────────────────────
                 string sensorsVal = ConfigManager.GetValue<string>("WINTAP_DISABLE_SENSORS");
                 bool sensorsDisabled = string.Equals(sensorsVal, "true", StringComparison.OrdinalIgnoreCase) ||
                                       string.Equals(sensorsVal, "1", StringComparison.OrdinalIgnoreCase);
                if (sensorsDisabled)
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                        foreach (string key in new[] { "Execve", "Clone", "Exit", "Network", "FileOps", "SELinux", "ProcessRundown" })
                            RuntimeCapabilities.Sensor(key, false, "global:WINTAP_DISABLE_SENSORS");
                    WintapLogger.Log.Append("Sensors disabled by WINTAP_DISABLE_SENSORS", LogLevel.Warn);
                }
                else try
                {
                    WintapLogger.Log.Append($"Starting {Env.AppName} sensors", LogLevel.Info);
                    AttributionTrace.RecordQuery("collector-start-call", "service", null, null);
                    subscriptionMgr = new SubscriptionManager();
                    subscriptionMgr.Start();
                    SensorHealthMonitor.Default.Start();
                    WintapLogger.Log.Append("Sensor health monitor started", LogLevel.Info);
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"ERROR starting event subscription manager: {ex.Message}",
                        LogLevel.Error);
                }

#if WINDOWS
                if (platform.windows.infrastructure.FileAttributionValidation.Enabled(
                    ConfigManager.GetValue<string>(platform.windows.infrastructure.FileAttributionValidation.Flag)))
                {
                    lock (fileValidationLock)
                    {
                        if (!fileValidationStopping && fileValidation == null)
                        {
                            fileValidation = new platform.windows.infrastructure.FileAttributionValidation(
                                processResolver is ProcessResolver concrete ? concrete.ReadAttributedProcessPath : null);
                            fileValidation.Start(platform.windows.infrastructure.FileAttributionValidation.Unavailable(
                                RuntimeInformation.IsOSPlatform(OSPlatform.Windows), processResolver != null,
                                subscriptionMgr?.HasStartedProcessAndFileCollectors == true,
                                key => ConfigManager.GetValue<string>(key)));
                        }
                    }
                }
#endif
                string capabilityJson = RuntimeCapabilities.Complete();
                WintapLogger.Log.Append("RUNTIME_CAPABILITIES " + capabilityJson, LogLevel.Info);
                // Independent of Esper/ETL enablement and previous HOST files.
                await core.etl.extract.HostSerializer.Instance.WriteHostRecordAsync(publish: true);
                WintapLogger.Log.Append("Startup complete.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error in startup worker: {ex.Message}",
                    LogLevel.Error);
                _logger.LogError(ex, "Fatal error in startup worker");
                throw;
            }
        }
    }
}
