using com.espertech.esper.client;
using com.espertech.esper.compat.collections;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.shared;
#if WINDOWS
using Microsoft.Diagnostics.Tracing;
#endif
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.IO;
using gov.llnl.wintap.core.etl;
using static gov.llnl.wintap.Interfaces;
using com.espertech.esper.runtime.client;
using com.espertech.esper.common.client;
using System.Threading.Tasks;
using System.Reflection;
using System.Threading;

namespace gov.llnl.wintap.core.infrastructure
{
    public class Runnable
    {
        public Lazy<IRun, IRunData> RunPlugin { get; set; }
        public TimeSpan RunInterval { get; set; }
        public DateTime LastRan { get; set; }
        public string RequiredHost { get; set; }
        public bool IsRunning { get; set; }
        public TimeSpan MaxTTL { get; set; }
        public TimeSpan PollRunIntervalRegistry { get; set; }
    }

    /// <summary>
    /// Manages the loading, execution, and lifecycle of Wintap plugins.
    /// Provides MEF-based plugin discovery and isolated plugin execution.
    /// Supports plugin-specific MCP servers with automatic tool namespacing.
    /// 
    /// PLUGIN CONVENTION:
    /// Each plugin must follow the directory structure: .\Plugins\PluginName\PluginName.dll
    /// Only DLLs matching their parent directory name will be loaded as plugins.
    /// All plugin dependencies should reside in the same directory.
    /// </summary>
    public class PluginManager
    {
        #region Fields and Properties

        // Static fields
        public static int PluginCount { get; private set; }
        internal static List<string> DynamicEtwProviderList { get; } = new List<string>();

        // Private fields
        private readonly WintapETL etl;
        private readonly bool doETL;
        private readonly ConcurrentQueue<Runnable> runQueue;
        private readonly HashSet<string> loadedPluginNames;
        private IsolatedPluginCatalog isolatedCatalog;
        private Watchdog watchdog;
        private int etlStopped;

        // MEF container
        private CompositionContainer mefContainer;

        // MEF imports
        [ImportMany]
        private IEnumerable<Lazy<ISubscribe, ISubscribeData>> subscribers;

        [ImportMany]
        private IEnumerable<Lazy<ISubscribeEtw, ISubscribeEtwData>> subscribersEtw;

        [ImportMany]
        private IEnumerable<Lazy<IRun, IRunData>> runners;

        [ImportMany]
        private IEnumerable<Lazy<IQuery, IQueryData>> queryPlugins;

        [ImportMany]
        private IEnumerable<Lazy<IProvide, IProvideData>> providers;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the PluginManager class.
        /// </summary>
        internal PluginManager()
        {
            WintapLogger.Log.Append("Plugin manager is starting", LogLevel.Info);
            RuntimeCapabilities.EnsureInitialized();

            runQueue = new ConcurrentQueue<Runnable>();
            loadedPluginNames = new HashSet<string>();
            string etlVal = ConfigManager.GetValue<string>("WINTAP_DISABLE_ETL");
            bool etlDisabled = string.Equals(etlVal, "true", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(etlVal, "1", StringComparison.OrdinalIgnoreCase);
            if (etlDisabled)
            {
                WintapLogger.Log.Append("ETL disabled by WINTAP_DISABLE_ETL", LogLevel.Warn);
                doETL = false;
            }
            else
            {
                etl = new WintapETL();
                doETL = etl.Start();
            }

            // Initialize exception handler
            PluginExceptionHandler.Instance.Initialize();

            WintapLogger.Log.Append($"Parquet serialization for this session: {doETL}", LogLevel.Info);
            RuntimeCapabilities.Setting("etlStarted", doETL, "plugin-manager-result");
        }

        #endregion

        #region Public Methods

        // Disabled ETL is an explicit bypass. A failed requested Start is not.
        internal Task<bool> ETLReady => etl == null ? Task.FromResult(true) : etl.Ready;

        /// <summary>
        /// Registers and initializes all discovered plugins.
        /// Async to support MCP server initialization.
        /// </summary>
        /// <param name="_watchdog">The watchdog instance to monitor plugin execution.</param>
        internal async Task RegisterPluginsAsync(Watchdog _watchdog)
        {
            try
            {
                watchdog = _watchdog;
                watchdog.Start();
                WintapLogger.Log.Append($"Loading plugins from: {Env.FilePluginPath}", LogLevel.Info);

                LoadPluginAssemblies();
#if !WINTAP_CORE
                await RegisterPluginMcpServersAsync();  // Register plugin MCP servers
#endif
                RegisterEventHandlers();
                StartPluginScheduler();

                WintapLogger.Log.Append($"PluginManager: done registering plugins. Total plugin count: {PluginCount}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Fatal error in plugin registration: {ex.Message}", LogLevel.Info);
                throw;
            }
        }

        /// <summary>
        /// Unregisters and performs cleanup for all plugins.
        /// Async to support MCP server shutdown.
        /// </summary>
        internal async Task UnregisterPluginsAsync()
        {
            watchdog?.Stop();

            try
            {
#if !WINTAP_CORE
                // Shutdown plugin MCP servers FIRST
                var mcpManager = ServiceProviderAccessor.Services?.GetService(typeof(PluginMcpManager)) as PluginMcpManager;
                if (mcpManager != null)
                {
                    await mcpManager.ShutdownAllAsync();
                }

#endif
                // Unregister providers
                foreach (var provider in providers.Reverse())
                {
                    try
                    {
                        WintapLogger.Log.Append($"Shutting down provider plugin: {provider.Metadata.Name}", LogLevel.Info);
                        provider.Value.Shutdown();
                        UnloadPluginDomain(provider.Metadata.Name);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Error shutting down provider {provider.Metadata.Name}: {ex.Message}", LogLevel.Info);
                    }
                }

                // Unregister runners
                foreach (var runner in runners.Reverse())
                {
                    try
                    {
                        WintapLogger.Log.Append($"Shutting down runner: {runner.Metadata.Name}", LogLevel.Info);
                        runner.Value.RunShutdown();
                        UnloadPluginDomain(runner.Metadata.Name);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Error shutting down runner {runner.Metadata.Name}: {ex.Message}", LogLevel.Info);
                    }
                }

                // Unregister subscribers
                foreach (var subscriber in subscribers.Reverse())
                {
                    try
                    {
                        WintapLogger.Log.Append($"Shutting down subscriber: {subscriber.Metadata.Name}", LogLevel.Info);
                        subscriber.Value.Shutdown();
                        UnloadPluginDomain(subscriber.Metadata.Name);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Error shutting down subscriber {subscriber.Metadata.Name}: {ex.Message}", LogLevel.Info);
                    }
                }

                // Unregister ETW subscribers
                foreach (var etwSubscriber in subscribersEtw.Reverse())
                {
                    try
                    {
                        WintapLogger.Log.Append($"Shutting down ETW subscriber: {etwSubscriber.Metadata.Name}", LogLevel.Info);
                        etwSubscriber.Value.Shutdown();
                        UnloadPluginDomain(etwSubscriber.Metadata.Name);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Error shutting down ETW subscriber {etwSubscriber.Metadata.Name}: {ex.Message}", LogLevel.Info);
                    }
                }

                // Unload remaining plugin domains
                foreach (var pluginName in loadedPluginNames.ToList())
                {
                    UnloadPluginDomain(pluginName);
                }

                loadedPluginNames.Clear();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error during plugin cleanup: {ex.Message}", LogLevel.Info);
            }
        }

        internal bool ShutdownEtl()
        {
            if (!doETL || etl == null || Interlocked.Exchange(ref etlStopped, 1) != 0)
            {
                return true;
            }

            return etl.Shutdown();
        }

        internal async Task<bool> ShutdownEtlWithBarrierAsync(CancellationToken cancellationToken)
        {
            if (!doETL || etl == null || Interlocked.Exchange(ref etlStopped, 1) != 0)
                return true;
            return await etl.ShutdownWithBarrierAsync(cancellationToken);
        }

        #endregion

        #region Plugin Registration Methods

        /// <summary>
        /// Discovers and loads plugin assemblies using directory-based convention.
        /// Only loads DLLs that match their parent directory name (e.g., .\Plugins\MyPlugin\MyPlugin.dll).
        /// This prevents accidental loading of dependency DLLs as plugins.
        /// </summary>
        private void LoadPluginAssemblies()
        {
            try
            {
                // Get the logger from DI container for plugin injection
                var logger = ServiceProviderAccessor.Services?.GetService(typeof(IWintapLogger)) as IWintapLogger;

                if (logger == null)
                {
                    WintapLogger.Log.Append("Warning: Could not retrieve IWintapLogger from DI container. Plugins may not have logger access.", LogLevel.Warn);
                    logger = WintapLogger.Log; // Fallback to static instance
                }

                // Get the inference service from DI container for plugin injection
                var inference = ServiceProviderAccessor.Services?.GetService(typeof(IInfer)) as IInfer;

                if (inference == null)
                {
                    WintapLogger.Log.Append("Warning: Could not retrieve IInfer from DI container. Plugins will not have AI inference access.", LogLevel.Warn);
                }
                else
                {
                    WintapLogger.Log.Append("IInfer service retrieved successfully for plugin injection", LogLevel.Debug);
                }

                // Discover plugins using directory-based convention
                var pluginPaths = DiscoverPlugins(Env.FilePluginPath);

                if (!pluginPaths.Any())
                {
                    WintapLogger.Log.Append($"No plugins discovered in {Env.FilePluginPath}", LogLevel.Warn);
                    WintapLogger.Log.Append(@"Plugin convention: .\Plugins\PluginName\PluginName.dll", LogLevel.Info);
                }

                // Create isolated catalog with discovered plugin paths
                isolatedCatalog = new IsolatedPluginCatalog(Env.FilePluginPath, pluginPaths);
                mefContainer = new CompositionContainer(isolatedCatalog);

                // Make the logger and inference service available for MEF to inject into plugin constructors
                var batch = new CompositionBatch();
                batch.AddExportedValue<IWintapLogger>(logger);

                if (inference != null)
                {
                    batch.AddExportedValue<IInfer>(inference);
                    WintapLogger.Log.Append("IInfer added to MEF composition batch", LogLevel.Debug);
                }

                mefContainer.Compose(batch);

                // Compose the PluginManager (imports all plugins)
                mefContainer.ComposeParts(this);

                PluginCount = subscribers.Count() + subscribersEtw.Count() + runners.Count();

                string servicesAvailable = inference != null ? "logger and AI inference" : "logger only";
                WintapLogger.Log.Append($"Loaded {PluginCount} plugins with {servicesAvailable} support", LogLevel.Info);
            }
            catch (ReflectionTypeLoadException ex)
            {
                foreach (Exception loaderException in ex.LoaderExceptions)
                {
                    WintapLogger.Log.Append($"Loader exception: {loaderException}", LogLevel.Info);
                }
                throw;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error loading plugin assemblies: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"Stack trace: {ex.StackTrace}", LogLevel.Debug);
                throw;
            }
        }

        /// <summary>
        /// Discovers plugins using directory-based convention.
        /// CONVENTION: .\Plugins\PluginName\PluginName.dll
        /// Only DLLs matching their parent directory name are considered plugins.
        /// </summary>
        /// <param name="pluginsBasePath">Base path to the Plugins directory</param>
        /// <returns>List of paths to valid plugin DLLs</returns>
        private List<string> DiscoverPlugins(string pluginsBasePath)
        {
            var pluginPaths = new List<string>();

            try
            {
                if (!Directory.Exists(pluginsBasePath))
                {
                    WintapLogger.Log.Append($"Plugins directory not found: {pluginsBasePath}", LogLevel.Warn);
                    return pluginPaths;
                }

                WintapLogger.Log.Append($"Discovering plugins using directory-based convention...", LogLevel.Info);

                // Iterate through each subdirectory in the Plugins folder
                foreach (var pluginDir in Directory.GetDirectories(pluginsBasePath))
                {
                    var dirName = Path.GetFileName(pluginDir);
                    var expectedDllPath = Path.Combine(pluginDir, $"{dirName}.dll");

                    if (File.Exists(expectedDllPath))
                    {
                        WintapLogger.Log.Append($"  ✓ Found plugin: {dirName} at {expectedDllPath}", LogLevel.Info);
                        pluginPaths.Add(expectedDllPath);
                        loadedPluginNames.Add(dirName);
                    }
                    else
                    {
                        WintapLogger.Log.Append($"  ✗ Skipping directory '{dirName}': no matching DLL found (expected: {expectedDllPath})", LogLevel.Debug);
                    }
                }

                WintapLogger.Log.Append($"Plugin discovery complete. Found {pluginPaths.Count} valid plugins.", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error during plugin discovery: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"Stack trace: {ex.StackTrace}", LogLevel.Debug);
            }

            return pluginPaths;
        }

        /// <summary>
        /// Registers MCP servers for plugins that implement IProvideMCP.
        /// Plugin MCP tools are automatically namespaced as "PluginName_ToolName".
        /// </summary>
#if !WINTAP_CORE
        private async Task RegisterPluginMcpServersAsync()
        {
            try
            {
                // Get the PluginMcpManager from DI
                var mcpManager = ServiceProviderAccessor.Services?.GetService(typeof(PluginMcpManager)) as PluginMcpManager;

                if (mcpManager == null)
                {
                    WintapLogger.Log.Append("PluginMcpManager not available, skipping plugin MCP server registration", LogLevel.Debug);
                    return;
                }

                int mcpPluginCount = 0;

                // Check all plugin types for IProvideMCP implementation
                mcpPluginCount += await RegisterMcpForPluginType(subscribers, mcpManager);
                mcpPluginCount += await RegisterMcpForPluginType(subscribersEtw, mcpManager);
                mcpPluginCount += await RegisterMcpForPluginType(runners, mcpManager);

                if (queryPlugins != null)
                {
                    mcpPluginCount += await RegisterMcpForPluginType(queryPlugins, mcpManager);
                }

                mcpPluginCount += await RegisterMcpForPluginType(providers, mcpManager);

                WintapLogger.Log.Append($"Registered MCP servers for {mcpPluginCount} plugins", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error registering plugin MCP servers: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"Stack trace: {ex.StackTrace}", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Registers MCP servers for a collection of plugins of type T.
        /// Uses reflection to check for IProvideMCP across isolated domains.
        /// </summary>
        /// <returns>Count of plugins with MCP servers registered</returns>
        private async Task<int> RegisterMcpForPluginType<T, TData>(IEnumerable<Lazy<T, TData>> plugins, PluginMcpManager mcpManager)
            where TData : class
        {
            if (plugins == null) return 0;

            int count = 0;

            foreach (var plugin in plugins)
            {
                try
                {
                    string pluginName = GetPluginName(plugin.Metadata);

                    // Get the plugin instance
                    var pluginValue = plugin.Value;
                    var pluginType = pluginValue.GetType();

                    // Check if plugin implements IProvideMCP using reflection
                    // This works across AssemblyLoadContext boundaries
                    var provideMcpInterface = pluginType.GetInterface("IProvideMCP");

                    if (provideMcpInterface != null)
                    {
                        WintapLogger.Log.Append($"Plugin {pluginName} implements IProvideMCP", LogLevel.Debug);

                        // Call GetMcpServerPath() using reflection
                        var getMcpServerPathMethod = pluginType.GetMethod("GetMcpServerPath");

                        if (getMcpServerPathMethod != null)
                        {
                            var mcpServerPath = getMcpServerPathMethod.Invoke(pluginValue, null) as string;

                            if (!string.IsNullOrWhiteSpace(mcpServerPath))
                            {
                                WintapLogger.Log.Append($"Plugin {pluginName} provides MCP server at {mcpServerPath}", LogLevel.Info);

                                bool success = await mcpManager.RegisterPluginMcpServerAsync(pluginName, mcpServerPath);

                                if (success)
                                {
                                    count++;
                                    WintapLogger.Log.Append($"Successfully registered MCP server for plugin {pluginName}", LogLevel.Info);
                                }
                                else
                                {
                                    WintapLogger.Log.Append($"Failed to register MCP server for plugin {pluginName}", LogLevel.Warn);
                                }
                            }
                            else
                            {
                                WintapLogger.Log.Append($"Plugin {pluginName} returned empty MCP server path", LogLevel.Debug);
                            }
                        }
                        else
                        {
                            WintapLogger.Log.Append($"Plugin {pluginName} implements IProvideMCP but GetMcpServerPath method not found", LogLevel.Warn);
                        }
                    }
                    else
                    {
                        WintapLogger.Log.Append($"Plugin {pluginName} does not implement IProvideMCP", LogLevel.Debug);
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Error checking plugin for MCP server: {ex.Message}", LogLevel.Warn);
                    WintapLogger.Log.Append($"Stack trace: {ex.StackTrace}", LogLevel.Debug);
                }
            }

            return count;
        }

        /// <summary>
        /// Helper method to extract plugin name from metadata.
        /// </summary>
#endif
        private string GetPluginName(object metadata)
        {
            // Use reflection to get the Name property from metadata
            var nameProperty = metadata.GetType().GetProperty("Name");
            return nameProperty?.GetValue(metadata)?.ToString() ?? "Unknown";
        }

        private void RegisterEventHandlers()
        {
            // Register subscribers
            foreach (var subscriber in subscribers)
            {
                RegisterSubscriber(subscriber);
            }

            // Register ETW subscribers
            foreach (var consumer in subscribersEtw)
            {
                RegisterEtwSubscriber(consumer);
            }

            // Register runners
            foreach (var runner in runners)
            {
                RegisterRunner(runner);
            }

            // Register providers
            foreach (var provider in providers)
            {
                RegisterProvider(provider);
            }

            // Register queries if enabled
            if (queryPlugins?.Any() == true)
            {
                foreach (var queryPlugin in queryPlugins)
                {
                    RegisterQueryPlugin(queryPlugin);
                }
            }

            ConfigureEsperEventRouting();
        }

        /// <summary>
        /// Registers a Wintap subscriber plugin by initializing it and enabling its requested event collectors. 
        /// The plugin specifies which events it wants to monitor (Process, File, Registry, etc.) via EventFlags,
        /// and the corresponding collectors are automatically enabled in Wintap's settings.
        /// </summary>
        /// <param name="subscriber">The lazy-loaded subscriber plugin with its metadata</param>
        private void RegisterSubscriber(Lazy<ISubscribe, ISubscribeData> subscriber)
        {
            var pluginName = subscriber.Metadata.Name;
            WintapLogger.Log.Append($"Loading {Env.AppName} subscriber: {pluginName}", LogLevel.Info);

            try
            {
                PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                {
                    EventFlags eventFlags = subscriber.Value.Startup();
                    enableEventFlags(eventFlags);
                }, pluginName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Problem loading subscriber {pluginName}: {ex.Message}", LogLevel.Warn);
            }
        }

        private void RegisterEtwSubscriber(Lazy<ISubscribeEtw, ISubscribeEtwData> consumer)
        {
            var pluginName = consumer.Metadata.Name;
            WintapLogger.Log.Append($"Loading ETW subscriber: {pluginName}", LogLevel.Info);

            try
            {
                PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                {
                    List<string> etwProviders = consumer.Value.Startup();
                    enableDynamicEtwProviders(etwProviders);
                }, pluginName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Problem loading ETW subscriber {pluginName}: {ex.Message}", LogLevel.Warn);
            }
        }

        private void RegisterRunner(Lazy<IRun, IRunData> runner)
        {
            var pluginName = runner.Metadata.Name;
            WintapLogger.Log.Append($"Loading runner: {pluginName}", LogLevel.Info);

            try
            {
                PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                {
                    var runManifest = runner.Value.RunStartup();
                    var maxTTL = runManifest.MaxRuntime;
                    var requiredHost = runManifest.RequiredHost;
                    var interval = runManifest.Interval;
                    var runnable = CreateRunnable(runner, maxTTL, requiredHost, interval);
                    runQueue.Enqueue(runnable);
                }, pluginName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Problem loading Runner {pluginName}: {ex.Message}", LogLevel.Warn);
            }
        }

        private void RegisterProvider(Lazy<IProvide, IProvideData> provider)
        {
            var pluginName = provider.Metadata.Name;
            WintapLogger.Log.Append($"Loading provider plugin: {pluginName}", LogLevel.Info);

            try
            {
                PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                {
                    provider.Value.Startup();
                    provider.Value.Events += Plugin_Events;
                }, pluginName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Problem loading provider plugin {pluginName}: {ex.Message}", LogLevel.Warn);
            }
        }

        private void RegisterQueryPlugin(Lazy<IQuery, IQueryData> queryPlugin)
        {
            var pluginName = queryPlugin.Metadata.Name;
            WintapLogger.Log.Append($"Loading query plugin: {pluginName}", LogLevel.Info);

            try
            {
                PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                {
                    List<EventQuery> queries = queryPlugin.Value.Startup();
                    foreach (var query in queries)
                    {
                        RegisterEsperQuery(query, pluginName);
                    }
                }, pluginName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Problem loading Query plugin {pluginName}: {ex.Message}", LogLevel.Warn);
            }
        }

        private void RegisterEsperQuery(EventQuery query, string pluginName)
        {
            try
            {
                EPDeployment deployment = EventChannel.CompileDeploy(query.Query, pluginName);
                deployment.Statements[0].Events += (sender, e) =>
                {
                    PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                    {
                        HandleQueryEvent(sender, e, query, pluginName);
                    }, pluginName);
                };
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error registering Esper query for {pluginName}: {ex.Message}", LogLevel.Info);
            }
        }

        private void ConfigureEsperEventRouting()
        {
            // ETL serializers deploy their own EPL statements. The broad
            // all-event route is only needed when subscriber plugins exist.
            if (subscribers.Any())
            {
                try
                {
                    WintapLogger.Log.Append("Creating Subscriber EPL", LogLevel.Info);
                    EPStatement processEvents = EventChannel.CompileDeploy(
                        "SELECT * FROM WintapMessage WHERE CAST(MessageType, string) <> 'ProcessPartial'", "ProcessPartial"
                    ).Statements[0];
                    processEvents.Events += All_Events;
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Error creating EPL: {ex.Message}", LogLevel.Info);
                }
            }

            if (subscribersEtw.Any())
            {
                try
                {
                    EPStatement allWintapMsgs = EventChannel.CompileDeploy(
                        "SELECT * FROM WintapMessage WHERE MessageType = 'GenericMessage' AND GenericMessage.Provider != 'Plugin'"
                    , Guid.NewGuid().ToString()).Statements[0];
                    allWintapMsgs.Events += AllGeneric_Events;
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Error creating EPL: {ex.Message}", LogLevel.Info);
                }
            }
        }

        #endregion

        #region Event Handlers

        private void All_Events(object sender, UpdateEventArgs e)
        {
            foreach (var consumer in subscribers)
            {
                foreach (var newEvent in e.NewEvents)
                {
                    try
                    {
                        var msg = (WintapMessage)newEvent.Underlying;
                        PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                        {
                            consumer.Value.Subscribe(msg);
                        }, consumer.Metadata.Name);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Could not deliver event to subscriber: {ex.Message}", LogLevel.Debug);
                    }
                }
            }
        }

        private void AllGeneric_Events(object sender, UpdateEventArgs e)
        {
            foreach (var consumer in subscribersEtw)
            {
                foreach (var newEvent in e.NewEvents)
                {
                    try
                    {
                        var msg = (WintapMessage)newEvent.Underlying;
                        PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                        {
                            consumer.Value.Subscribe(msg);
                        }, consumer.Metadata.Name);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Could not deliver GENERIC ETW event to subscriber: {ex.Message}", LogLevel.Debug);
                    }
                }
            }
        }

        private void Plugin_Events(object sender, ProviderEventArgs e)
        {
            try
            {
                var msg = new WintapMessage(DateTime.UtcNow, e.GenericEvent.PID, WintapMessage.MessageTypeEnum.GenericMessage)
                {
                    GenericMessage = e.GenericEvent,
                    ActivityType = WintapMessage.ActivityTypeEnum.Other
                };
                EventChannel.Send(msg);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error on plugin event: {ex.Message}", LogLevel.Debug);
            }
        }

        private void HandleQueryEvent(object sender, UpdateEventArgs e, EventQuery query, string pluginName)
        {
            QueryResult result = new QueryResult
            {
                Name = query.Name,
                EventDetails = new List<KeyValuePair<string, string>>(),
                Activity = new List<WintapMessage>()
            };

            foreach (var newEvent in e.NewEvents)
            {
                // Add event details
                foreach (var propName in newEvent.EventType.PropertyNames)
                {
                    result.EventDetails.Add(new KeyValuePair<string, string>(
                        propName,
                        newEvent[propName]?.ToString() ?? "null"
                    ));
                }

                // Add activity if it's a WintapMessage
                if (newEvent.Underlying is WintapMessage msg)
                {
                    result.Activity.Add(msg);
                }
            }

            // Find the query plugin and process the result
            var plugin = queryPlugins.FirstOrDefault(p => p.Metadata.Name == pluginName);
            if (plugin != null)
            {
                plugin.Value.Process(result);
            }
        }

        #endregion

        #region Plugin Domain Management

        private void UnloadPluginDomain(string pluginName)
        {
            try
            {
                if (isolatedCatalog != null)
                {
                    isolatedCatalog.UnloadPlugin(pluginName);
                    loadedPluginNames.Remove(pluginName);
                    WintapLogger.Log.Append($"Successfully unloaded plugin domain for {pluginName}", LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error unloading plugin domain for {pluginName}: {ex.Message}", LogLevel.Info);
            }
        }

        #endregion

        #region Plugin Execution Methods

        private void StartPluginScheduler()
        {
            if (runQueue.Count > 0)
            {
                WintapLogger.Log.Append("Starting Run scheduler", LogLevel.Info);
                BackgroundWorker scheduler = new BackgroundWorker();
                scheduler.DoWork += Scheduler_DoWork;
                scheduler.RunWorkerAsync();
            }
        }

        private void Scheduler_DoWork(object sender, DoWorkEventArgs e)
        {
            bool schedulerLoopAlive = true;
            while (schedulerLoopAlive && !e.Cancel)
            {
                ProcessRunQueue(ref schedulerLoopAlive);
                System.Threading.Thread.Sleep(60000);
            }
            WintapLogger.Log.Append("Plugin run scheduler is quitting", LogLevel.Info);
        }

        private void ProcessRunQueue(ref bool schedulerLoopAlive)
        {
            for (int i = 0; i < runQueue.Count && schedulerLoopAlive; i++)
            {
                Runnable runnable;
                if (runQueue.TryDequeue(out runnable))
                {
                    try
                    {
                        var pluginName = runnable.RunPlugin.Metadata.Name;
                        PluginExceptionHandler.Instance.WrapPluginMethod(() =>
                        {
                            if (checkConditions(runnable))
                            {
                                ExecuteRunnable(runnable);
                            }
                        }, pluginName);
                        runQueue.Enqueue(runnable);
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"Error in plugin scheduler: {ex.Message}. Run scheduler is aborting", LogLevel.Info);
                        schedulerLoopAlive = false;
                    }
                }
            }
        }

        private void ExecuteRunnable(Runnable runnable)
        {
            try
            {
                runnable.LastRan = persistLastRan(runnable);
                watchdog.ProtectedRun(runnable);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error executing runnable: {ex.Message}", LogLevel.Info);
                throw;
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// this section allows plugins to enable certain sensors at runtime (as opposed to config)
        /// todo:  make dynamic or extend to full sensor list
        /// </summary>
        /// <param name="eventFlags"></param>
        private void enableEventFlags(EventFlags eventFlags)
        {
            var flagsStr = eventFlags.ToString();

            // WindowsProcessSensor is mandatory and no longer settings-enabled.
            if (flagsStr.Contains("FileActivity"))
                Properties.Settings.Default.FileSensor = true;
            if (flagsStr.Contains("RegistryActivity"))
                Properties.Settings.Default.RegistrySensor = true;
            if (flagsStr.Contains("UdpPacket"))
                Properties.Settings.Default.UdpSensor = true;
            if (flagsStr.Contains("TcpConnection"))
                Properties.Settings.Default.TcpSensor = true;
            if (flagsStr.Contains("SessionChange"))
                Properties.Settings.Default.SensSensor = true;
            if (flagsStr.Contains("FocusChange"))
                Properties.Settings.Default.UISensor = true;
            if (flagsStr.Contains("ImageLoad"))
                Properties.Settings.Default.ImageLoadSensor = true;
            if (flagsStr.Contains("WaitCursor"))
                Properties.Settings.Default.UISensor = true;
        }

        private void enableDynamicEtwProviders(List<string> etwProviders)
        {
            foreach (string provider in etwProviders)
            {
                if (!DynamicEtwProviderList.Contains(provider))
                {
                    DynamicEtwProviderList.Add(provider);
                }
            }
        }

        private bool checkConditions(Runnable runnable)
        {
            var timeConditionToRun = CheckTimeCondition(runnable);
            var hostConditionMet = CheckHostCondition(runnable);
            return timeConditionToRun && hostConditionMet;
        }

        private bool CheckTimeCondition(Runnable runnable)
        {
            var useConfigInterval = runnable.PollRunIntervalRegistry.TotalMilliseconds > 0;
            var interval = useConfigInterval ? runnable.PollRunIntervalRegistry : runnable.RunInterval;

            return interval.TotalMilliseconds > 0 &&
                   DateTime.Now - runnable.LastRan >= interval;
        }

        private bool CheckHostCondition(Runnable runnable)
        {
            if (runnable.RequiredHost == "NONE")
                return true;

            return pingHost(runnable.RequiredHost);
        }

        private DateTime persistLastRan(Runnable runnable)
        {
            var lastRan = DateTime.Now;
            try
            {
                using (var pluginKey = Registry.LocalMachine.CreateSubKey(
                    Env.RegistryPluginPath + "\\" + runnable.RunPlugin.Metadata.Name,
                    RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    pluginKey.SetValue("LastRan", lastRan.ToString());
                    pluginKey.Flush();
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error updating LastRan registry key: {ex.Message}", LogLevel.Info);
            }
            return lastRan;
        }

        private Runnable CreateRunnable(Lazy<IRun, IRunData> runPlugin, TimeSpan maxTTL, string requiredHost, TimeSpan interval)
        {
            try
            {
                var runnable = new Runnable
                {
                    RunPlugin = runPlugin,
                    MaxTTL = maxTTL,
                    RequiredHost = requiredHost,
                    RunInterval = interval,
                    LastRan = DateTime.Now - new TimeSpan(24, 0, 0), // Default to time expiry on all plugins
                    IsRunning = false
                };

                // Try to get last run time from registry
                try
                {
                    using (var pluginKey = Registry.LocalMachine.OpenSubKey(Env.RegistryPluginPath + "\\" + runPlugin.Metadata.Name))
                    {
                        if (pluginKey != null)
                        {
                            var lastRanStr = pluginKey.GetValue("LastRan")?.ToString();
                            if (!string.IsNullOrEmpty(lastRanStr))
                            {
                                runnable.LastRan = DateTime.Parse(lastRanStr);
                            }

                            var runIntervalStr = pluginKey.GetValue("RunInterval")?.ToString();
                            if (!string.IsNullOrEmpty(runIntervalStr))
                            {
                                runnable.PollRunIntervalRegistry = TimeSpan.FromSeconds(Convert.ToInt32(runIntervalStr));
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Error reading plugin registry settings: {ex.Message}", LogLevel.Info);
                }

                return runnable;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error creating runnable: {ex.Message}", LogLevel.Info);
                throw;
            }
        }

        private bool pingHost(string hostname)
        {
            using (var pingSender = new Ping())
            {
                try
                {
                    var options = new PingOptions { DontFragment = true };
                    var data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    var buffer = Encoding.ASCII.GetBytes(data);
                    var timeout = 120;

                    var reply = pingSender.Send(hostname, timeout, buffer, options);
                    return reply.Status == IPStatus.Success;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        #endregion
    }
}
