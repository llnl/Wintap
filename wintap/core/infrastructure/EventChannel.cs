/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using com.espertech.esper.common.client;
using com.espertech.esper.common.client.configuration;
using com.espertech.esper.compat;
using com.espertech.esper.compiler.client;
using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.infrastructure.health;
using gov.llnl.wintap.core.infrastructure.helpers;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace gov.llnl.wintap.core.infrastructure
{
    /// <summary>
    /// Central event routing and processing hub for Wintap telemetry data.
    /// Manages event enrichment, statistics tracking, and interactive query workbench functionality for real-time telemetry analysis.
    /// </summary>
    /// <remarks>
    /// Core Responsibilities (todo: map these to seperate classes):
    /// - Event Processing: Routes telemetry events to Esper CEP engine with process lineage enrichment
    /// - Event History:  Provides process attribution through historical process lookup
    /// - Performance Monitoring: Tracks throughput metrics including events/second, peak rates, and total event counts
    /// - Query Management: Compiles, deploys, and manages user-defined EPL (Event Processing Language) queries
    /// - Workbench State: Persists and restores interactive analysis queries across sessions
    /// 
    /// Query Workbench:
    /// The workbench allows researchers to interactively create and test EPL queries against live telemetry streams.
    /// Only one query can be active at a time, with state persisted to workbench-state.json.
    /// </remarks>
    public sealed class EventChannel
    {
        private static readonly EventChannel instance = new EventChannel();

        // **************************************************************************
        // ***  STATISTICS TRACKING
        // **************************************************************************
        private static long eventsPerSecond;
        private static long maxEventsPerSecond;
        private static DateTime maxEventTime;
        private static long totalEvents;
        private static long lastTotalEvents;
        private static int droppedEventCount;
        private static IProcessResolver _processResolver;

        // Avoid spamming logs when process attribution is missing.
        private static readonly ConcurrentDictionary<int, byte> _loggedMissingOwnerPid = new ConcurrentDictionary<int, byte>();
        private static readonly ConcurrentDictionary<int, byte> _loggedMissingParentPid = new ConcurrentDictionary<int, byte>();
        private static readonly bool _directParquetEnabled = IsConfiguredEnabled("WINTAP_ENABLE_DIRECT_PARQUET");
        private static readonly bool _skipProcessResolve = IsConfiguredEnabled("WINTAP_SKIP_PROCESS_RESOLVE");
        private static readonly bool _skipParentProcessResolve = IsConfiguredEnabled("WINTAP_SKIP_PARENT_PROCESS_RESOLVE");
        private static readonly bool _skipProcessRegister = IsConfiguredEnabled("WINTAP_SKIP_PROCESS_REGISTER");
        private static readonly bool _skipEsperSend = IsConfiguredEnabled("WINTAP_SKIP_ESPER_SEND");
        private static long _fileProcessCacheHits;
        private static long _fileProcessCacheMisses;

        private static readonly Lazy<string> UnknownPidHash = new Lazy<string>(() => new ProcessHash().GenPidHash(-1, 0));

        // Health-check egress hook (shc-02). The override is a test seam
        // (InternalsVisibleTo "Wintap.Tests"); production always resolves to
        // SensorHealthMonitor.Default.
        internal static SensorHealthMonitor HealthMonitorOverride;

        internal static void InspectForHealth(WintapMessage message)
        {
            (HealthMonitorOverride ?? SensorHealthMonitor.Default).Inspect(message);
        }


        private static Stopwatch stopWatch;

        // Esper configuration and runtime
        private static Configuration esperConfig;
        private static EPRuntime esperRuntime;
        private static readonly object compileDeployLock = new object();

        // Public statistics properties
        public static long EventsPerSecond => eventsPerSecond;
        public static long MaxEventsPerSecond => maxEventsPerSecond;
        public static DateTime MaxEventTime => maxEventTime;
        public static long TotalEvents => totalEvents;
        public static string Runtime => stopWatch.Elapsed.ToString(@"dd\.hh\:mm\:ss");
        public static int DroppedEventCount => droppedEventCount;

        internal struct EventSendTiming
        {
            internal long ProcessResolveTicks;
            internal long HealthTicks;
            internal long EsperTicks;
        }

        internal static void AddDroppedEvents(int count)
        {
            if (count <= 0)
            {
                return;
            }

            Interlocked.Add(ref droppedEventCount, count);
        }

        /// <summary>
        /// Esper configuration accessor
        /// </summary>
        public static Configuration EsperConfig
        {
            get
            {
                if (esperConfig == null)
                {
                    InitializeEsperConfiguration();
                }
                return esperConfig;
            }
            set => esperConfig = value;
        }

        /// <summary>
        /// Esper runtime accessor
        /// </summary>
        public static EPRuntime EsperRuntime
        {
            get
            {
                if (esperRuntime == null)
                {
                    InitializeEsperRuntime();
                }
                return esperRuntime;
            }
        }

        private EventChannel()
        {
            //  tracks total runtime
            stopWatch = new Stopwatch();
            stopWatch.Start();

            // Start statistics worker
            BackgroundWorker statsWorker = new BackgroundWorker();
            statsWorker.DoWork += StatsWorker_DoWork;
            statsWorker.RunWorkerAsync();

            // Reset workbench state
            ResetWorkbench();
        }

        internal static void Initialize(IProcessResolver processResolver)
        {
            _processResolver = processResolver;
            WintapLogger.Log.Append("EventChannel initialized with process resolver", LogLevel.Info);
        }

       


        // **************************************************************************
        // ***  ESPER INFRASTRUCTURE LIFECYCLE
        // **************************************************************************
        /// <summary>
        /// Initialize Esper configuration
        /// </summary>
        private static void InitializeEsperConfiguration()
        {
            try
            {
                esperConfig = new Configuration();
                esperConfig.Common.EventMeta.ClassPropertyResolutionStyle = PropertyResolutionStyle.CASE_INSENSITIVE;

                // Add WintapMessage as an event type
                esperConfig.Common.AddEventType(typeof(WintapMessage));

                // Configuration settings from Esper 8 upgrade guide
                esperConfig.Compiler.ByteCode.IsAllowSubscriber = true;
                esperConfig.Compiler.ByteCode.SetAccessModifiersPublic();
                esperConfig.Compiler.ByteCode.BusModifierEventType = com.espertech.esper.common.client.util.EventTypeBusModifier.BUS;

                WintapLogger.Log.Append("Esper configuration initialized", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error initializing Esper configuration: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Initialize Esper runtime
        /// </summary>
        private static void InitializeEsperRuntime()
        {
            try
            {
                if (esperConfig == null)
                {
                    InitializeEsperConfiguration();
                }

                esperRuntime = EPRuntimeProvider.GetDefaultRuntime(esperConfig);
                WintapLogger.Log.Append("Esper runtime initialized", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error initializing Esper runtime: {ex.Message}", LogLevel.Error);
                throw;
            }
        }


        // **************************************************************************
        // ***  EVENT ROUTING & ENRICHMENT
        // **************************************************************************

        /// <summary>
        /// Sends a telemetry event to the Esper event processing engine after enriching it with process lineage information.
        /// This method filters out Wintap's own events, resolves process ownership details, and tracks event throughput metrics.
        /// </summary>
        /// <param name="streamedEvent">The telemetry event to send. Events from Wintap's own process (PID matching StateManager.WintapPID) are silently discarded.</param>
        /// <remarks>
        /// Event Processing:
        /// - For non-Process events: Resolves and attaches the owning process's PidHash and ProcessName
        /// - For Process events: Resolves and attaches the parent process's PidHash and ParentProcessName
        /// - All events are tagged with the current AgentId
        /// 
        /// Performance Tracking:
        /// - Maintains running counts of total events processed
        /// - Calculates events per second and tracks peak throughput
        /// 
        /// </remarks>
        public static void Send(WintapMessage streamedEvent)
        {
            SendCore(streamedEvent, false, out _);
        }

        internal static void SendMeasured(WintapMessage streamedEvent, out EventSendTiming timing)
        {
            SendCore(streamedEvent, true, out timing);
        }

        private static void SendCore(WintapMessage streamedEvent, bool measure, out EventSendTiming timing)
        {
            timing = default;
            // Update events per second calculation
            totalEvents++;
            var now = DateTime.Now;
            if (now.Second != lastTotalEvents)
            {
                eventsPerSecond = totalEvents - lastTotalEvents;
                lastTotalEvents = totalEvents;
                if (eventsPerSecond > maxEventsPerSecond)
                {
                    maxEventsPerSecond = eventsPerSecond;
                    maxEventTime = now;
                }
            }

            // Send to Esper (filter out Wintap's own events)
            try
            {
                // Skip Wintap's own events
                if (streamedEvent.PID == StateManager.WintapPID)
                {
                    return;
                }

                // Tag with AgentId
                streamedEvent.AgentId = StateManager.AgentId.ToString();

                if (_directParquetEnabled)
                {
                    long directHealthStarted = measure ? Stopwatch.GetTimestamp() : 0;
                    InspectForHealth(streamedEvent);
                    if (measure)
                    {
                        timing.HealthTicks = Stopwatch.GetTimestamp() - directHealthStarted;
                    }
                    DirectParquetSink.Save(streamedEvent);
                    return;
                }
                long processResolveStarted = measure ? Stopwatch.GetTimestamp() : 0;
                DateTime eventTimeUtc = DateTime.FromFileTimeUtc(streamedEvent.EventTime);

                // Resolve process information using platform-specific resolver
                if (_processResolver != null && !_skipProcessResolve)
                {
                    if (streamedEvent.MessageType != WintapMessage.MessageTypeEnum.Process)
                    {
                        // For non-Process events: resolve the owning process
                        ProcessRecord ownerProcess = null;
                        bool usedCurrentProcessCache = false;
                        bool canUsePrepopulatedIdentity = streamedEvent.MessageType == WintapMessage.MessageTypeEnum.File ||
                            streamedEvent.MessageType == WintapMessage.MessageTypeEnum.SELinuxAvc ||
                            streamedEvent.MessageType == WintapMessage.MessageTypeEnum.SELinuxTransition ||
                            streamedEvent.MessageType == WintapMessage.MessageTypeEnum.SELinuxInteraction;
                        bool hasPrepopulatedIdentity = canUsePrepopulatedIdentity &&
                            !string.IsNullOrWhiteSpace(streamedEvent.PidHash) &&
                            !string.IsNullOrWhiteSpace(streamedEvent.ProcessName);

                        if (streamedEvent.MessageType == WintapMessage.MessageTypeEnum.File && !hasPrepopulatedIdentity)
                        {
                            usedCurrentProcessCache = _processResolver.TryResolveCurrentProcessAtTime(streamedEvent.PID, eventTimeUtc, out ownerProcess);
                            if (usedCurrentProcessCache)
                            {
                                Interlocked.Increment(ref _fileProcessCacheHits);
                            }
                            else
                            {
                                Interlocked.Increment(ref _fileProcessCacheMisses);
                            }
                        }

                        if (hasPrepopulatedIdentity)
                        {
                            ownerProcess = new ProcessRecord
                            {
                                PidHash = streamedEvent.PidHash,
                                ProcessId = streamedEvent.PID,
                                ProcessName = streamedEvent.ProcessName,
                                CreateTime = eventTimeUtc
                            };
                        }
                        else if (!usedCurrentProcessCache)
                        {
                            ownerProcess = streamedEvent.MessageType == WintapMessage.MessageTypeEnum.File
                                ? _processResolver.ResolveProcessIdentityAtTime(streamedEvent.PID, eventTimeUtc)
                                : _processResolver.ResolveProcessAtTime(streamedEvent.PID, eventTimeUtc);
                        }

                        if (ownerProcess != null)
                        {
                            streamedEvent.PidHash = ownerProcess.PidHash;
                            streamedEvent.ProcessName = ownerProcess.ProcessName;
                        }
                        else
                        {
                            // Generate a best-effort PidHash so events still have an identifier.
                            // Prefer resolver lookup; fall back to a local hash when resolver has no record.
                            var fallbackPidHash = _processResolver.GetPidHash(streamedEvent.PID, eventTimeUtc);
                            streamedEvent.PidHash = fallbackPidHash ?? new ProcessHash().GenPidHash(streamedEvent.PID, streamedEvent.EventTime);
                            streamedEvent.ProcessName = "Unknown";

                            // Log only once per PID to avoid log floods.
                            if (_loggedMissingOwnerPid.TryAdd(streamedEvent.PID, 0))
                            {
                                var level = fallbackPidHash == null ? LogLevel.Warn : LogLevel.Debug;
                                WintapLogger.Log.Append($"Could not resolve owner process for PID {streamedEvent.PID} ({streamedEvent.MessageType})", level);
                            }
                        }
                    }
                    else if (!_skipParentProcessResolve)
                    {
                        // For Process events: resolve the parent process
                        WintapLogger.Log.Append($"Attempting to resolve parent process for {streamedEvent.PID}", LogLevel.Debug);
                        try
                        {
                            if (streamedEvent.Process != null && streamedEvent.Process.ParentPID > 0)
                            {
                                if (!string.IsNullOrWhiteSpace(streamedEvent.Process.ParentPidHash))
                                {
                                    WintapLogger.Log.Append($"Process {streamedEvent.PID} already has parent process context", LogLevel.Debug);
                                }
                                else if (streamedEvent.Process.ParentPID == streamedEvent.PID)
                                {
                                    WintapLogger.Log.Append(
                                        $"Process {streamedEvent.PID} is self-parenting, using own PidHash as ParentPidHash",
                                        LogLevel.Info);

                                    streamedEvent.Process.ParentPidHash = streamedEvent.PidHash;
                                    streamedEvent.Process.ParentProcessName = streamedEvent.ProcessName;
                                }
                                else
                                {
                                    // Normal parent resolution
                                    WintapLogger.Log.Append($"Attempting to retrieve parent process from process resolver pid: {streamedEvent.PID}, parentPid: {streamedEvent.Process.ParentPID}", LogLevel.Debug);
                                    ProcessRecord parentProcess = EventChannel.GetProcessHistory(
                                        streamedEvent.Process.ParentPID,
                                        eventTimeUtc);

                                    if (parentProcess != null)
                                    {
                                        streamedEvent.Process.ParentPidHash = parentProcess.PidHash;
                                        streamedEvent.Process.ParentProcessName = parentProcess.ProcessName;
                                    }
                                     else
                                      {
                                         if (_loggedMissingParentPid.TryAdd(streamedEvent.Process.ParentPID, 0))
                                         {
                                             // Best-effort: if the parent wasn't registered (ordering/rundown gaps),
                                             // try to derive a stable ParentPidHash from /proc start time on Linux.
                                             // This keeps parent lineage usable even when we missed the parent's
                                             // process event.
                                             string? fallbackParentPidHash = null;
                                             try
                                             {
                                                 fallbackParentPidHash = _processResolver?.GetPidHash(
                                                     streamedEvent.Process.ParentPID,
                                                     eventTimeUtc);
                                              }
                                              catch { }

                                              var level = string.IsNullOrEmpty(fallbackParentPidHash) ? LogLevel.Warn : LogLevel.Debug;
                                              WintapLogger.Log.Append(
                                                  $"Best-effort parent attribution unavailable (childPid={streamedEvent.PID}, parentPid={streamedEvent.Process.ParentPID}); parent may have exited before observation or be outside snapshot/boot coverage; using unknown-parent sentinel (logged once per parent PID)",
                                                  level);

                                             if (!string.IsNullOrEmpty(fallbackParentPidHash))
                                             {
                                                 streamedEvent.Process.ParentPidHash = fallbackParentPidHash;
                                                 streamedEvent.Process.ParentProcessName = "Unknown";
                                             }
                                         }

                                         // Stable sentinel for unknown parent attribution.
                                         if (string.IsNullOrWhiteSpace(streamedEvent.Process.ParentPidHash))
                                         {
                                             streamedEvent.Process.ParentPidHash = UnknownPidHash.Value;
                                             streamedEvent.Process.ParentProcessName = "Unknown";
                                         }
                                      }
                                 }
                             }
                         }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append($"Could not resolve parent process for pid {streamedEvent.PID}", LogLevel.Warn);
                        }
                    }
                }
                else if (_processResolver == null)
                {
                    // No process resolver available (shouldn't happen, but handle gracefully)
                    WintapLogger.Log.Append(
                        "ProcessResolver not initialized in EventChannel",
                        LogLevel.Warn);
                }

                // Send to backing store
                if (streamedEvent.MessageType == WintapMessage.MessageTypeEnum.Process)
                {
                    if (!_skipProcessRegister)
                    {
                        _processResolver.RegisterProcess(streamedEvent);
                    }
                }

                if (measure)
                {
                    timing.ProcessResolveTicks = Stopwatch.GetTimestamp() - processResolveStarted;
                }

                long healthStarted = measure ? Stopwatch.GetTimestamp() : 0;
                InspectForHealth(streamedEvent);
                if (measure)
                {
                    timing.HealthTicks = Stopwatch.GetTimestamp() - healthStarted;
                }

                if (_skipEsperSend)
                {
                    return;
                }

                // Send to Esper
                long esperStarted = measure ? Stopwatch.GetTimestamp() : 0;
                EsperRuntime.EventService.SendEventBean(streamedEvent, "WintapMessage");
                if (measure)
                {
                    timing.EsperTicks = Stopwatch.GetTimestamp() - esperStarted;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append(
                    $"Error sending event for {streamedEvent.MessageType}: {ex.ToString()}",
                    LogLevel.Error);
            }
        }

        private static bool IsEnvEnabled(string name)
        {
            var val = ConfigManager.GetValue<string>(name);
            return !string.IsNullOrEmpty(val) && (string.Equals(val, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(val, "1", StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsConfiguredEnabled(string name)
        {
            return IsEnvEnabled(name);
        }

        internal static void TakeFileProcessCacheCounters(out long hits, out long misses)
        {
            hits = Interlocked.Exchange(ref _fileProcessCacheHits, 0);
            misses = Interlocked.Exchange(ref _fileProcessCacheMisses, 0);
        }

        internal static void TakeHistoricalProcessCacheCounters(out long hits, out long misses, out long evictions, out int entries)
        {
            if (_processResolver != null)
            {
                _processResolver.TakeHistoricalIdentityCacheCounters(out hits, out misses, out evictions, out entries);
                return;
            }

            hits = 0;
            misses = 0;
            evictions = 0;
            entries = 0;
        }

        internal static bool TryPopulateCurrentProcessIdentity(WintapMessage streamedEvent)
        {
            if (streamedEvent == null || _processResolver == null || _skipProcessResolve)
            {
                return false;
            }

            if (streamedEvent.MessageType != WintapMessage.MessageTypeEnum.File)
            {
                return false;
            }

            if (_processResolver.TryResolveCurrentProcessAtTime(
                streamedEvent.PID,
                DateTime.FromFileTimeUtc(streamedEvent.EventTime),
                out ProcessRecord ownerProcess) &&
                ownerProcess != null)
            {
                streamedEvent.PidHash = ownerProcess.PidHash;
                streamedEvent.ProcessName = ownerProcess.ProcessName;
                Interlocked.Increment(ref _fileProcessCacheHits);
                return true;
            }

            return false;
        }

        // **************************************************************************
        // ***  HISTORICAL EVENT ACCESS
        // **************************************************************************
        public static List<ProcessRecord> GetProcessHistory()
        {
            return _processResolver.GetAllProcesses();
        }

        public static ProcessRecord GetProcessHistory(int _pid,  DateTime _eventTime)
        {
            return _processResolver.ResolveProcessAtTime(_pid, _eventTime.ToUniversalTime());
        }

        public static void ClearProcessDB()
        {
            _processResolver.ClearDB();
        }

        public static bool IsProcessRowOpen(string pidHash)
        {
            return _processResolver?.IsProcessRowOpen(pidHash) ?? false;
        }

        public static void UpdateCollectionHeartbeat()
        {
            _processResolver?.UpdateCollectionHeartbeat();
        }

        public static bool TryReadCollectionHeartbeat(out DateTime lastWriteUtc, out string sessionId)
        {
            if (_processResolver != null)
            {
                return _processResolver.TryReadCollectionHeartbeat(out lastWriteUtc, out sessionId);
            }

            lastWriteUtc = default;
            sessionId = string.Empty;
            return false;
        }

        public static int ReconcileStartupProcesses(IReadOnlyCollection<string> livePidHashes, DateTime gapEndUtc)
        {
            return _processResolver?.ReconcileStartupOpenRows(livePidHashes, gapEndUtc) ?? 0;
        }

        public static bool TryRepairParentLinkage(string pidHash, int parentPid, string parentPidHash)
        {
            return _processResolver?.TryRepairParentLinkage(pidHash, parentPid, parentPidHash) ?? false;
        }

        public static void WriteCollectionGap(DateTime gapStartUtc, DateTime gapEndUtc, string priorSessionId, string reason)
        {
            _processResolver?.WriteCollectionGap(gapStartUtc, gapEndUtc, priorSessionId, reason);
        }

        // **************************************************************************
        // ***  QUERY COMPILATION & DEPLOYMENT
        // **************************************************************************

        /// <summary>
        /// Compile and deploy EPL statements
        /// </summary>
        public static EPDeployment CompileDeploy(string epl, string name)
        {
            lock (compileDeployLock)
            {
                try
                {
                    // Get the Esper configuration
                    Configuration configuration = EsperConfig;

                    // Always convert string-based queries to enum-based queries
                    // This ensures consistent behavior regardless of where the query comes from
                    string adaptedEpl = FormatQueryForCompile(epl);

                    if (name != "ETWBootTrace")
                    {
                        adaptedEpl = $"@name('WB-{name}') {adaptedEpl}";
                    }

                    // Log the original and adapted queries for debugging if needed
                    if (epl != adaptedEpl)
                    {
                        WintapLogger.Log.Append($"Original EPL: {epl}", LogLevel.Debug);
                        WintapLogger.Log.Append($"Adapted EPL: {adaptedEpl}", LogLevel.Debug);
                    }

                    // Build compiler arguments
                    CompilerArguments args = new CompilerArguments(configuration);

                    // Make the existing EPL objects available to the compiler
                    args.GetPath().Add(EsperRuntime.RuntimePath);

                    // Parse the module
                    var module = EPCompilerProvider.Compiler.ParseModule(adaptedEpl);

                    // Validate syntax only (throws EPCompileException on error)
                    EPCompilerProvider.Compiler.SyntaxValidate(module, args);

                    // Compile the EPL
                    EPCompiled compiled = EPCompilerProvider.Compiler.Compile(adaptedEpl, args);

                    // Deploy and return the deployment
                    return EsperRuntime.DeploymentService.Deploy(compiled);
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Problem compiling/deploying EPL '{epl}': {ex.Message}", LogLevel.Warn);
                    throw;
                }
            }
        }

        // **************************************************************************
        // ***  WORKBENCH STATE MANAGEMENT
        // **************************************************************************

        /// <summary>
        /// Manage workbench queries
        /// </summary>
        internal static EsperQuery ManageWorkbenchQuery(EsperQuery q)
        {
            try
            {
                var queries = GetWorkbenchState();
                EsperQuery targetQuery = null;

                if (queries.ContainsKey(q.Name))
                {
                    targetQuery = queries[q.Name];
                    targetQuery.State = q.State;
                    targetQuery.Query = q.Query;

                    if (q.State == EsperQuery.EsperState.ACTIVE)
                    {
                        // Set all other queries to STOPPED
                        foreach (var eq in queries.Values)
                        {
                            if (eq.Name != q.Name)
                            {
                                eq.State = EsperQuery.EsperState.STOPPED;
                            }
                        }

                        // Create new deployment
                        targetQuery = CreateWorkbenchQuery(q);
                        queries[q.Name] = targetQuery;
                    }
                    else if (q.State == EsperQuery.EsperState.DELETED)
                    {
                        try
                        {
                            EsperRuntime.DeploymentService.Undeploy(targetQuery.Id);
                        }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append($"Error undeploying query {targetQuery.Id}: {ex.Message}", LogLevel.Debug);
                        }

                        bool removeOK = queries.Remove(q.Name);
                        WintapLogger.Log.Append($"Query {targetQuery.Id} removed: {removeOK}", LogLevel.Info);
                    }
                }
                else
                {
                    if (q.State == EsperQuery.EsperState.ACTIVE)
                    {
                        // Create a new query
                        targetQuery = CreateWorkbenchQuery(q);

                        // Set all other queries to STOPPED
                        foreach (var eq in queries.Values)
                        {
                            eq.State = EsperQuery.EsperState.STOPPED;
                        }

                        queries.Add(targetQuery.Name, targetQuery);
                    }
                }

                SetWorkbenchState(queries);
                return targetQuery;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error managing workbench query: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Create a new workbench query
        /// </summary>
        private static EsperQuery CreateWorkbenchQuery(EsperQuery q)
        {
            try
            {
                // Store the original query string for display purposes
                string originalQuery = q.Query;

                // Deploy with adapter-processed query
                EPDeployment deployment = CompileDeploy(q.Query, q.Name);
                q.Id = deployment.DeploymentId;

                // Ensure we keep the original string-based query for display to users
                q.Query = originalQuery;

                return q;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error creating workbench query: {ex.Message}", LogLevel.Error);
                throw;
            }
        }

        /// <summary>
        /// Get all saved workbench queries
        /// </summary>
        internal static Dictionary<string, EsperQuery> GetWorkbenchState()
        {
            try
            {
                var queries = new Dictionary<string, EsperQuery>();
                string stateFile = Path.Combine(Env.FileDataRoot, "workbench-state.json");

                if (File.Exists(stateFile))
                {
                    string json = File.ReadAllText(stateFile);
                    var queryList = JsonConvert.DeserializeObject<List<EsperQuery>>(json);

                    if (queryList != null)
                    {
                        foreach (var query in queryList)
                        {
                            queries[query.Name] = query;
                        }
                    }
                }

                return queries;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error getting workbench state: {ex.Message}", LogLevel.Error);
                return new Dictionary<string, EsperQuery>();
            }
        }

        /// <summary>
        /// Save workbench state
        /// </summary>
        private static void SetWorkbenchState(Dictionary<string, EsperQuery> queries)
        {
            try
            {
                string stateFile = Path.Combine(Env.FileDataRoot, "workbench-state.json");
                var queryList = queries.Values.ToList();
                string json = JsonConvert.SerializeObject(queryList, Formatting.Indented);

                File.WriteAllText(stateFile, json);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error setting workbench state: {ex.Message}", LogLevel.Error);
            }
        }

        /// <summary>
        /// Reset workbench state - ensure all queries are stopped
        /// </summary>
        private static void ResetWorkbench()
        {
            try
            {
                var queries = GetWorkbenchState();
                foreach (var query in queries.Values)
                {
                    query.State = EsperQuery.EsperState.STOPPED;
                }
                SetWorkbenchState(queries);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error resetting workbench: {ex.Message}", LogLevel.Error);
            }
        }

        internal static void setWorkbenchState(Dictionary<string, EsperQuery> esperQueries)
        {
            string jsonString = JsonConvert.SerializeObject(esperQueries.Values, Formatting.Indented);
            string filePath = Path.Combine(Environment.CurrentDirectory, "workbenchstate.json");
            File.WriteAllText(filePath, jsonString);
        }

        internal static Dictionary<string, EsperQuery> getWorkbenchState()
        {
            FileInfo stateInfo = new FileInfo(Path.Combine(Environment.CurrentDirectory, "workbenchstate.json"));
            Dictionary<string, EsperQuery> queries = new Dictionary<string, EsperQuery>();
            if (stateInfo.Exists)
            {
                string readJsonString = File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "workbenchstate.json"));
                List<EsperQuery> esperQueries = JsonConvert.DeserializeObject<List<EsperQuery>>(readJsonString);
                foreach (EsperQuery eq in esperQueries)
                {
                    queries.Add(eq.Name, eq);
                }
            }
            return queries;
        }


        /// <summary>
        /// Format query for compilation - handles enum conversion if needed
        /// </summary>
        private static string FormatQueryForCompile(string epl)
        {
            try
            {
                // Try to use EnumFormatter if available
                string formattedEpl = EnumFormatter.FormatQueryForCompile(epl);
                 if (string.Equals(ConfigManager.GetValue<string>("WINTAP_DISABLE_ESPER_ENUM_CAST"), "true", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(ConfigManager.GetValue<string>("WINTAP_DISABLE_ESPER_ENUM_CAST"), "1", StringComparison.OrdinalIgnoreCase))
                {
                    formattedEpl = FormatEnumCastsAsEnumLiterals(formattedEpl);
                }

                return formattedEpl;
            }
            catch (Exception ex)
            {
                // If EnumFormatter is not available, log and return original
                WintapLogger.Log.Append($"EnumFormatter not available, using original EPL: {ex.Message}", LogLevel.Debug);
                return epl;
            }
        }

        private static string FormatEnumCastsAsEnumLiterals(string epl)
        {
            string propertyPattern = @"(?:CAST\s*\(\s*(MessageType|messageType|ActivityType|activityType)\s*,\s*string\s*\)|(MessageType|messageType|ActivityType|activityType))";

            epl = Regex.Replace(epl, propertyPattern + @"\s*(=|<>|!=)\s*(['""“”])([^'""“”]+)\2", match =>
            {
                string property = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
                string op = match.Groups[3].Value;
                string value = match.Groups[5].Value;
                return $"{property} {op} {GetEnumLiteral(property, value)}";
            }, RegexOptions.IgnoreCase);

            epl = Regex.Replace(epl, propertyPattern + @"\s+(NOT\s+IN|IN)\s*\(([^)]*)\)", match =>
            {
                string property = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
                string op = match.Groups[3].Value;
                string[] values = Regex.Matches(match.Groups[4].Value, @"['""“”]([^'""“”]+)['""“”]")
                    .Cast<Match>()
                    .Select(valueMatch => GetEnumLiteral(property, valueMatch.Groups[1].Value))
                    .ToArray();

                return $"{property} {op} ({string.Join(",", values)})";
            }, RegexOptions.IgnoreCase);

            return Regex.Replace(epl, @"CAST\s*\(\s*(MessageType|messageType|ActivityType|activityType)\s*,\s*string\s*\)", "$1", RegexOptions.IgnoreCase);
        }

        private static string GetEnumLiteral(string property, string value)
        {
            if (property.Equals("MessageType", StringComparison.OrdinalIgnoreCase))
            {
                return $"gov.llnl.wintap.collect.models.WintapMessage$MessageTypeEnum.{value}";
            }

            return $"gov.llnl.wintap.collect.models.WintapMessage$ActivityTypeEnum.{value}";
        }

        private static void StatsWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            while (true)
            {
                System.Threading.Thread.Sleep(1000);

                // Calculate events per second
                eventsPerSecond = totalEvents - lastTotalEvents;
                lastTotalEvents = totalEvents;

                if (eventsPerSecond > maxEventsPerSecond)
                {
                    maxEventsPerSecond = eventsPerSecond;
                    maxEventTime = DateTime.Now;
                }
            }
        }
    }

    public class EsperQuery
    {
        //public enum EsperState { ACTIVE, STARTED, STOPPED, CREATED, DELETED }
        public enum EsperState { ACTIVE, STOPPED, DELETED }
        public string Name { get; set; }
        public string Id { get; set; }
        public string Query { get; set; }
        public EsperState State { get; set; }
    }
}
