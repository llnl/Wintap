/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using com.espertech.esper.client;
using com.espertech.esper.common.client;
using com.espertech.esper.runtime.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.etl.model;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.shared;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Timers;
using static gov.llnl.wintap.core.etl.shared.Utilities;
using System.Runtime.InteropServices;
using System.Threading;


namespace gov.llnl.wintap.core.etl.extract
{
    internal abstract class Serializer
    {
        // Ensure the shared Esper context is deployed once per process.
        private static int _esperContextRegistered = 0;

        private List<string> esperQueries = new List<string>();  // the query epl files used by this sensor
        private int maxEventsPerSec = 25000;
        private System.Timers.Timer backoffTimer;
        private string esperNameSpacePrefix = "gov.llnl.wintap.core.etl.esper.";
        private ConcurrentQueue<ExpandoObject> sensorData;
        private long sensorDataDepth;

        // Backlog protection: bound in-memory event queue per serializer to avoid OOM
        // when downstream aggregation/serialization can’t keep up.
        private int maxInMemoryEvents;
        private long droppedDueToBacklog;
        private DateTime lastBacklogLogUtc = DateTime.MinValue;
        private DropPolicy backlogDropPolicy = DropPolicy.DropNewest;

        private enum DropPolicy
        {
            DropNewest,
            DropOldest
        }

        private static DropPolicy ParseDropPolicy(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return DropPolicy.DropNewest;
            }

            if (string.Equals(value, "oldest", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "drop_oldest", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "dropoldest", StringComparison.OrdinalIgnoreCase))
            {
                return DropPolicy.DropOldest;
            }

            return DropPolicy.DropNewest;
        }
        private ParquetWriter parquetWriter;
        private bool fileBusy;  // prevents file IO contention when snapshot is being rotated.
        private System.Timers.Timer flushToDiskTimer;
        private int flushInProgress;
        private long skippedOverlappingFlushes;
        private int fileFlushHighWaterEvents;
        private int highWaterFlushRequested;

        protected Serializer(string[] queries)
        {
            initSensor();
            foreach (string query in queries)
            {
                registerQuery(query, Guid.NewGuid().ToString());
                esperQueries.Add(query);
            }
            ;
        }

        protected Serializer(string query)
        {
            initSensor();
            registerQuery(query, Guid.NewGuid().ToString());
            esperQueries.Add(query);
        }

        #region internal

        internal enum MessageTypeEnum { Process, FocusChange }

        /// <summary>
        /// provides realtime feed of sensor data
        /// </summary>
        internal event EventHandler<SensorDataEventArgs> SensorEvent;
        internal class SensorDataEventArgs : EventArgs
        {
            internal SensorData SensorData { get; set; }
        }
        protected virtual void OnNewProcessEvent(SensorDataEventArgs e)
        {
            EventHandler<SensorDataEventArgs> handler = SensorEvent;
            if (handler != null)
            {
                handler(this, e);
            }
        }

        /// <summary>
        /// Recovery event for when Esper is overrun by event volume
        /// </summary>
        internal event EventHandler<EventArgs> Overrun;
        protected virtual void OnOverrunEvent(EventArgs e)
        {
            EventHandler<EventArgs> handler = Overrun;
            if (handler != null)
            {
                handler(this, e);
            }
        }

        protected virtual void HandleSensorEvent(EventBean sensorEvent)
        {
            // handled in subclasses
        }

        /// <summary>
        /// Is the sensor currently accepting new events.  For 'Production' sensors, this is disabled/reenabled dynamically, per-sensor based upon per-second event volume.
        /// </summary>
        internal bool IsEnabled { get; set; }
        internal string SensorName { get; set; }


        /// <summary>
        /// Receives the original WintapMessage from Subscribe
        /// TODO:  do we still need this?
        /// </summary>
        /// <param name="wintapMessage"></param>
        internal void Listen(WintapMessage wintapMessage)
        {
            try
            {
                gov.llnl.wintap.core.infrastructure.EventChannel.EsperRuntime.EventService.SendEventBean(wintapMessage, "WintapMessage");
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Problem sending WintapMessage event from: " + this.GetType().Name + ":" + ex.Message, LogLevel.Info);
            }
        }

        /// <summary>
        /// Saves to memory for downstream processing
        /// </summary>
        /// <param name="obj"></param>
        /// <exception cref="Exception"></exception>
        internal void Save(ExpandoObject obj)
        {
            dynamic dobj = (dynamic)obj;
            if (!String.IsNullOrWhiteSpace(dobj.PidHash))
            {
                if (maxInMemoryEvents > 0)
                {
                    while (Interlocked.Read(ref sensorDataDepth) >= maxInMemoryEvents && backlogDropPolicy == DropPolicy.DropOldest)
                    {
                        // Make room by evicting the oldest queued item.
                        if (sensorData.TryDequeue(out _))
                        {
                            Interlocked.Decrement(ref sensorDataDepth);
                            Interlocked.Increment(ref droppedDueToBacklog);
                            gov.llnl.wintap.core.infrastructure.EventChannel.AddDroppedEvents(1);
                        }
                        else
                        {
                            break;
                        }
                    }

                    if (Interlocked.Read(ref sensorDataDepth) >= maxInMemoryEvents)
                    {
                        // Drop the newest event.
                        Interlocked.Increment(ref droppedDueToBacklog);
                        gov.llnl.wintap.core.infrastructure.EventChannel.AddDroppedEvents(1);

                        var now = DateTime.UtcNow;
                        if ((now - lastBacklogLogUtc).TotalSeconds >= 5)
                        {
                            lastBacklogLogUtc = now;
                            WintapLogger.Log.Append($"{SensorName}: in-memory backlog limit reached (max={maxInMemoryEvents}, policy={backlogDropPolicy}). Dropping events. dropped={Interlocked.Read(ref droppedDueToBacklog)} depth={Interlocked.Read(ref sensorDataDepth)}", LogLevel.Warn);
                        }

                        return;
                    }
                }

                this.sensorData.Enqueue(obj);
                long queueDepth = Interlocked.Increment(ref sensorDataDepth);
                RequestHighWaterFlush(queueDepth);
            }
            else
            {
                throw new Exception("NULL_PIDHASH");
            }
        }


        internal void EsperMon_Overrun(object sender, EventArgs e)
        {
            try
            {
                WintapLogger.Log.Append("Handing esper overrun condition in " + this.GetType().Name + "  suspending ETL data stream for: " + backoffTimer.Interval + "ms", LogLevel.Info);
                backoffTimer.Start();
                this.Stop();
                sendThrottleEvent("SUSPEND");
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Problem attempting to suspend esper processing in  " + this.GetType().Name + ": " + ex.Message, LogLevel.Info);
            }
        }

        static internal long GetUnixNowTime()
        {
            return ((System.DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
        }

        static internal long GetUnixEventTime(long wintapTime)
        {
            return ((System.DateTimeOffset)DateTime.FromFileTimeUtc(wintapTime)).ToUnixTimeSeconds();
        }

        /// <summary>
        /// Re-registers the queries defined in this class
        /// </summary>
        internal void Start()
        {
            regContext();
            foreach (string query in esperQueries)
            {
                registerQuery(query, Guid.NewGuid().ToString());
            }

            IsEnabled = true;
        }

        internal void Stop()
        {
            IsEnabled = false;
            // do we still need to do this?  sensors only stop when wintap stops now (no throttling)
            //esper.EPAdministrator.DestroyAllStatements();
        }
        #endregion

        #region private

        private void initSensor()
        {
            IsEnabled = false;
            this.SensorName = this.GetType().Name.ToLower();

            parquetWriter = new ParquetWriter();
            sensorData = new ConcurrentQueue<ExpandoObject>();
            sensorDataDepth = 0;

            // Optional per-serializer queue bound to prevent unbounded memory growth.
            // Global: WINTAP_ETL_MAX_QUEUE_EVENTS
            // Per serializer: WINTAP_ETL_MAX_QUEUE_EVENTS_<SERIALIZERNAME>
            // (e.g., WINTAP_ETL_MAX_QUEUE_EVENTS_TCPCONNECTIONSERIALIZER)
            maxInMemoryEvents = 0;
            if (int.TryParse(gov.llnl.wintap.core.shared.ConfigManager.GetValue<string>("WINTAP_ETL_MAX_QUEUE_EVENTS"), out int globalMax) && globalMax > 0)
            {
                maxInMemoryEvents = globalMax;
            }

            string perSensorName = $"WINTAP_ETL_MAX_QUEUE_EVENTS_{this.GetType().Name.ToUpperInvariant()}";
            if (int.TryParse(gov.llnl.wintap.core.shared.ConfigManager.GetValue<string>(perSensorName), out int perMax) && perMax > 0)
            {
                maxInMemoryEvents = perMax;
            }

            // Backlog drop policy (default drop newest).
            // Global: WINTAP_ETL_QUEUE_DROP_POLICY ("newest"|"oldest")
            // Per serializer: WINTAP_ETL_QUEUE_DROP_POLICY_<SERIALIZERNAME>
            backlogDropPolicy = ParseDropPolicy(gov.llnl.wintap.core.shared.ConfigManager.GetValue<string>("WINTAP_ETL_QUEUE_DROP_POLICY"));
            string perPolicyName = $"WINTAP_ETL_QUEUE_DROP_POLICY_{this.GetType().Name.ToUpperInvariant()}";
            backlogDropPolicy = ParseDropPolicy(gov.llnl.wintap.core.shared.ConfigManager.GetValue<string>(perPolicyName)) == DropPolicy.DropOldest
                ? DropPolicy.DropOldest
                : backlogDropPolicy;

            ETLConfig etlConfig = Utilities.GetETLConfig();
            int flushIntervalSeconds = SerializerSchedule.ResolveIntervalSeconds(
                SensorName,
                etlConfig.SerializationIntervalSec,
                etlConfig.FileSerializationIntervalSec ?? 5);
            fileFlushHighWaterEvents = etlConfig.FileSerializationHighWaterEvents ?? 5000;
            flushToDiskTimer = new System.Timers.Timer();
            flushToDiskTimer.Interval = flushIntervalSeconds * 1000;
            flushToDiskTimer.AutoReset = true;
            flushToDiskTimer.Elapsed += FlushToDiskTimer_Elapsed;
            flushToDiskTimer.Start();

            WintapLogger.Log.Append($"{SensorName}: serializer flush interval={flushIntervalSeconds}s", LogLevel.Info);
            if (fileFlushHighWaterEvents > 0 && SensorName == "fileserializer")
            {
                WintapLogger.Log.Append($"{SensorName}: serializer high-water flush threshold={fileFlushHighWaterEvents}", LogLevel.Info);
            }

            regContext();

            IsEnabled = true;
            WintapLogger.Log.Append("initialization complete on: " + this.GetType().Name, LogLevel.Debug);
        }


        private void FlushToDiskTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            FlushToDisk("timer");
        }

        private void RequestHighWaterFlush(long queueDepth)
        {
            if (!SerializerSchedule.ShouldRequestHighWaterFlush(SensorName, queueDepth, fileFlushHighWaterEvents) ||
                Interlocked.CompareExchange(ref highWaterFlushRequested, 1, 0) != 0)
            {
                return;
            }

            WintapLogger.Log.Append($"{SensorName}: serializer high-water flush requested depth={queueDepth}", LogLevel.Info);
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    while (Interlocked.Read(ref sensorDataDepth) >= fileFlushHighWaterEvents)
                    {
                        if (FlushToDisk("high_water"))
                        {
                            break;
                        }

                        Thread.Sleep(1);
                    }
                }
                finally
                {
                    Interlocked.Exchange(ref highWaterFlushRequested, 0);
                    RequestHighWaterFlush(Interlocked.Read(ref sensorDataDepth));
                }
            });
        }

        private bool FlushToDisk(string trigger)
        {
            if (this.SensorName == "Host" || this.SensorName == "MacIp")
            {
                return false;
            }

            // A slow disk write must not start a second drain over the same queue.
            if (Interlocked.CompareExchange(ref flushInProgress, 1, 0) != 0)
            {
                Interlocked.Increment(ref skippedOverlappingFlushes);
                return false;
            }

            long started = System.Diagnostics.Stopwatch.GetTimestamp();
            int drained = 0;

            try
            {
                int currentQueueDepth = (int)Math.Min(int.MaxValue, Interlocked.Read(ref sensorDataDepth));
                List<ExpandoObject> tempQueue = new List<ExpandoObject>(currentQueueDepth);

                for (int i = 0; i < currentQueueDepth; i++)
                {
                    try
                    {
                        ExpandoObject msg;
                        if (sensorData.TryDequeue(out msg))
                        {
                            tempQueue.Add(msg);
                            Interlocked.Decrement(ref sensorDataDepth);
                            drained++;
                        }
                        else
                        {
                            WintapLogger.Log.Append($"{this.SensorName}: WARNING - Failed to dequeue message at index {i}", LogLevel.Info);
                        }
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"{this.SensorName}: ERROR getting message from SendQueue at index {i}: {ex.Message}", LogLevel.Info);
                    }
                }

                if (tempQueue.Count > 0)
                {
                    try
                    {
                        if (serialize(tempQueue).Count == 0)
                        {
                            tempQueue.Clear();
                        }
                        else
                        {
                            WintapLogger.Log.Append($"{this.SensorName}: ERROR - temp queue not empty after serialize. Dropped event count: {tempQueue.Count}", LogLevel.Info);
                        }
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append($"{this.SensorName}: ERROR writing event data to disk: {ex.Message}", LogLevel.Info);
                    }
                }
            }
            finally
            {
                long elapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - started) * 1000L / System.Diagnostics.Stopwatch.Frequency;
                long skipped = Interlocked.Exchange(ref skippedOverlappingFlushes, 0);
                if (drained > 0 || skipped > 0)
                {
                    WintapLogger.Log.Append(
                        $"{this.SensorName}: serializer_flush trigger={trigger},drained={drained},remaining={Interlocked.Read(ref sensorDataDepth)},elapsed_ms={elapsedMs},skipped_overlap={skipped},parquet_backlog={parquetWriter.Backlog}",
                        LogLevel.Info);
                }
                Interlocked.Exchange(ref flushInProgress, 0);
            }

            return true;
        }

        private List<ExpandoObject> serialize(List<ExpandoObject> tempQueue)
        {
            ParquetWriter.Batch batch = new ParquetWriter.Batch(this.SensorName);
            try
            {
                // Preserve each message type's arrival order while grouping in one pass.
                var dataByMessageType = new Dictionary<string, ConcurrentQueue<ExpandoObject>>();
                foreach (ExpandoObject message in tempQueue)
                {
                    dynamic typedMessage = message;
                    string messageType = typedMessage.MessageType;
                    if (!dataByMessageType.TryGetValue(messageType, out ConcurrentQueue<ExpandoObject> messages))
                    {
                        messages = new ConcurrentQueue<ExpandoObject>();
                        dataByMessageType[messageType] = messages;
                    }
                    messages.Enqueue(message);
                }

                foreach (KeyValuePair<string, ConcurrentQueue<ExpandoObject>> entry in dataByMessageType)
                {
                    ParquetWriter.Batch.SensorData set = new ParquetWriter.Batch.SensorData(this.SensorName, entry.Key, entry.Value);
                    batch.Add(set);
                }
                tempQueue.Clear();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("ERROR writing parquet: " + ex.Message, LogLevel.Info);
            }
            parquetWriter.Add(batch);
            return tempQueue;
        }

        private void regContext()
        {
            try
            {
                // All serializers share the same Esper context; registering it per serializer
                // causes duplicate-context warnings and extra compile/deploy work.
                if (Interlocked.CompareExchange(ref _esperContextRegistered, 1, 0) != 0)
                {
                    return;
                }

                var esper1 = esperNameSpacePrefix + "esper-context.epl";
                string esperQuery = readQueryFromFile(esper1);
                gov.llnl.wintap.core.infrastructure.EventChannel.CompileDeploy(esperQuery, "esper_context");
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("problem creating esper context query: " + ex.Message, LogLevel.Debug);
            }
        }

        private void registerQuery(string queryPath, string queryName)
        {
            try
            {
                string esperQuery = readQueryFromFile(queryPath);
                foreach (EPStatement statement in gov.llnl.wintap.core.infrastructure.EventChannel.CompileDeploy(esperQuery, queryName).Statements)
                {
                    statement.Events += ProcStatement_Events;
                }
                WintapLogger.Log.Append("EPL created and event handlers attached on " + GetType().Name, LogLevel.Debug);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("error registering EPL: " + ex.Message, LogLevel.Info);
            }


        }

        private string readQueryFromFile(string fileName)
        {
            string eplFileName = fileName;
            int eplSuffix = fileName.LastIndexOf(".epl", StringComparison.OrdinalIgnoreCase);
            if (eplSuffix >= 0)
            {
                int nameStart = fileName.LastIndexOf('.', eplSuffix - 1) + 1;
                eplFileName = fileName.Substring(nameStart, eplSuffix - nameStart + 4);
            }

            string outputPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "esper", eplFileName);
            if (File.Exists(outputPath))
            {
                return File.ReadAllText(outputPath);
            }

            var assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream(fileName))
            {
                if (stream == null)
                {
                    throw new FileNotFoundException($"Could not find EPL query as file or embedded resource: {fileName}", outputPath);
                }

                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }



        private void ProcStatement_Events(object sender, UpdateEventArgs e)
        {
            if (e.NewEvents != null)
            {
                foreach (EventBean eb in e.NewEvents)
                {
                    HandleSensorEvent(eb);
                }
            }
        }

        private void sendThrottleEvent(string action)
        {
            GenericData wd = new GenericData();
            wd.Info = "ThrottleEvent";
            wd.Message = "Serializer=" + this.GetType().Name + ",Action=" + action;
            DateTime foo = DateTime.UtcNow;
            long unixTime = ((DateTimeOffset)foo).ToUnixTimeSeconds();
            wd.Timestamp = ((System.DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
            wd.Hostname = HostSerializer.Instance.HostId.Hostname;
            wd.Type = "GENERIC_INFO";
            wd.EventTime = GetUnixNowTime();
            WintapLogger.Log.Append(wd.Info + ": " + wd.Message, LogLevel.Debug);
        }
        #endregion
    }
}
