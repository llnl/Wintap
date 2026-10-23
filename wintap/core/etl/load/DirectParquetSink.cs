using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Dynamic;
using System.Reflection;
using System.Timers;

namespace gov.llnl.wintap.core.etl.load
{
    internal static class DirectParquetSink
    {
        private static readonly ConcurrentDictionary<string, ConcurrentQueue<ExpandoObject>> queues = new();
        private static readonly ParquetWriter parquetWriter = new();
        private static readonly Timer flushTimer;

        // Bound memory usage in direct-parquet mode as well.
        // 0 means unlimited.
        private static readonly int maxQueueEvents;
        private static readonly DropPolicy backlogDropPolicy;
        private static long droppedEvents;
        private static DateTime lastDropLogUtc = DateTime.MinValue;

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

        static DirectParquetSink()
        {
            if (!int.TryParse(ConfigManager.GetValue<string>("WINTAP_DIRECT_PARQUET_MAX_QUEUE_EVENTS"), out maxQueueEvents) || maxQueueEvents < 0)
            {
                maxQueueEvents = 0;
            }

            backlogDropPolicy = ParseDropPolicy(ConfigManager.GetValue<string>("WINTAP_DIRECT_PARQUET_QUEUE_DROP_POLICY"));

            int flushSeconds = 15;
            if (int.TryParse(ConfigManager.GetValue<string>("WINTAP_DIRECT_PARQUET_FLUSH_SECONDS"), out int configuredSeconds) && configuredSeconds > 0)
            {
                flushSeconds = configuredSeconds;
            }

            flushTimer = new Timer(flushSeconds * 1000);
            RuntimeCapabilities.Setting("directParquet.maxQueueEvents", maxQueueEvents, "direct-sink-effective");
            RuntimeCapabilities.Setting("directParquet.dropPolicy", backlogDropPolicy.ToString(), "direct-sink-effective");
            RuntimeCapabilities.Setting("directParquet.flushSeconds", flushSeconds, "direct-sink-effective");
            flushTimer.AutoReset = true;
            flushTimer.Elapsed += FlushTimer_Elapsed;
            flushTimer.Start();
        }

        internal static bool IsEnabled
        {
            get
            {
                var val = ConfigManager.GetValue<string>("WINTAP_ENABLE_DIRECT_PARQUET");
                if (!string.IsNullOrEmpty(val) && (string.Equals(val, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(val, "1", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }

                // Fallback to environment variable
                return false;
            }
        }

        internal static void Save(WintapMessage message)
        {
            if (!IsEnabled || message == null)
            {
                return;
            }

            string messageType = message.MessageType.ToString();
            ConcurrentQueue<ExpandoObject> queue = queues.GetOrAdd(messageType, _ => new ConcurrentQueue<ExpandoObject>());

            if (maxQueueEvents > 0 && queue.Count >= maxQueueEvents)
            {
                if (backlogDropPolicy == DropPolicy.DropOldest)
                {
                    // Evict one oldest event to make room.
                    if (queue.TryDequeue(out _))
                    {
                        droppedEvents++;
                        gov.llnl.wintap.core.infrastructure.EventChannel.AddDroppedEvents(1);
                    }
                    else
                    {
                        // Nothing to evict; drop newest.
                        droppedEvents++;
                        gov.llnl.wintap.core.infrastructure.EventChannel.AddDroppedEvents(1);
                        var now2 = DateTime.UtcNow;
                        if ((now2 - lastDropLogUtc).TotalSeconds >= 5)
                        {
                            lastDropLogUtc = now2;
                            WintapLogger.Log.Append($"DirectParquetSink backlog limit reached (type={messageType}, max={maxQueueEvents}, policy={backlogDropPolicy}). Dropping events. dropped={droppedEvents}", LogLevel.Warn);
                        }
                        return;
                    }
                }
                else
                {
                    droppedEvents++;
                    gov.llnl.wintap.core.infrastructure.EventChannel.AddDroppedEvents(1);
                    var now = DateTime.UtcNow;
                    if ((now - lastDropLogUtc).TotalSeconds >= 5)
                    {
                        lastDropLogUtc = now;
                        WintapLogger.Log.Append($"DirectParquetSink backlog limit reached (type={messageType}, max={maxQueueEvents}, policy={backlogDropPolicy}). Dropping events. dropped={droppedEvents}", LogLevel.Warn);
                    }
                    return;
                }

                var nowLog = DateTime.UtcNow;
                if ((nowLog - lastDropLogUtc).TotalSeconds >= 5)
                {
                    lastDropLogUtc = nowLog;
                    WintapLogger.Log.Append($"DirectParquetSink backlog limit reached (type={messageType}, max={maxQueueEvents}, policy={backlogDropPolicy}). Dropping events. dropped={droppedEvents}", LogLevel.Warn);
                }
            }

            queue.Enqueue(ToExpando(message));
        }

        private static void FlushTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            foreach (KeyValuePair<string, ConcurrentQueue<ExpandoObject>> queuePair in queues)
            {
                List<ExpandoObject> records = new List<ExpandoObject>();
                while (queuePair.Value.TryDequeue(out ExpandoObject record))
                {
                    records.Add(record);
                }

                if (records.Count == 0)
                {
                    continue;
                }

                ConcurrentQueue<ExpandoObject> data = new ConcurrentQueue<ExpandoObject>(records);
                ParquetWriter.Batch batch = new ParquetWriter.Batch(queuePair.Key);
                batch.Add(new ParquetWriter.Batch.SensorData(queuePair.Key, queuePair.Key, data));
                parquetWriter.Add(batch);
                WintapLogger.Log.Append($"DirectParquetSink queued {records.Count} {queuePair.Key} records for parquet write", LogLevel.Info);
            }
        }

        private static ExpandoObject ToExpando(WintapMessage message)
        {
            ExpandoObject expando = new ExpandoObject();
            IDictionary<string, object> values = expando;

            values["MessageType"] = message.MessageType.ToString();
            values["ActivityType"] = message.ActivityType.ToString();
            values["PID"] = message.PID;
            values["EventTime"] = message.EventTime;
            values["AgentId"] = message.AgentId ?? string.Empty;
            values["PidHash"] = message.PidHash ?? string.Empty;
            values["ProcessName"] = message.ProcessName ?? string.Empty;
            values["ProcessPath"] = message.ProcessPath ?? string.Empty;
            values["CapturedUtc"] = DateTime.UtcNow;

            AddScalarProperties(values, "Process", message.Process);
            AddScalarProperties(values, "File", message.File);
            AddScalarProperties(values, "TcpConnection", message.TcpConnection);
            AddScalarProperties(values, "UdpPacket", message.UdpPacket);
            AddScalarProperties(values, "Registry", message.Registry);
            AddScalarProperties(values, "GenericMessage", message.GenericMessage);

            return expando;
        }

        private static void AddScalarProperties(IDictionary<string, object> values, string prefix, object source)
        {
            if (source == null)
            {
                return;
            }

            foreach (PropertyInfo property in source.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public))
            {
                object value = property.GetValue(source);
                if (value == null)
                {
                    continue;
                }

                Type valueType = Nullable.GetUnderlyingType(value.GetType()) ?? value.GetType();
                if (valueType.IsPrimitive || valueType.IsEnum || valueType == typeof(string) || valueType == typeof(decimal) || valueType == typeof(DateTime) || valueType == typeof(Guid))
                {
                    values[prefix + "_" + property.Name] = valueType.IsEnum ? value.ToString() : value;
                }
            }
        }
    }
}
