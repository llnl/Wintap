/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using Parquet;
using Parquet.Data;
using Parquet.Schema;
using Parquet.Serialization;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.etl.load
{
    internal class ParquetWriter : FileWriter
    {
        private ConcurrentQueue<Batch> batches = new ConcurrentQueue<Batch>();  // complete collection of all sensor data awaiting serialization
        private readonly BackgroundWorker batchWorker;
        private readonly ManualResetEventSlim drained = new(true);
        private long pendingBatches;
        private long writeFailures;

        // Bound memory usage if downstream IO falls behind.
        // 0 means unlimited (default).
        private readonly int maxBatchBacklog;
        private readonly DropPolicy backlogDropPolicy;
        private long droppedBatches;
        private DateTime lastDropLogUtc = DateTime.MinValue;

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

        internal ParquetWriter()
        {
            if (!int.TryParse(ConfigManager.GetValue<string>("WINTAP_PARQUET_MAX_BATCH_BACKLOG"), out maxBatchBacklog) || maxBatchBacklog < 0)
            {
                maxBatchBacklog = 0;
            }

            backlogDropPolicy = ParseDropPolicy(ConfigManager.GetValue<string>("WINTAP_PARQUET_BACKLOG_DROP_POLICY"));
            RuntimeCapabilities.Setting("writer.maxBatchBacklog", maxBatchBacklog, "writer-effective");
            RuntimeCapabilities.Setting("writer.dropPolicy", backlogDropPolicy.ToString(), "writer-effective");

            batchWorker = new BackgroundWorker();
            batchWorker.DoWork += BatchWorker_DoWork;
            batchWorker.RunWorkerAsync();
        }

        // BackgroundWorker does not support async work reliably. Using async void here
        // causes RunWorkerCompleted to fire early and can create multiple concurrent
        // writers (memory spike + file contention). Keep this worker strictly sync.
        private void BatchWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            while (true)
            {
                bool didWork = false;

                while (batches.TryDequeue(out Batch batch))
                {
                    didWork = true;
                    try
                    {
                        while (batch.Set.TryDequeue(out Batch.SensorData dataSet))
                        {
                            string fileName = "NA";
                            try
                            {
                                fileName = Write(dataSet).GetAwaiter().GetResult();
                            }
                            catch (Exception ex)
                            {
                                Interlocked.Increment(ref writeFailures);
                                WintapLogger.Log.Append($"Error in ParquetWriter worker for {dataSet.SensorName}: {ex.Message}", LogLevel.Info);
                            }

                            if (fileName != "NA")
                            {
                                try
                                {
                                    FileInfo flushedFile = new FileInfo(fileName);
                                    flushedFile.MoveTo(flushedFile.FullName.Replace(".parquet.active", ".parquet"));
                                    WintapLogger.Log.Append($" ready for merge: {fileName}", LogLevel.Info);
                                }
                                catch (Exception ex)
                                {
                                    Interlocked.Increment(ref writeFailures);
                                    WintapLogger.Log.Append($"ERROR renaming parquet for upload: {ex.Message}", LogLevel.Info);
                                }
                            }
                            else
                            {
                                WintapLogger.Log.Append($"{dataSet.SensorName}: Call to WRITE returned no parquet data file.", LogLevel.Info);
                            }
                        }
                    }
                    finally
                    {
                        MarkBatchComplete();
                    }
                }

                // No batches queued; avoid busy looping.
                if (!didWork)
                {
                    System.Threading.Thread.Sleep(250);
                }
            }
        }

        internal int Backlog { get { return batches.Count; } }

        internal bool WaitForCompletion(TimeSpan timeout)
        {
            return drained.Wait(timeout)
                && Interlocked.Read(ref writeFailures) == 0
                && Interlocked.Read(ref droppedBatches) == 0;
        }

        internal long FailureCount => Interlocked.Read(ref writeFailures);

        internal long DroppedBatchCount => Interlocked.Read(ref droppedBatches);

        internal void Add(Batch batch)
        {
            if (maxBatchBacklog > 0 && batches.Count >= maxBatchBacklog)
            {
                if (backlogDropPolicy == DropPolicy.DropOldest)
                {
                    // Evict one oldest batch to make room.
                    if (batches.TryDequeue(out _))
                    {
                        Interlocked.Increment(ref droppedBatches);
                        MarkBatchComplete();
                    }
                    else
                    {
                        Interlocked.Increment(ref droppedBatches);
                        // Nothing to evict; fall back to dropping newest below.
                        var now2 = DateTime.UtcNow;
                        if ((now2 - lastDropLogUtc).TotalSeconds >= 5)
                        {
                            lastDropLogUtc = now2;
                            WintapLogger.Log.Append($"ParquetWriter backlog limit reached (max={maxBatchBacklog}, policy={backlogDropPolicy}). Dropping batches. dropped={Interlocked.Read(ref droppedBatches)}", LogLevel.Warn);
                        }
                        return;
                    }

                    // now there should be room
                }
                else
                {
                    // Drop newest batch
                    Interlocked.Increment(ref droppedBatches);
                    var now = DateTime.UtcNow;
                    if ((now - lastDropLogUtc).TotalSeconds >= 5)
                    {
                        lastDropLogUtc = now;
                        WintapLogger.Log.Append($"ParquetWriter backlog limit reached (max={maxBatchBacklog}, policy={backlogDropPolicy}). Dropping batches. dropped={Interlocked.Read(ref droppedBatches)}", LogLevel.Warn);
                    }
                    return;
                }

                // Throttle logging; this can occur under sustained load.
                var nowLog = DateTime.UtcNow;
                if ((nowLog - lastDropLogUtc).TotalSeconds >= 5)
                {
                    lastDropLogUtc = nowLog;
                    WintapLogger.Log.Append($"ParquetWriter backlog limit reached (max={maxBatchBacklog}, policy={backlogDropPolicy}). Dropping batches. dropped={Interlocked.Read(ref droppedBatches)}", LogLevel.Warn);
                }
            }

            drained.Reset();
            Interlocked.Increment(ref pendingBatches);
            batches.Enqueue(batch);
        }

        private void MarkBatchComplete()
        {
            if (Interlocked.Decrement(ref pendingBatches) == 0)
            {
                drained.Set();
            }
        }

        internal static CompressionMethod GetCompressionMethod()
        {
            string configured = ConfigManager.GetValue<string>("WINTAP_PARQUET_COMPRESSION");
            if (string.IsNullOrWhiteSpace(configured))
            {
                return CompressionMethod.Snappy;
            }

            if (Enum.TryParse(configured, ignoreCase: true, out CompressionMethod method))
            {
                return method;
            }

            WintapLogger.Log.Append($"Unknown WINTAP_PARQUET_COMPRESSION '{configured}', using Snappy", LogLevel.Warn);
            return CompressionMethod.Snappy;
        }

        internal async Task<string> Write(Batch.SensorData dataSet)
        {
            // prevent file name collisions on shared event types
            bool applyOffset = false;
            foreach (dynamic d in dataSet.Data)
            {
                if (d.MessageType.ToLower().Contains("conn_incr"))
                {
                    if (d.Protocol == "UDP")
                    {
                        applyOffset = true;
                    }
                }
                if (d.MessageType.ToUpper() == "PROCESS")
                {
                    if (d.ActivityType == "STOP")
                    {
                        applyOffset = true;
                        d.MessageType = d.MessageType + "_stop";
                    }

                }
                break;
            }
            long timestamp = DateTime.UtcNow.ToFileTimeUtc() + Convert.ToInt32(applyOffset);
            string fileName = dataSet.ParquetPath + "-" + timestamp + ".parquet.active";  // name will be .active to avoid file contention with the uploader.
            WintapLogger.Log.Append($"{dataSet.SensorName} is writing {dataSet.Data.Count} records to path: {fileName}", LogLevel.Info);
            try
            {
                ParquetSchema schema = DetermineSchemaFromExpando(dataSet.Data.First());
                ParquetOptions options = new ParquetOptions();
                options.CompressionMethod = GetCompressionMethod();
                using (var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    await ParquetSerializer.SerializeUntypedAsync(dataSet.Data.Cast<IDictionary<string, object>>().ToList(), schema, fileStream, options);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error in ParquetWriter.Write: {ex.Message} ", LogLevel.Info);
                if (ex.Message.Contains("used by another process"))
                {
                    WintapLogger.Log.Append($"Retrying write operation...", LogLevel.Info);
                    timestamp = DateTime.UtcNow.ToFileTimeUtc() + 1;
                    fileName = dataSet.ParquetPath + "-" + timestamp + ".parquet.active";  // name will be .active to avoid file contention with the uploader.
                    WintapLogger.Log.Append($"{dataSet.SensorName} is retrying {dataSet.Data.Count} records to path: {fileName}", LogLevel.Info);
                    try
                    {
                        ParquetSchema schema = DetermineSchemaFromExpando(dataSet.Data.First());
                        ParquetOptions options = new ParquetOptions();
                        options.CompressionMethod = GetCompressionMethod();
                        using (var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                        {
                            await ParquetSerializer.SerializeUntypedAsync(dataSet.Data.Cast<IDictionary<string, object>>().ToList(), schema, fileStream, options);
                        }
                    }
                    catch (Exception ex2)
                    {
                        WintapLogger.Log.Append($"{SensorName} error on retry of WRITE operation: {ex2.Message}", LogLevel.Info);
                        throw new IOException("Parquet write retry failed.", ex2);
                    }
                }
                else
                {
                    throw;
                }
            }
            return fileName;
        }

        private static ParquetSchema DetermineSchemaFromExpando(ExpandoObject firstItem)
        {
            List<Field> fields = new List<Field>();
            foreach (var kvp in firstItem)
            {
                try
                {
                    DataField field = null;
                    if ((kvp.Key == "ParentPidHash" || kvp.Key == "FileSha2" || kvp.Key == "FileMd5") && kvp.Value == null)
                    {
                        // HACK: Just set type to "string". Not sure how to get the base type correctly, but Key is the type we want.
                        // Next HACK, set a default on the ProcessRecord
                        Type type = kvp.Key?.GetType() ?? typeof(string);
                        field = new DataField(kvp.Key, type);                        
                    } else
                    {
                        Type type = kvp.Value?.GetType() ?? typeof(string);
                        field = new DataField(kvp.Key, type);                        
                    }
                    fields.Add(field);
                }
                catch (Exception ex)
                {
                        WintapLogger.Log.Append($"Error on determining parquet schema: {ex}", LogLevel.Error);
                }
            }
            ParquetSchema schema = new ParquetSchema(fields.ToArray());
            return schema;
        }

        internal class Batch
        {
            private readonly long timestamp;
            private readonly string sensorName;
            //private readonly string dataDirectory;

            /// <summary>
            /// The time that this batch was requested by a sensor
            /// </summary>
            internal long Timestamp { get { return timestamp; } }

            /// <summary>
            /// The complete set of data for a given sensor for an interval that ended at the time specified by Name
            /// </summary>
            internal ConcurrentQueue<SensorData> Set;

            internal string SensorName { get { return sensorName; } }

            internal Batch(string _sensorName)
            {
                timestamp = DateTime.Now.ToFileTimeUtc(); // so we can process batches in time order
                sensorName = _sensorName;
                Set = new ConcurrentQueue<SensorData>();
            }

            /// <summary>
            /// Adds a set of typed sensor data to the current batch
            ///     Default sensor can have more than one type in its set, others will be a single.
            /// </summary>
            /// <param name="_sensorData"></param>
            internal void Add(SensorData _sensorData)
            {
                Set.Enqueue(_sensorData);
            }

            internal class SensorData
            {
                private readonly string sensorName;
                private readonly ConcurrentQueue<ExpandoObject> sensorData;
                private string parquetPath;

                internal SensorData(string _sensorName, string _messageType, ConcurrentQueue<ExpandoObject> sensorData)
                {
                    this.sensorName = _sensorName.ToLower();
                    this.sensorName = _messageType.ToLower();
                    this.sensorData = sensorData;
                    this.parquetPath = gov.llnl.wintap.core.etl.shared.Utilities.GetFileStorePath(_sensorName);
                    DirectoryInfo sensorDataDir = new DirectoryInfo(this.parquetPath);
                    if (this.sensorName.ToUpper() == "DefaultSerializer")
                    {
                        sensorDataDir = new DirectoryInfo(Path.Combine(this.parquetPath, this.sensorName));
                        this.parquetPath = Path.Combine(this.parquetPath, this.sensorName, this.sensorName);
                    }
                    else
                    {
                        this.parquetPath = Path.Combine(this.parquetPath, this.sensorName);
                    }
                    if (!sensorDataDir.Exists)
                    {
                        sensorDataDir.Create();
                    }
                }

                internal string SensorName { get { return sensorName; } }
                internal ConcurrentQueue<ExpandoObject> Data { get { return sensorData; } }
                internal string ParquetPath { get { return parquetPath; } }
            }
        }
    }
}
