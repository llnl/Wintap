/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using gov.llnl.wintap.platform.windows.infrastructure;

namespace gov.llnl.wintap.platform.windows.collect.etw
{

    /// <summary>
    /// File events from the ETW 'nt kernel logger'
    /// </summary>
    internal class FileSensor : EtwProviderCollector
    {
        private const string RundownEtlSubPath = "etl\\kernelrundown.etl";
        private const string EtlFileExtension = ".etl";

        private ConcurrentDictionary<ulong, string> fileKeyToPath;
        private readonly WindowsFilePathNormalizer pathNormalizer = new WindowsFilePathNormalizer(
            () => WindowsFileVolumeMap.Discover(), summary: text => WintapLogger.Log.Append(text, LogLevel.Debug));

        internal enum FileIoSubscription
        {
            Write,
            Delete,
            Name,
            Create,
            Close,
            Read
        }

        public FileSensor() : base()
        {
            SensorName = "File";
            EtwProviderId = "SystemTraceControlGuid";
            KernelTraceEventFlags = Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.FileIOInit
                | Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.DiskFileIO;
            fileKeyToPath = new ConcurrentDictionary<ulong, string>();
        }

        /// <summary>
        /// Starts the file sensor and processes the ETW rundown trace.
        /// </summary>
        /// <returns>True if the sensor started successfully.</returns>
        public override bool Start()
        {
            pathNormalizer.Initialize();
            foreach (FileIoSubscription subscription in BuildSubscriptionPlan(Properties.Settings.Default.CollectFileRead))
            {
                SubscribeKernelFileIoEvent(subscription);
            }

            ProcessRundownTrace();
            WintapLogger.Log.Append(
                "Skipping ETW file rundown execution while shared kernel session is active; relying on live FileIOName/FileIOCreate events for path mapping.",
                LogLevel.Warn);
            enabled = true;

            return true;
        }

        internal static FileIoSubscription[] BuildSubscriptionPlan(bool collectFileRead)
        {
            return collectFileRead
                ? new[]
                {
                    FileIoSubscription.Write,
                    FileIoSubscription.Delete,
                    FileIoSubscription.Name,
                    FileIoSubscription.Create,
                    FileIoSubscription.Read
                }
                : new[]
                {
                    FileIoSubscription.Write,
                    FileIoSubscription.Delete,
                    FileIoSubscription.Name,
                    FileIoSubscription.Create
                };
        }

        internal static string SelectTraceEventFileNameOnly(string traceEventFileName)
        {
            return traceEventFileName;
        }

        private void SubscribeKernelFileIoEvent(FileIoSubscription subscription)
        {
            switch (subscription)
            {
                case FileIoSubscription.Write:
                    KernelParser.Instance.EtwParser.FileIOWrite += Kernel_FileIoWrite;
                    break;
                case FileIoSubscription.Delete:
                    KernelParser.Instance.EtwParser.FileIODelete += Kernel_FileIoDelete;
                    break;
                case FileIoSubscription.Name:
                    KernelParser.Instance.EtwParser.FileIOName += EtwParser_FileIOName;
                    break;
                case FileIoSubscription.Create:
                    KernelParser.Instance.EtwParser.FileIOCreate += Kernel_FileIoCreate;
                    break;
                case FileIoSubscription.Read:
                    KernelParser.Instance.EtwParser.FileIORead += Kernel_FileIoRead;
                    break;
                case FileIoSubscription.Close:
                    // Intentionally suppressed: Close events dominated File volume and are not emitted by Wintap.
                    break;
            }
        }

        /// <summary>
        /// Processes the kernel rundown ETL file to populate the file key to path mapping.
        /// </summary>
        private void ProcessRundownTrace()
        {
            WintapLogger.Log.Append("Processing rundown trace", LogLevel.Info);

            string etlFilePath = Path.Combine(Env.FileRootPath, RundownEtlSubPath);
            FileInfo rundownInfo = new FileInfo(etlFilePath);

            if (rundownInfo.Exists)
            {
                WintapLogger.Log.Append($"Processing rundown trace from {etlFilePath}", LogLevel.Info);
                int counter = 0;

                using (var source = new ETWTraceEventSource(etlFilePath))
                {
                    source.Kernel.FileIOFileRundown += delegate (FileIONameTraceData data)
                    {
                        if (data.EventName.ToLower().Contains("rundown"))
                        {
                            fileKeyToPath.TryAdd(data.FileKey, data.FileName);
                            counter++;
                        }
                    };
                    source.Process();
                    WintapLogger.Log.Append($"Rundown file event trace complete. Total rundowns processed: {counter}", LogLevel.Info);
                }
            }
            else
            {
                WintapLogger.Log.Append("No file rundown ETL found. File events may not always contain a path for this session.", LogLevel.Warn);
            }
        }

        /// <summary>
        /// Executes the ETW rundown process via WintapCoreSvcMgr.
        /// </summary>
        private void ExecuteEtwRundown()
        {
            WintapLogger.Log.Append("Executing ETW event rundown", LogLevel.Always);

            ProcessStartInfo rundownPsi = new ProcessStartInfo
            {
                FileName = Path.Combine(Env.FileRootPath, "WintapCoreSvcMgr.exe"),
                Arguments = "RUNDOWN"
            };

            using (Process rundown = new Process { StartInfo = rundownPsi })
            {
                rundown.Start();
                rundown.WaitForExit();
            }

            WintapLogger.Log.Append("ETW Rundown complete", LogLevel.Always);
        }

        /// <summary>
        /// Handles file close events from ETW.
        /// </summary>
        private void EtwParser_FileIOClose(FileIOSimpleOpTraceData obj)
        {
            try
            {
                string path;
                if (!fileKeyToPath.TryGetValue(obj.FileKey, out path) || string.IsNullOrEmpty(path))
                {
                    fileKeyToPath.TryGetValue(obj.FileObject, out path);
                }

                if (!string.IsNullOrEmpty(path))
                {
                    string activityId = TryGetActivityId(obj);
                    string correlationId = TryGetCorrelationId(obj);
                    sendFileEvent(path, obj.ProcessID, obj.TimeStamp, WintapMessage.ActivityTypeEnum.Close, 0, activityId, correlationId);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"CLOSE handler error: {ex.Message}", LogLevel.Info);
            }
        }

        /// <summary>
        /// Handles file create events from ETW and maps FileObject to file name.
        /// FileObject is per-openfile not per-filename (fileKey).
        /// </summary>
        private void Kernel_FileIoCreate(FileIOCreateTraceData obj)
        {
            try
            {
                fileKeyToPath.TryAdd(obj.FileObject, obj.FileName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"CREATE handler error: {ex.Message}", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Handles file name events from ETW and maps FileKey to file name.
        /// </summary>
        private void EtwParser_FileIOName(FileIONameTraceData obj)
        {
            try
            {
                fileKeyToPath.TryAdd(obj.FileKey, obj.FileName);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"FILE NAME handler error: {ex.Message}", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Handles file read events from ETW.
        /// </summary>
        private void Kernel_FileIoRead(FileIOReadWriteTraceData obj)
        {
            try
            {
                string filePath = SelectTraceEventFileNameOnly(obj.FileName);
                if (!string.IsNullOrEmpty(filePath))
                {
                    string activityId = TryGetActivityId(obj);
                    string correlationId = TryGetCorrelationId(obj);
                    sendFileEvent(filePath, obj.ProcessID, obj.TimeStamp, WintapMessage.ActivityTypeEnum.Read, obj.IoSize, activityId, correlationId);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error handling Kernel_FileIoRead event: {ex.Message}", LogLevel.Info);
            }
        }

        /// <summary>
        /// Handles file write events from ETW.
        /// </summary>
        private void Kernel_FileIoWrite(FileIOReadWriteTraceData obj)
        {
            if (obj.ProcessID == StateManager.WintapPID)
            {
                return; // Prevent feedback loop
            }

            try
            {
                string filePath = SelectTraceEventFileNameOnly(obj.FileName);

                if (!string.IsNullOrEmpty(filePath))
                {
                    string activityId = TryGetActivityId(obj);
                    string correlationId = TryGetCorrelationId(obj);
                    sendFileEvent(filePath, obj.ProcessID, obj.TimeStamp, WintapMessage.ActivityTypeEnum.Write, obj.IoSize, activityId, correlationId);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error handling Kernel_FileIoWrite event: {ex.Message} - {obj}", LogLevel.Info);
            }
        }

        /// <summary>
        /// Resolves the file path from either the existing path or file object/key lookups.
        /// </summary>
        private string resolveIoFilePath(string existingPath, ulong fileObj, ulong fileKey)
        {
            if (!string.IsNullOrEmpty(existingPath))
            {
                return existingPath;
            }

            string filePath;
            if (fileKeyToPath.TryGetValue(fileObj, out filePath) && !string.IsNullOrEmpty(filePath))
            {
                WintapLogger.Log.Append($"Resolved path from fileTable lookup: {filePath}", LogLevel.Debug);
                return filePath;
            }

            fileKeyToPath.TryGetValue(fileKey, out filePath);
            return filePath;
        }

        /// <summary>
        /// Sends a file event to the event channel.
        /// </summary>
        private void sendFileEvent(string filePath, int pid, DateTime eventTime, WintapMessage.ActivityTypeEnum opName, int bytesRequested, string activityId, string correlationId)
        {
            var message = CreateFileMessage(filePath, pid, eventTime, opName, bytesRequested, activityId, correlationId, pathNormalizer.Normalize);
            if (message != null) EventChannel.Send(message);
        }

        internal static WintapMessage CreateFileMessage(string filePath, int pid, DateTime eventTime,
            WintapMessage.ActivityTypeEnum opName, int bytesRequested, string activityId, string correlationId,
            Func<string, string> normalize)
        {
            if (string.IsNullOrEmpty(filePath) || filePath.EndsWith(EtlFileExtension, StringComparison.OrdinalIgnoreCase)) return null;
            return new WintapMessage(eventTime, pid, WintapMessage.MessageTypeEnum.File)
            {
                File = new WintapMessage.FileActivityObject { Path = normalize(filePath), BytesRequested = bytesRequested },
                ActivityType = opName, ActivityId = activityId, CorrelationId = correlationId
            };
        }
        /// <summary>
        /// Safely attempts to get the activity ID from the trace data.
        /// </summary>
        private string TryGetActivityId(TraceEvent obj)
        {
            try
            {
                return obj.ActivityID.ToString();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Failed to get ActivityID: {ex.Message}", LogLevel.Debug);
                return null;
            }
        }

        /// <summary>
        /// Safely attempts to get the correlation ID from the trace data payload.
        /// </summary>
        private string TryGetCorrelationId(TraceEvent obj)
        {
            try
            {
                return obj.PayloadStringByName("CorrelationId");
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Failed to get CorrelationId: {ex.Message}", LogLevel.Debug);
                return null;
            }
        }

        /// <summary>
        /// Handles file delete events from ETW.
        /// </summary>
        private void Kernel_FileIoDelete(FileIOInfoTraceData obj)
        {
            base.Process_Event(obj);

            if (obj.ProcessID == StateManager.WintapPID)
            {
                return; // Prevent feedback loop
            }

            try
            {
                string filePath = SelectTraceEventFileNameOnly(obj.FileName);

                if (!string.IsNullOrEmpty(filePath))
                {
                    string activityId = TryGetActivityId(obj);
                    string correlationId = TryGetCorrelationId(obj);
                    sendFileEvent(filePath, obj.ProcessID, obj.TimeStamp, WintapMessage.ActivityTypeEnum.Delete, 0, activityId, correlationId);
                }

                fileKeyToPath.TryRemove(obj.FileKey, out _);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error in Kernel_FileIoDelete event: {ex.Message}", LogLevel.Info);
            }
        }
    }
}
