/*
 * Copyright (c) 2023, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.etl.extract;
using gov.llnl.wintap.core.etl.load.interfaces;
using gov.llnl.wintap.core.etl.model;
using gov.llnl.wintap.core.etl.shared;
using gov.llnl.wintap.core.infrastructure;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Timers;
using System.Threading;

namespace gov.llnl.wintap.core.etl.load
{
    internal class CacheManager
    {
        private BackgroundWorker uploaderThread;
        private volatile bool svcRunning;
        private DirectoryInfo cacheDir;
        private long bytesOnDisk;
        private int mergeHelperPid;
        private List<IUpload> uploaders;
        private BackgroundWorker workerThread;
        private readonly ManualResetEventSlim workerStopped = new(false);

        internal ETLConfig etlConfig;
        internal static ConcurrentQueue<dynamic> SendQueue;

        internal CacheManager(ETLConfig _config)
        {
            uploaders = new List<IUpload>();
            WintapLogger.Log.Append("Cache Manager is starting up", LogLevel.Info);
            etlConfig = _config;
            LogStartupConfiguration();
            svcRunning = true;
            SendQueue = new ConcurrentQueue<dynamic>();
            DirectoryInfo stagingDir = new DirectoryInfo(Paths.EsperStagingPath);
            if (!stagingDir.Exists)
            {
                stagingDir.Create();
            }
            cacheDir = stagingDir;
            bytesOnDisk = getCurrentCacheDirSize();

            WintapLogger.Log.Append("Loading data uploaders...", LogLevel.Info);
            foreach (ETLConfig.Adapter u in etlConfig.Adapters)
            {
                try
                {
                    Type type = ResolveAdapterType(u.Name);
                    if (type == null)
                    {
                        WintapLogger.Log.Append("ERROR: No assembly matching the name " + u.Name + " was found. This uploader will not run. Check the spelling or remove this config entry.", LogLevel.Error);
                        continue;
                    }

                    IUpload uploader = (IUpload)Activator.CreateInstance(type, null);
                    uploader.Name = u.Name;
                    if (u.Enabled)
                    {
                        uploaders.Add(uploader);
                        WintapLogger.Log.Append("Loaded uploader: " + u.Name, LogLevel.Info);
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append("ERROR: Could not initialize uploader " + u.Name + ": " + ex.Message, LogLevel.Error);
                }
            }
            createMetaRecords();
            WintapLogger.Log.Append("Total uploaders: " + uploaders.Count, LogLevel.Info);
            clearRawSensor();
            workerThread = new BackgroundWorker();
            workerThread.DoWork += WorkerThread_DoWork;
        }

        private void LogStartupConfiguration()
        {
            Utilities.LogStartupConfigurationMessage("ETL startup configuration summary", LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("ETLConfig path: " + Utilities.GetETLConfigPath(), LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("ETLConfig exists: " + File.Exists(Utilities.GetETLConfigPath()), LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Data root: " + Paths.DataRoot, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Runtime root: " + Paths.RuntimeRoot, LogLevel.Info);
            if (string.Equals(
                Path.GetFullPath(Paths.DataRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                Path.GetFullPath(Paths.RuntimeRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase))
            {
                Utilities.LogStartupConfigurationMessage("Data and runtime roots are the same; host-specific state will share the data tree.", LogLevel.Warn);
            }
            Utilities.LogStartupConfigurationMessage("Parquet data path: " + Paths.ParquetDataPath, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Esper staging path: " + Paths.EsperStagingPath, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Serialization interval (sec): " + etlConfig.SerializationIntervalSec, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Upload interval (sec): " + etlConfig.UploadIntervalSec, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Write to parquet: " + etlConfig.WriteToParquet, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Write to csv: " + etlConfig.WriteToCsv, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Configured adapters: " + etlConfig.Adapters.Count, LogLevel.Info);
            Utilities.LogStartupConfigurationMessage("Enabled adapters: " + etlConfig.Adapters.Count(adapter => adapter != null && adapter.Enabled), LogLevel.Info);

            foreach (ETLConfig.Adapter adapter in etlConfig.Adapters)
            {
                LogAdapterConfiguration(adapter);
            }
        }

        private void LogAdapterConfiguration(ETLConfig.Adapter adapter)
        {
            if (adapter == null)
            {
                Utilities.LogStartupConfigurationMessage("Adapter config entry is null", LogLevel.Warn);
                return;
            }

            string adapterName = string.IsNullOrWhiteSpace(adapter.Name) ? "<missing>" : adapter.Name;
            Type adapterType = ResolveAdapterType(adapter.Name);
            Utilities.LogStartupConfigurationMessage($"Adapter config: name={adapterName}, enabled={adapter.Enabled}, typeResolved={adapterType != null}", LogLevel.Info);

            if (adapterType == null)
            {
                Utilities.LogStartupConfigurationMessage($"Adapter config warning: {adapterName} does not resolve to a known uploader type", LogLevel.Warn);
            }

            if (!adapter.Enabled)
            {
                return;
            }

            if (adapter.Properties == null || adapter.Properties.Count == 0)
            {
                Utilities.LogStartupConfigurationMessage($"Enabled adapter properties for {adapterName}: none", LogLevel.Info);
                return;
            }

            foreach (KeyValuePair<string, string> property in adapter.Properties.OrderBy(p => p.Key))
            {
                Utilities.LogStartupConfigurationMessage($"Enabled adapter property: {adapterName}.{property.Key}={SanitizeAdapterProperty(property.Key, property.Value)}", LogLevel.Info);
            }

            LogAdapterSpecificValidation(adapterName, adapter.Properties);
        }

        private void LogAdapterSpecificValidation(string adapterName, Dictionary<string, string> properties)
        {
            if (adapterName.Equals("S3Adapter", StringComparison.OrdinalIgnoreCase))
            {
                string bucket = GetAdapterProperty(properties, "Bucket");
                string regionEndpoint = GetAdapterProperty(properties, "RegionEndpoint");
                string serviceUrl = GetAdapterProperty(properties, "ServiceURL");
                string endpoint = GetAdapterProperty(properties, "Endpoint");
                string accessKey = GetAdapterProperty(properties, "AccessKey");
                string secretKey = GetAdapterProperty(properties, "SecretKey");
                string sessionToken = GetAdapterProperty(properties, "SessionToken");
                string forcePathStyle = GetAdapterProperty(properties, "ForcePathStyle");
                string keyPrefix = GetAdapterProperty(properties, "KeyPrefix");

                Utilities.LogStartupConfigurationMessage($"S3Adapter config summary: bucket={(string.IsNullOrWhiteSpace(bucket) ? "<missing>" : bucket)}, endpoint={(string.IsNullOrWhiteSpace(serviceUrl) ? endpoint : serviceUrl)}, region={regionEndpoint}, keyPrefix={keyPrefix}, forcePathStyle={forcePathStyle}, credentialSource={GetS3CredentialSource(accessKey, secretKey, sessionToken)}", LogLevel.Info);

                if (string.IsNullOrWhiteSpace(bucket))
                {
                    Utilities.LogStartupConfigurationMessage("S3Adapter config warning: Bucket is not set; uploads will fail with NO_BUCKET_SPECIFIED", LogLevel.Warn);
                }

                if (string.IsNullOrWhiteSpace(regionEndpoint) && string.IsNullOrWhiteSpace(serviceUrl) && string.IsNullOrWhiteSpace(endpoint))
                {
                    Utilities.LogStartupConfigurationMessage("S3Adapter config warning: RegionEndpoint, ServiceURL, and Endpoint are all empty; AWS SDK defaults will be used", LogLevel.Warn);
                }

                if (!string.IsNullOrWhiteSpace(accessKey) != !string.IsNullOrWhiteSpace(secretKey))
                {
                    Utilities.LogStartupConfigurationMessage("S3Adapter config warning: AccessKey and SecretKey must be configured together; instance profile credentials will be used if either is missing", LogLevel.Warn);
                }

                if (!string.IsNullOrWhiteSpace(forcePathStyle) && !bool.TryParse(forcePathStyle, out _))
                {
                    Utilities.LogStartupConfigurationMessage("S3Adapter config warning: ForcePathStyle is not a valid boolean: " + forcePathStyle, LogLevel.Warn);
                }
            }
            else if (adapterName.Equals("SMBFileShareAdapter", StringComparison.OrdinalIgnoreCase))
            {
                string uncPath = GetAdapterProperty(properties, "UNCPath");
                Utilities.LogStartupConfigurationMessage("SMBFileShareAdapter config summary: UNCPath=" + (string.IsNullOrWhiteSpace(uncPath) ? "<missing>" : uncPath), LogLevel.Info);
                if (string.IsNullOrWhiteSpace(uncPath))
                {
                    Utilities.LogStartupConfigurationMessage("SMBFileShareAdapter config warning: UNCPath is not set", LogLevel.Warn);
                }
            }
        }

        private Type ResolveAdapterType(string adapterName)
        {
            if (string.IsNullOrWhiteSpace(adapterName))
            {
                return null;
            }

            return Type.GetType("gov.llnl.wintap.core.etl.load.adapters." + adapterName);
        }

        private string GetAdapterProperty(Dictionary<string, string> properties, string key)
        {
            if (properties != null && properties.TryGetValue(key, out string value) && value != null)
            {
                return value;
            }

            return string.Empty;
        }

        private string SanitizeAdapterProperty(string key, string value)
        {
            if (value == null)
            {
                return "<null>";
            }

            if (IsSensitiveAdapterProperty(key))
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return "<empty>";
                }

                return "<set; length=" + value.Length + ">";
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                return "<empty>";
            }

            return value;
        }

        private bool IsSensitiveAdapterProperty(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return false;
            }

            return key.IndexOf("secret", StringComparison.OrdinalIgnoreCase) >= 0
                || key.IndexOf("token", StringComparison.OrdinalIgnoreCase) >= 0
                || key.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0
                || key.IndexOf("accesskey", StringComparison.OrdinalIgnoreCase) >= 0
                || key.IndexOf("certificate", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private string GetS3CredentialSource(string accessKey, string secretKey, string sessionToken)
        {
            if (!string.IsNullOrWhiteSpace(accessKey) && !string.IsNullOrWhiteSpace(secretKey))
            {
                return string.IsNullOrWhiteSpace(sessionToken) ? "ETLConfig AccessKey/SecretKey" : "ETLConfig session credentials";
            }

            return "instance profile/default AWS credentials";
        }

        internal void Start()
        {
            svcRunning = true;
            clearCache();
            workerThread.RunWorkerAsync();
        }

        internal bool Stop(TimeSpan timeout)
        {
            svcRunning = false;
            if (workerThread.IsBusy && !workerStopped.Wait(timeout))
            {
                WintapLogger.Log.Append("CacheManager shutdown timed out waiting for its worker; final merge was not started.", LogLevel.Warn);
                return false;
            }

            // Serializers have finalized their parquet files before this call.
            // Materialize one final cross-stream snapshot instead of waiting for
            // the next periodic upload interval.
            bool mergeComplete = doMerge();
            cleanup();
            WintapLogger.Log.Append($"CacheManager final merge complete={mergeComplete}.", mergeComplete ? LogLevel.Info : LogLevel.Warn);
            return mergeComplete;
        }

        private void WorkerThread_DoWork(object sender, DoWorkEventArgs e)
        {
            WintapLogger.Log.Append("uploader thread is running", LogLevel.Info);
            Stopwatch uploadTimer = new Stopwatch();
            uploadTimer.Restart();
            try
            {
                while (svcRunning)
                {
                    if (uploadTimer.Elapsed.TotalSeconds > etlConfig.UploadIntervalSec)
                    {
                        var cycleTimer = Stopwatch.StartNew();
                        doMerge();
                        List<RawSensorCacheFile> rawSensorFiles = getRawSensorParquetFiles();
                        long mergeElapsedMs = cycleTimer.ElapsedMilliseconds;
                        int rawSensorFileCount = rawSensorFiles.Count;
                        long rawSensorBytes = rawSensorFiles.Sum(file => file.Length);
                        if (rawSensorFiles.Count > 0)
                        {
                            WintapLogger.Log.Append("upload worker is awake and processing: " + cacheDir.FullName, LogLevel.Info);
                            try
                            {
                                rawSensorFiles = pruneCache(rawSensorFiles);
                            }
                            catch (Exception ex)
                            {
                                WintapLogger.Log.Append("error cleaning up cache files: " + ex.Message, LogLevel.Warn);
                            }
                            foreach (IUpload uploader in uploaders)
                            {
                                WintapLogger.Log.Append("Calling pre-upload method on: " + uploader.Name, LogLevel.Info);
                                try
                                {
                                    uploader.PreUpload(getUploaderParameters(uploader));
                                }
                                catch (Exception ex)
                                {
                                    WintapLogger.Log.Append($"ERROR in preUpload for {uploader.Name}: {ex.Message}", LogLevel.Info);
                                }
                            }
                            upload(rawSensorFiles);
                            foreach (IUpload uploader in uploaders)
                            {
                                try
                                {
                                    uploader.PostUpload();
                                }
                                catch (Exception ex)
                                {
                                    WintapLogger.Log.Append($"ERROR in PostUpload for {uploader.Name}: {ex.Message}", LogLevel.Warn);
                                }
                            }
                        }
                        WintapLogger.Log.Append(
                            $"CacheManager cycle metrics: files={rawSensorFileCount},bytes={rawSensorBytes},merge_ms={mergeElapsedMs},total_ms={cycleTimer.ElapsedMilliseconds}",
                            LogLevel.Info);
                        uploadTimer.Restart();
                    }
                    if (DateTime.Now.Minute == 0 && DateTime.Now.Second < 2)  // only once at the top of the hour
                    {
                        createMetaRecords();  // host, macip
                    }
                    System.Threading.Thread.Sleep(1000);
                }
            }
            finally
            {
                workerStopped.Set();
            }
        }

        private void upload(List<RawSensorCacheFile> rawSensorFiles)
        {
            DirectoryInfo rawSensorDir = new DirectoryInfo(Path.Combine(Paths.ParquetDataPath, "raw_sensor"));
            WintapLogger.Log.Append("CacheManager upload method is starting. raw_sensor directory: " + rawSensorDir.FullName, LogLevel.Info);

            if (!rawSensorDir.Exists)
            {
                return;
            }

            foreach (RawSensorCacheFile rawSensorFile in rawSensorFiles)
            {
                FileInfo dataFile = new FileInfo(rawSensorFile.FullPath);
                if (!dataFile.Exists)
                {
                    continue;
                }

                if (dataFile.Length == 0)
                {
                    WintapLogger.Log.Append("Deleting zero-byte parquet file: " + dataFile.FullName, LogLevel.Warn);
                    tryDeleteUploadedFile(dataFile, "zero-byte parquet cleanup");
                    System.Threading.Thread.Sleep(250);
                    continue;
                }

                bool successfulUpload = false;
                foreach (IUpload uploader in uploaders)
                {
                    try
                    {
                        WintapLogger.Log.Append("Calling upload: " + uploader.Name, LogLevel.Info);
                        if (uploader.Upload(dataFile.FullName, getUploaderParameters(uploader)).Result)
                        {
                            successfulUpload = true; // any success = all success, for now.
                        }
                    }
                    catch (Exception ex)
                    {
                        WintapLogger.Log.Append("Upload failed with error: " + ex.Message, LogLevel.Warn);
                    }
                }

                if (successfulUpload)
                {
                    tryDeleteUploadedFile(dataFile, "confirmed upload");
                }
                else
                {
                    WintapLogger.Log.Append("All uploads failed for file; retaining for retry next cycle: " + dataFile.FullName, LogLevel.Debug);
                }

                System.Threading.Thread.Sleep(250);  // throttle the upload to prevent CPU/IO spike
            }

            WintapLogger.Log.Append("CacheManager upload method is complete", LogLevel.Info);
        }

        private void cleanup()
        {
            try
            {
                FileInfo[] orphanedActives = cacheDir.GetFiles("*.active", SearchOption.AllDirectories);
                for (int i = 0; i < orphanedActives.Length; i++)
                {
                    orphanedActives[i].Delete();
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error cleaning up active files: " + ex.Message, LogLevel.Info);
            }
        }

        /// <summary>
        /// Host and MacIp records.
        /// </summary>
        private void createMetaRecords()
        {
            bool genHost = true;
            bool genMacIp = true;
            DirectoryInfo hostDirInfo = new DirectoryInfo(gov.llnl.wintap.core.etl.shared.Utilities.GetFileStorePath("host"));
            DirectoryInfo macipDirInfo = new DirectoryInfo(gov.llnl.wintap.core.etl.shared.Utilities.GetFileStorePath("macip"));

            if (!hostDirInfo.Exists)
            {
                hostDirInfo.Create();
            }
            if (!macipDirInfo.Exists)
            {
                macipDirInfo.Create();
            }

            foreach (FileInfo hostFile in (hostDirInfo.GetFiles()))
            {
                if (hostFile.Name.ToLower().Contains("host"))
                {
                    genHost = false;
                }
            }
            foreach (FileInfo macipFile in (macipDirInfo.GetFiles()))
            {
                if (macipFile.Name.ToLower().Contains("macip"))
                {
                    genMacIp = false;
                }
            }

            if (genHost) { HostSerializer.Instance.WriteHostRecord(); }
            if (genMacIp) { HostSerializer.Instance.WriteMacIPRecords(); }
        }

        /// Running external program to do the merging to avoid parquet schema stickiness  
        private bool doMerge()
        {
            DateTime mergeTime = DateTime.UtcNow;
            Merge merger = new Merge();
            bool complete = true;
            foreach (DirectoryInfo sensorDir in cacheDir.GetDirectories())
            {
                if (sensorDir.Name.ToUpper() == "CSV") { continue; }

                try
                {
                    if (sensorDir.Name.ToLower() == "default_sensor")
                    {
                        foreach (DirectoryInfo defaultSensor in sensorDir.GetDirectories())
                        {
                            if (defaultSensor.GetFiles("*.parquet").Length == 0) { continue; }
                            string[] mergeArgs = new string[2];
                            mergeArgs[0] = defaultSensor.FullName;
                            mergeArgs[1] = mergeTime.ToFileTimeUtc().ToString();
                            complete &= merger.Start(mergeArgs);
                        }
                    }
                    else
                    {
                        if (sensorDir.GetFiles("*.parquet").Length == 0) { continue; }
                        string[] mergeArgs = new string[2];
                        mergeArgs[0] = sensorDir.FullName;
                        mergeArgs[1] = mergeTime.ToFileTimeUtc().ToString();
                        complete &= merger.Start(mergeArgs);
                    }

                }
                catch (Exception ex)
                {
                    complete = false;
                    WintapLogger.Log.Append("ERROR RUNNING MERGE: " + ex.Message, LogLevel.Info);
                }
            }
            return complete;
        }

        private void cleanupUnmergedParquet(string path)
        {
            if (path.EndsWith("merged")) { return; }
            DirectoryInfo directoryInfo = new DirectoryInfo(path);
            foreach (FileInfo file in directoryInfo.GetFiles())
            {
                try
                {
                    if (file.FullName.EndsWith("parquet"))
                    {
                        file.Delete();
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append("ERROR deleting merged parquet: " + ex.Message, LogLevel.Debug);
                }
            }
        }

        private void HangDetector_Elapsed(object sender, ElapsedEventArgs e)
        {
            WintapLogger.Log.Append("MergeHelper process hang detected", LogLevel.Info);
            Process hungHelper = Process.GetProcessById(mergeHelperPid);
            if (hungHelper.ProcessName.ToLower().StartsWith("mergehelper"))
            {
                hungHelper.Kill();
                WintapLogger.Log.Append("MergeHelper killed, clearing unmerged parquet only", LogLevel.Info);

                DirectoryInfo parquetDir = new DirectoryInfo(Paths.EsperStagingPath);
                long totalParquetRemoved = 0;
                foreach (DirectoryInfo directory in parquetDir.GetDirectories())
                {
                    if (isProtectedCacheDirectory(directory))
                    {
                        continue;
                    }

                    totalParquetRemoved += deleteParquetFiles(directory.FullName, 0);
                }
                WintapLogger.Log.Append("Total parquet cleared: " + totalParquetRemoved, LogLevel.Info);
            }
        }

        private long deleteParquetFiles(string directoryPath, long fileCount)
        {
            if (isProtectedCacheDirectory(new DirectoryInfo(directoryPath)))
            {
                return fileCount;
            }

            // Delete .parquet files in the current directory.
            var files = Directory.EnumerateFiles(directoryPath, "*.parquet");
            foreach (var file in files)
            {
                try
                {
                    WintapLogger.Log.Append("2 - DELETING FILE: " + file, LogLevel.Info);
                    File.Delete(file);
                    fileCount++;
                }
                catch (Exception e)
                {
                    WintapLogger.Log.Append($"Error while deleting file {file}. Error: {e.Message}", LogLevel.Warn);
                }
            }

            // Recursively call this method for each subdirectory.
            var subdirectories = Directory.GetDirectories(directoryPath);
            foreach (var subdir in subdirectories)
            {
                fileCount = deleteParquetFiles(subdir, fileCount);
            }
            return fileCount;
        }

        private void clearCache()
        {
            if (uploaders.Count > 0)
            {
                foreach (FileInfo fi in cacheDir.GetFiles())
                {
                    deleteFile(fi);
                }
            }
        }

        private void clearRawSensor()
        {
            DirectoryInfo rawSensorDir = new DirectoryInfo(Path.Combine(Paths.ParquetDataPath, "raw_sensor"));
            if (!rawSensorDir.Exists)
            {
                rawSensorDir.Create();
            }
            if (uploaders.Count > 0)
            {
                foreach (FileInfo fi in rawSensorDir.GetFiles("*.parquet", SearchOption.AllDirectories))
                {
                    deleteFile(fi);
                }
            }
        }

        /// <summary>
        /// prevent infinite growth of store/forward parquet cache
        /// </summary>
        private List<RawSensorCacheFile> pruneCache(List<RawSensorCacheFile> rawSensorFiles)
        {
            long maxCacheSizeBytes = etlConfig.RawSensorMaxCacheSizeBytes > 0 ? etlConfig.RawSensorMaxCacheSizeBytes : 256000000;
            TimeSpan protectionWindow = TimeSpan.FromSeconds(Math.Max(0, etlConfig.UploadIntervalSec));
            RawSensorCachePruneResult result = RawSensorCachePruner.Prune(
                rawSensorFiles,
                maxCacheSizeBytes,
                DateTime.UtcNow,
                protectionWindow,
                deletePrunedRawSensorFile);

            bytesOnDisk = result.RetainedBytes;
            if (result.StartingBytes > maxCacheSizeBytes)
            {
                foreach (RawSensorCacheDeletionFailure failure in result.DeletionFailures)
                {
                    WintapLogger.Log.Append($"Could not delete file while pruning cache: {failure.File.FullPath}. Reason: {failure.Exception.Message}", LogLevel.Warn);
                }

                string status = getPruneStatus(result);
                WintapLogger.Log.Append(
                    $"Raw-sensor cache prune: status={status}, limitBytes={maxCacheSizeBytes}, startingBytes={result.StartingBytes}, retainedBytes={result.RetainedBytes}, deletedFiles={result.DeletedFileCount}, deletedBytes={result.DeletedBytes}, alreadyAbsentFiles={result.AlreadyAbsentFileCount}, alreadyAbsentBytes={result.AlreadyAbsentBytes}, protectedFiles={result.ProtectedFileCount}, protectedBytes={result.ProtectedBytes}, deletionFailures={result.DeletionFailureCount}, limitReached={result.LimitReached}, survivingFiles={result.SurvivingFiles.Count}",
                    result.LimitReached ? LogLevel.Info : LogLevel.Warn);
            }

            return result.SurvivingFiles.ToList();
        }

        private RawSensorCacheDeleteOutcome deletePrunedRawSensorFile(string path)
        {
            try
            {
                File.GetAttributes(path);
            }
            catch (FileNotFoundException)
            {
                return RawSensorCacheDeleteOutcome.AlreadyAbsent;
            }
            catch (DirectoryNotFoundException)
            {
                return RawSensorCacheDeleteOutcome.AlreadyAbsent;
            }

            FileInfo file = new FileInfo(path);
            DirectoryInfo parentDirectory = file.Directory;
            file.Delete();
            cleanupEmptyPartitionDirectories(parentDirectory, new DirectoryInfo(Path.Combine(Paths.ParquetDataPath, "raw_sensor")));
            return RawSensorCacheDeleteOutcome.Deleted;
        }

        private string getPruneStatus(RawSensorCachePruneResult result)
        {
            if (result.LimitReached)
            {
                return result.DeletionFailureCount > 0 ? "limit-satisfied-with-deletion-failures" : "limit-satisfied";
            }
            if (result.ProtectedFileCount > 0 && result.DeletionFailureCount > 0)
            {
                return "limit-not-reached-protected-and-deletion-failure";
            }
            if (result.ProtectedFileCount > 0)
            {
                return "limit-not-reached-protected";
            }

            return "limit-not-reached-deletion-failure";
        }

        private void deleteFile(FileInfo fi)
        {
            try
            {
                WintapLogger.Log.Append("1 - DELETING FILE: " + fi.Name, LogLevel.Info);
                fi.Delete();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("ERROR deleting cache file: " + ex.Message, LogLevel.Debug);
                gov.llnl.wintap.core.etl.shared.Utilities.LogEvent(1005, "error deleting cache file: " + ex.Message, EventLogEntryType.Warning);
            }
        }

        private bool tryDeleteUploadedFile(FileInfo fi, string reason)
        {
            if (!fi.Exists)
            {
                return true;
            }

            try
            {
                long fileLength = fi.Length;
                string fileName = fi.FullName;
                DirectoryInfo parentDirectory = fi.Directory;
                fi.Delete();
                WintapLogger.Log.Append($"Deleted file after {reason}: {fileName} ({fileLength} bytes)", LogLevel.Info);
                cleanupEmptyPartitionDirectories(parentDirectory, new DirectoryInfo(Path.Combine(Paths.ParquetDataPath, "raw_sensor")));
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Could not delete file after {reason}: {fi.FullName}. Reason: {ex.Message}", LogLevel.Warn);
                return false;
            }
        }

        private void cleanupEmptyPartitionDirectories(DirectoryInfo startDirectory, DirectoryInfo rawSensorRoot)
        {
            DirectoryInfo currentDirectory = startDirectory;
            while (currentDirectory != null && !pathsEqual(currentDirectory.FullName, rawSensorRoot.FullName))
            {
                try
                {
                    if (!currentDirectory.Exists || currentDirectory.EnumerateFileSystemInfos().Any())
                    {
                        break;
                    }

                    DirectoryInfo parentDirectory = currentDirectory.Parent;
                    currentDirectory.Delete();
                    WintapLogger.Log.Append("Removed empty partition directory: " + currentDirectory.FullName, LogLevel.Info);
                    currentDirectory = parentDirectory;
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append("Could not remove empty partition directory: " + currentDirectory.FullName + " reason: " + ex.Message, LogLevel.Warn);
                    break;
                }
            }
        }

        private List<RawSensorCacheFile> getRawSensorParquetFiles()
        {
            DirectoryInfo rawSensorDir = new DirectoryInfo(Path.Combine(Paths.ParquetDataPath, "raw_sensor"));
            return RawSensorCachePruner.EnumerateFinalizedFiles(rawSensorDir.FullName).ToList();
        }

        private Dictionary<string, string> getUploaderParameters(IUpload uploader)
        {
            return etlConfig.Adapters.First(u => u.Name == uploader.Name).Properties;
        }

        private bool isProtectedCacheDirectory(DirectoryInfo directory)
        {
            return directory.Name.Equals("raw_sensor", StringComparison.OrdinalIgnoreCase)
                || directory.Name.Equals("merged", StringComparison.OrdinalIgnoreCase)
                || directory.Name.Equals("csv", StringComparison.OrdinalIgnoreCase);
        }

        private bool pathsEqual(string leftPath, string rightPath)
        {
            string normalizedLeft = Path.GetFullPath(leftPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string normalizedRight = Path.GetFullPath(rightPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return string.Equals(normalizedLeft, normalizedRight, StringComparison.OrdinalIgnoreCase);
        }

        private long getCurrentCacheDirSize()
        {
            DirectoryInfo rawSensorDir = new DirectoryInfo(Path.Combine(Paths.ParquetDataPath, "raw_sensor"));
            if (!rawSensorDir.Exists)
            {
                return 0;
            }

            long curSize = 0;
            foreach (FileInfo fi in rawSensorDir.GetFiles("*.parquet", SearchOption.AllDirectories))
            {
                curSize += fi.Length;
            }
            return curSize;
        }
    }
}
