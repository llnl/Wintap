/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using DuckDB.NET.Data;  // For direct database access
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;  // For StateManager
using gov.llnl.wintap.platform.windows.collect.etw.helpers;
using gov.llnl.wintap.platform.windows.models;  // For ProcessHash
using System;
using System.Collections.Generic;
using System.IO;

namespace WintapCoreSvcMgr.Database
{

    public class BackupDatabaseManager : IDisposable
    {

        // ProcessHash for consistent PidHash generation
        private readonly ProcessHash _processHash;
        private Guid _fallbackAgentId;

        private bool _disposed = false;

        // File path
        private string RECOVERY_DB_PATH;
        private string MAIN_DB_PATH;
        
        private string DB_PATH;
        private DuckDBConnection _connection;

        // In-memory cache for fast PID-to-PidHash resolution
        private readonly Dictionary<int, string> _activePidToPidHash = new();
        private readonly object _cacheLock = new object();

        public enum DatabaseTargetEnum { MAIN, RECOVERY }

        public BackupDatabaseManager(DatabaseTargetEnum target)
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            RECOVERY_DB_PATH = Path.Combine(programData, "Wintap", "ProcessTree", ProcessIdentity.RecoveryStoreFileName);
            MAIN_DB_PATH = Path.Combine(programData, "Wintap", "ProcessTree", ProcessIdentity.MainStoreFileName);


            DB_PATH = MAIN_DB_PATH;
            if (target == DatabaseTargetEnum.RECOVERY)
            {
                DB_PATH = RECOVERY_DB_PATH;
            }
            _ = StateManager.AgentId; // This triggers StateManager initialization

            _processHash = new ProcessHash();

            InitializeDatabase();

            LogInfo("BackupDatabaseManager initialized for WintapCoreSvcMgr.exe");
        }

        public void DeleteMainDb()
        {
            FileInfo mainDbInfo = new FileInfo(MAIN_DB_PATH);
            if (mainDbInfo.Exists)
            {
                mainDbInfo.Delete();
            }
        }

        public void DeleteRecoveryDb()
        {
            FileInfo backupDbInfo = new FileInfo(RECOVERY_DB_PATH);
            if (backupDbInfo.Exists)
            {
                _connection.Close();
                _connection.Dispose();
                backupDbInfo.Delete();
            }
        }

        public bool InsertProcessStart(ProcessRecord process)
        {
            try
            {
                // Helper methods
                string EscapeString(string value)
                {
                    if (value == null) return "NULL";
                    return "'" + value.Replace("'", "''") + "'";
                }

                string EscapeDateTime(DateTime dateTime)
                {
                    return "'" + dateTime.ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                }

                var sql = $@"
            INSERT OR REPLACE INTO live_processes (
                pid_hash, parent_pid_hash, process_id, parent_process_id,
                process_name, image_path, command_line, 
                create_time, is_active, source, depth, has_live_descendants,
                user_name
            ) VALUES (
                {EscapeString(process.PidHash)},
                {EscapeString(process.ParentPidHash)},
                {process.ProcessId},
                {process.ParentProcessId},
                {EscapeString(process.ProcessName)},
                {EscapeString(process.ProcessPath)},
                {EscapeString(process.CommandLine)},
                {EscapeDateTime(process.CreateTime)},
                {process.IsActive.ToString().ToLower()},
                {EscapeString(process.Source)},
                {process.Depth},
                {process.HasLiveDescendants.ToString().ToLower()},
                {EscapeString(process.UserName)}
            )";

                using var cmd = new DuckDBCommand(sql, _connection);
                cmd.ExecuteNonQuery();
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Failed to insert process start for {process.PidHash}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Insert boot trace ProcessRecord - INSERT ONLY, never update
        /// Boot trace records are historical one-time events from system startup
        /// </summary>
        public bool InsertBootTraceRecord(gov.llnl.wintap.platform.windows.models.ProcessRecord process)
        {
            try
            {

                string EscapeString(string value)
                {
                    if (value == null) return "NULL";
                    return "'" + value.Replace("'", "''") + "'";
                }

                string EscapeDateTime(DateTime dateTime)
                {
                    return "'" + dateTime.ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                }

                var sql = $@"
        INSERT INTO live_processes (
            pid_hash, parent_pid_hash, process_id, parent_process_id,
            process_name, image_path, command_line, 
            create_time, is_active, source, depth, has_live_descendants,
            user_name
        ) VALUES (
            {EscapeString(process.PidHash)},
            {EscapeString(process.ParentPidHash)},
            {process.ProcessId},
            {process.ParentProcessId},
            {EscapeString(process.ProcessName)},
            {EscapeString(process.ProcessPath)},
            {EscapeString(process.CommandLine)},
            {EscapeDateTime(process.CreateTime)},
            {(process.IsActive ? 1 : 0)},
            {EscapeString(process.Source)},
            {process.Depth},
            {(process.HasLiveDescendants ? 1 : 0)},
            {EscapeString(process.UserName)}
        )";

                using var cmd = new DuckDBCommand(sql, _connection);
                cmd.ExecuteNonQuery();

                LogInfo($"Inserted boot trace ProcessRecord: PID {process.ProcessId}, PidHash {process.PidHash}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Failed to insert boot trace ProcessRecord {process.ProcessPath} {process.PidHash}: {ex.Message}");

                // If this fails due to duplicate PidHash, that indicates a logic error in boot trace processing
                if (ex.Message.Contains("UNIQUE constraint failed") || ex.Message.Contains("duplicate"))
                {
                    LogError($"DUPLICATE PidHash detected during boot trace insert: {process.PidHash} - this indicates a processing error");
                }

                return false;
            }
        }

        // Helper method from ProcessTreeDatabase.cs
        private void ExecuteNonQuery(string sql)
        {
            using var cmd = new DuckDBCommand(sql, _connection);
            cmd.ExecuteNonQuery();
        }

        private void InitializeDatabase()
        {
            try
            {
                _connection = new DuckDBConnection($"Data Source={DB_PATH}");
                _connection.Open();

                var createProcessTable = @"
        CREATE TABLE IF NOT EXISTS live_processes (
            pid_hash VARCHAR PRIMARY KEY,
            parent_pid_hash VARCHAR,
            process_id INTEGER,
            parent_process_id INTEGER,
            unique_process_key UBIGINT,
            process_name VARCHAR,
            image_path VARCHAR,
            command_line VARCHAR,
            create_time TIMESTAMP,
            exit_time TIMESTAMP,
            exit_code INTEGER,
            is_active BOOLEAN,
            source VARCHAR,
            depth INTEGER,
            has_live_descendants BOOLEAN,
            user_name VARCHAR,
            md5_hash VARCHAR,
            sha2_hash VARCHAR,
            -- FOREIGN KEY (parent_pid_hash) REFERENCES live_processes(pid_hash)
        );";

                var createIndexes = @"
        CREATE INDEX IF NOT EXISTS idx_parent_pid_hash ON live_processes(parent_pid_hash);
        CREATE INDEX IF NOT EXISTS idx_process_id ON live_processes(process_id);
        CREATE INDEX IF NOT EXISTS idx_process_name ON live_processes(process_name);
        CREATE INDEX IF NOT EXISTS idx_is_active ON live_processes(is_active);
        CREATE INDEX IF NOT EXISTS idx_has_live_descendants ON live_processes(has_live_descendants);
        CREATE INDEX IF NOT EXISTS idx_create_time ON live_processes(create_time);
        CREATE INDEX IF NOT EXISTS idx_pid_active_createtime ON live_processes(process_id, is_active, create_time DESC);";

                ExecuteNonQuery(createProcessTable);
                ExecuteNonQuery(createIndexes);
                LogInfo($"Backup database initialized successfully for: {DB_PATH}");
            }
            catch (Exception ex)
            {
                LogError($"Failed to initialize backup database: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Synchronize databases (copy recovery.duckdb → main-trace.duckdb)
        ///
        /// </summary>
        public DatabaseOperationResult SynchronizeDatabases()
        {
            try
            {
                LogInfo("Starting database synchronization (backup → main)");

                if (!File.Exists(RECOVERY_DB_PATH))
                {
                    LogError($"Backup database not found: {RECOVERY_DB_PATH}");
                    return DatabaseOperationResult.Failure("Backup database not found");
                }

                // Ensure main database directory exists
                var mainDbDir = Path.GetDirectoryName(MAIN_DB_PATH);
                if (!Directory.Exists(mainDbDir))
                {
                    Directory.CreateDirectory(mainDbDir);
                }

                // Close backup database connection temporarily for file copy
                _connection.Close();
                _connection.Dispose();

                // Copy backup database to main database
                File.Copy(RECOVERY_DB_PATH, MAIN_DB_PATH, overwrite: true);

                // Copy WAL file if it exists
                var backupWalPath = RECOVERY_DB_PATH + ".wal";
                var mainWalPath = MAIN_DB_PATH + ".wal";
                if (File.Exists(backupWalPath))
                {
                    File.Copy(backupWalPath, mainWalPath, overwrite: true);
                }

                // reioe backup database
                _connection.Open();

                LogInfo("Database synchronization completed successfully");

                return DatabaseOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                LogError($"Failed to synchronize databases: {ex.Message}");
                return DatabaseOperationResult.Failure(ex.Message);
            }
        }

        /// <summary>
        /// this method determines whether or not the Recovery DB has a valid root of the process tree,
        /// meaning that the existence of the essential boot process tree (ntoskrnl -> smss -> etc) is within a reasonable time after boot
        /// </summary>
        /// <returns>True if Recovery DB contains valid boot process tree, false otherwise</returns>
        internal bool DuckHasValidRoot()
        {
            
            try
            {
                var uptimeMs = Environment.TickCount64;
                var uptime = TimeSpan.FromMilliseconds(uptimeMs);
                var bootTime = DateTime.Now.Subtract(uptime);
                bootTime = bootTime.AddSeconds(-2).ToUniversalTime(); // loosen up the precision - TickCount64 is actually a few ticks AFTER ntoskrnl start 

                // Define reasonable timeframe for system boot
                var bootProcessWindowEnd = bootTime.AddSeconds(60).ToUniversalTime();

                WintapLogger.Log.Append($"!! Looking for SYSTEM process between boot start: {bootTime} and boot windows end: {bootProcessWindowEnd}", LogLevel.Info);

                using (var connection = new DuckDBConnection($"Data Source={RECOVERY_DB_PATH}"))
                {
                    connection.Open();

                    // Essential Windows boot processes that should exist early in boot sequence
                    var essentialProcesses = new[]
                    {
                "System",           // PID 4 - Windows System process
                "smss.exe",         // Session Manager Subsystem
                "csrss.exe",        // Client/Server Runtime Subsystem  
                "wininit.exe",      // Windows Start-Up Application
                "winlogon.exe",     // Windows Logon Application
                "services.exe",     // Service Control Manager
                "lsass.exe"         // Local Security Authority Subsystem Service
            };

                    // Check if we have essential boot processes within reasonable time after boot
                    foreach (var processName in essentialProcesses)
                    {
                        var sql = $@"
                    SELECT COUNT(*) 
                    FROM live_processes 
                    WHERE LOWER(process_name) = LOWER('{processName}')
                    AND create_time >= '{bootTime:yyyy-MM-dd HH:mm:ss.fff}' 
                    AND create_time <= '{bootProcessWindowEnd:yyyy-MM-dd HH:mm:ss.fff}'";

                        using var cmd = new DuckDBCommand(sql, connection);

                        WintapLogger.Log.Append($"verifying boot process with: {cmd.CommandText}", LogLevel.Info);

                        var count = Convert.ToInt32(cmd.ExecuteScalar());

                        if (count == 0)
                        {
                            WintapLogger.Log.Append($"Essential boot process '{processName}' not found in Recovery DB within boot window", LogLevel.Warn);
                            return false;
                        }
                    }

                    // Additional validation: Check that we have System process (PID 4) as root
                    var systemProcessSql = $@"
                SELECT COUNT(*) 
                FROM live_processes 
                WHERE process_id = 4 
                AND LOWER(process_name) = 'system'
                AND create_time >= '{bootTime:yyyy-MM-dd HH:mm:ss.fff}' 
                AND create_time <= '{bootProcessWindowEnd:yyyy-MM-dd HH:mm:ss.fff}'";

                    using var systemCmd = new DuckDBCommand(systemProcessSql, connection);

                    var systemCount = Convert.ToInt32(systemCmd.ExecuteScalar());

                    if (systemCount == 0)
                    {
                        WintapLogger.Log.Append("System process (PID 4) not found in Recovery DB - invalid root", LogLevel.Warn);
                        return false;
                    }

                    // Validate process hierarchy: Check that key processes have expected parent relationships
                    var hierarchyValidationSql = $@"
                SELECT 
                    p.process_name,
                    p.process_id,
                    p.parent_process_id,
                    parent.process_name as parent_name
                FROM live_processes p
                LEFT JOIN live_processes parent ON p.parent_process_id = parent.process_id 
                WHERE p.process_name IN ('smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe')
                AND p.create_time >= '{bootTime:yyyy-MM-dd HH:mm:ss.fff}' 
                AND p.create_time <= '{bootProcessWindowEnd:yyyy-MM-dd HH:mm:ss.fff}'";

                    using var hierarchyCmd = new DuckDBCommand(hierarchyValidationSql, connection);

                    using var reader = hierarchyCmd.ExecuteReader();
                    var processHierarchyFound = false;

                    while (reader.Read())
                    {
                        processHierarchyFound = true;
                        var processName = reader["process_name"]?.ToString();
                        var parentName = reader["parent_name"]?.ToString();

                        WintapLogger.Log.Append($"Found boot process: {processName} -> Parent: {parentName}", LogLevel.Debug);
                    }

                    if (!processHierarchyFound)
                    {
                        WintapLogger.Log.Append("No valid process hierarchy found in Recovery DB", LogLevel.Warn);
                        return false;
                    }

                    // Final check: Ensure we have a reasonable number of total processes within boot window
                    // A healthy Windows boot should have dozens of processes started
                    var totalProcessesSql = $@"
                SELECT COUNT(*) 
                FROM live_processes 
                WHERE create_time >= '{bootTime:yyyy-MM-dd HH:mm:ss.fff}' 
                AND create_time <= '{bootProcessWindowEnd:yyyy-MM-dd HH:mm:ss.fff}'
                AND source NOT IN ('boot_trace', 'mini_trace')";

                    using var totalCmd = new DuckDBCommand(totalProcessesSql, connection);

                    var totalProcesses = Convert.ToInt32(totalCmd.ExecuteScalar());

                    // We should have at least 20 processes during a normal Windows boot sequence
                    if (totalProcesses < 20)
                    {
                        WintapLogger.Log.Append($"Insufficient boot processes in Recovery DB ({totalProcesses} found, minimum 20 expected)", LogLevel.Warn);
                        return false;
                    }

                    WintapLogger.Log.Append($"Recovery DB has valid root: {totalProcesses} boot processes found, all essential processes present", LogLevel.Info);
                    return true;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error validating Recovery DB root: {ex.Message}", LogLevel.Error);
                return false;
            }
        }

        private void LogInfo(string message)
        {
            WintapLogger.Log.Append(message, gov.llnl.wintap.core.infrastructure.LogLevel.Info);
        }

        private void LogWarning(string message)
        {
            WintapLogger.Log.Append(message, gov.llnl.wintap.core.infrastructure.LogLevel.Warn);
        }

        private void LogError(string message)
        {
            WintapLogger.Log.Append(message, gov.llnl.wintap.core.infrastructure.LogLevel.Error);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
            }
        }

        internal DateTime GetLatestRecord()
        {
            var countSql = "SELECT create_time FROM live_processes ORDER BY create_time DESC LIMIT 1";
            using var countCmd = new DuckDBCommand(countSql, _connection);

            DateTime mostRecentProcessTime = DateTime.SpecifyKind(DateTime.Parse(countCmd.ExecuteScalar().ToString()), DateTimeKind.Utc);

            Console.WriteLine($"Most recent process create time: {mostRecentProcessTime.ToUniversalTime()}");
            return mostRecentProcessTime.ToUniversalTime();
        }

        internal string GetParentPidHash(int pid, string processName)
        {
            var countSql = $"SELECT pid_hash FROM live_processes WHERE pid = {pid} AND process_name = {processName} ORDER BY create_time DESC LIMIT 1";
            using var countCmd = new DuckDBCommand(countSql, _connection);
            string parentPidHash = countCmd.ExecuteScalar().ToString();
            return parentPidHash;
        }
    }

    /// <summary>
    /// Status information for mini-trace ETW session
    /// </summary>
    public class MiniTraceSessionStatus
    {
        public bool IsRunning { get; set; }
        public bool ETLFileExists { get; set; }
        public DateTime? LastETLModified { get; set; }
        public long ETLFileSizeBytes { get; set; }
        public double ETLFileSizeMB { get; set; }
        public DateTime CheckedAt { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Status information for backup database
    /// </summary>
    public class BackupDatabaseStatus
    {
        public bool IsHealthy { get; set; }
        public bool DatabaseExists { get; set; }
        public string DatabasePath { get; set; }
        public int TotalProcesses { get; set; }
        public int ActiveProcesses { get; set; }
        public double DatabaseSizeMB { get; set; }
        public DateTime? LastModified { get; set; }
        public DateTime CheckedAt { get; set; }
        public string HealthDetails { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Simple class for JSON deserialization of wintapstate.json
    /// </summary>
    public class WintapState
    {
        public string AgentId { get; set; }
    }
}
