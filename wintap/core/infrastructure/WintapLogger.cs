/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.etl.shared;
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using SysEventLogEntryType = System.Diagnostics.EventLogEntryType;

namespace gov.llnl.wintap.core.infrastructure
{
    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN LOGGER (Singleton, implements IWintapLogger)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Super simple and dependency free text file logger.
    /// Implements IWintapLogger for plugin access.
    /// </summary>
    public sealed class WintapLogger : gov.llnl.wintap.IWintapLogger
    {
        private static readonly WintapLogger _instance = new WintapLogger();
        private readonly ComponentLogger _defaultLogger;

        public static WintapLogger Log => _instance;

        private WintapLogger()
        {
            _defaultLogger = LoggerManager.GetLogger(Env.AppName, LogType.Overwrite, LogLevel.Info);
        }

        public void Init() { /* Legacy init kept for compatibility */ }

        // ─── IWintapLogger Implementation ──────────────────────────────────────

        public void Append(string message,
            LogLevel level = LogLevel.Info,
            [CallerMemberName] string member = "",
            [CallerFilePath] string file = "",
            bool alsoToEventLog = false,
            EventLogEntryType? eventLogType = null,
            int eventId = 0)
        {
            // Log to file
            _defaultLogger.Append(message, level, member, file);

            // If requested, also log to the Windows Event Log
            if (alsoToEventLog)
            {
                try
                {
                    // Ensure the event source exists
                    if (!EventLog.SourceExists("Wintap"))
                    {
                        // Note: This requires admin privileges and should ideally be done during installation
                        EventLog.CreateEventSource("Wintap", "Application");
                    }

                    // Convert our API EventLogEntryType to System.Diagnostics.EventLogEntryType
                    var sysEventLogType = eventLogType.HasValue
                        ? (SysEventLogEntryType)(int)eventLogType.Value
                        : MapToEventLogEntryType(level);

                    // Write to the application log with the Wintap source
                    EventLog.WriteEntry("Wintap", message, sysEventLogType, eventId);
                }
                catch (Exception ex)
                {
                    // If event logging fails, log that failure to the file log
                    _defaultLogger.Append(
                        $"Failed to write to Event Log: {ex.Message}",
                        LogLevel.Error,
                        member,
                        file);
                }
            }
        }

        public void Close()
        {
            _defaultLogger.Close();
        }

        public LogLevel Verbosity
        {
            get => _defaultLogger.Verbosity;
            set => _defaultLogger.Verbosity = value;
        }

        public string LogName => Env.AppName;

        // ─── Helper Methods ────────────────────────────────────────────────────

        private SysEventLogEntryType MapToEventLogEntryType(LogLevel level)
        {
            return level switch
            {
                LogLevel.Fatal => SysEventLogEntryType.Error,
                LogLevel.Error => SysEventLogEntryType.Error,
                LogLevel.Warn => SysEventLogEntryType.Warning,
                LogLevel.Info => SysEventLogEntryType.Information,
                _ => SysEventLogEntryType.Information,
            };
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPONENT LOGGER (Actual logging implementation)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// The core logging implementation.
    /// Can be used to create separate log files for different components.
    /// </summary>
    public class ComponentLogger
    {
        private readonly ConcurrentQueue<LogEntry> _pendingEntries;
        private readonly BackgroundWorker _loggingThread;
        private readonly ManualResetEventSlim _loggingStopped = new(false);
        private readonly object _lifecycleLock = new();

        private readonly string _logPath;
        private readonly StreamWriter _logWriter;
        private LogLevel _verbosity;
        private readonly int _maxSize;
        private volatile bool _logIsOpen;

        public string LogName { get; }

        public LogLevel Verbosity
        {
            get => _verbosity;
            set => _verbosity = value;
        }

        public ComponentLogger(string logName, LogType logType = LogType.Overwrite, LogLevel verbosity = LogLevel.Info, int maxSize = 3000000)
            : this(logName, logType, verbosity, maxSize, null)
        {
        }

        internal ComponentLogger(string logName, LogType logType, LogLevel verbosity, int maxSize, string logDirectory)
        {
            LogName = logName;
            _verbosity = verbosity;
            _maxSize = maxSize;
            logDirectory ??= Paths.LogDataPath;
            Directory.CreateDirectory(logDirectory);
            _logPath = Path.Combine(logDirectory, logName + ".log");

            _pendingEntries = new ConcurrentQueue<LogEntry>();

            switch (logType)
            {
                case LogType.Append:
                    _logWriter = new StreamWriter(File.Open(_logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite));
                    break;
                case LogType.Archive:
                    if (File.Exists(_logPath))
                    {
                        string archiveName = _logPath + DateTime.Now.ToString("yyyyMMddHHmmss") + ".log";
                        File.Move(_logPath, archiveName);
                    }
                    _logWriter = new StreamWriter(File.Open(_logPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite));
                    break;
                default:
                    _logWriter = new StreamWriter(File.Open(_logPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite));
                    break;
            }

            _logIsOpen = true;
            _logWriter.WriteLine($"Start of log for: {LogName} version:{System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString()} at {DateTime.Now}");
            _logWriter.Flush();

            _loggingThread = new BackgroundWorker();
            _loggingThread.DoWork += LoggingThread_DoWork;
            _loggingThread.RunWorkerAsync();
        }

        private LogLevel GetConfiguredLogLevel()
        {
            string configLevel = Properties.Settings.Default.LoggingLevel;

            return configLevel.ToLower() switch
            {
                "debug" => LogLevel.Debug,
                "trace" => LogLevel.Trace,
                "info" => LogLevel.Info,
                "warn" => LogLevel.Warn,
                "error" => LogLevel.Error,
                "fatal" => LogLevel.Fatal,
                _ => LogLevel.Info // Default to Info if not recognized
            };
        }

        public void Append(string message, LogLevel level = LogLevel.Info,
            [CallerMemberName] string member = "",
            [CallerFilePath] string file = "")
        {
            if ((int)level < (int)_verbosity) return;

            var logEntry = new LogEntry
            {
                Entry = message,
                Time = DateTime.Now,
                Level = level,
                CallerInfo = $"{Path.GetFileNameWithoutExtension(file)}.{member}"
            };

            lock (_lifecycleLock)
            {
                if (!_logIsOpen) return;
                _pendingEntries.Enqueue(logEntry);
            }
        }

        public void Close()
        {
            lock (_lifecycleLock)
            {
                if (!_logIsOpen) return;
                _logIsOpen = false;
            }
            _loggingStopped.Wait();
            _logWriter.WriteLine("END OF LOG");
            _logWriter.Flush();
            _logWriter.Close();
            _loggingStopped.Dispose();
        }

        private void LoggingThread_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                // Close switches off new steady-state waits, but every entry
                // already accepted by Append must reach disk before the writer
                // is closed.
                while (_logIsOpen || !_pendingEntries.IsEmpty)
                {
                    bool wrote = false;
                    while (_pendingEntries.TryDequeue(out var entry))
                    {
                        string logLine = $"{entry.Time} [{entry.Level.ToString()}]  [{entry.CallerInfo}]:   {entry.Entry}";
                        _logWriter.WriteLine(logLine);
                        wrote = true;
                    }

                    if (wrote)
                    {
                        _logWriter.Flush();
                    }
                    else if (_logIsOpen)
                    {
                        Thread.Sleep(200);
                    }
                }
            }
            finally
            {
                _loggingStopped.Set();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOGGER MANAGER (Factory for component loggers)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Logger manager for components to get dedicated loggers.
    /// </summary>
    public static class LoggerManager
    {
        private static readonly ConcurrentDictionary<string, ComponentLogger> _loggers = new();

        public static ComponentLogger GetLogger(string componentName,
            LogType logType = LogType.Overwrite, LogLevel verbosity = LogLevel.Info, int maxSize = 3000000)
        {
            return _loggers.GetOrAdd(componentName, name =>
                new ComponentLogger(name, logType, verbosity, maxSize));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SUPPORTING TYPES
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Log type enum for file handling behavior.
    /// </summary>
    public enum LogType
    {
        Overwrite,
        Append,
        Archive
    }

    /// <summary>
    /// Internal log entry representation.
    /// </summary>
    internal class LogEntry
    {
        public DateTime Time { get; set; }
        public string Entry { get; set; }
        public LogLevel Level { get; set; }
        public string CallerInfo { get; set; }
    }
}
