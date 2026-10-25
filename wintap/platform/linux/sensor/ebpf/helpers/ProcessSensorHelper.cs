using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.IO;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Shared helper methods for process sensors
    /// </summary>
    internal static class ProcessSensorHelper
    {
        /// <summary>
        /// Extract just the process name from a full path
        /// Examples:
        ///   "/usr/bin/bash" → "bash"
        ///   "/bin/sshd" → "sshd"
        ///   "bash" → "bash"
        ///   "bash -c ls" → "bash" (extracts first word if looks like cmdline)
        /// 
        /// Handles empty strings, command lines, and malformed paths
        /// </summary>
        public static string ExtractProcessName(string path, string fallback = "unknown-4")
        {
            // Handle null or empty (whitespace counts as empty too)
            if (string.IsNullOrWhiteSpace(path))
                return NormalizeFallback(fallback);

            try
            {
                path = path.Trim();
                
                // If path contains spaces, it might be a command line - extract first word
                if (path.Contains(" "))
                {
                    string firstArg = path.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
                    path = firstArg;
                }
                
                // Get the filename from the path (handles both /usr/bin/bash and bash)
                string fileName = Path.GetFileName(path);
                
                // If GetFileName returned empty
                if (string.IsNullOrWhiteSpace(fileName))
                    return NormalizeFallback(fallback);
                
                // Final check - return fileName if valid, otherwise fallback
                return string.IsNullOrWhiteSpace(fileName) ? NormalizeFallback(fallback) : fileName;
            }
            catch
            {
                return NormalizeFallback(fallback);
            }
        }

        /// <summary>
        /// Normalize fallback to ensure it's never empty
        /// </summary>
        private static string NormalizeFallback(string fallback)
        {
            return string.IsNullOrWhiteSpace(fallback) ? "unknown-fallback" : fallback.Trim();
        }

        /// <summary>
        /// Create a ProcessObject for WintapMessage with all required fields
        /// Ensures no fields are null or empty
        /// </summary>
        public static WintapMessage.ProcessObject CreateProcessObject(
            int pid,
            int ppid,
            string name,
            string path,
            string commandLine,
            string user,
            int? exitCode = null,
            string arguments = null)
        {
            var processObj = new WintapMessage.ProcessObject
            {
                PID = pid,
                ParentPID = ppid,
                Name = NormalizeFallback(name),
                Path = string.IsNullOrWhiteSpace(path) ? "unknown-5" : path,
                CommandLine = commandLine ?? "",
                User = NormalizeFallback(user),
                UniqueProcessKey = "unknown-key"
            };

            if (exitCode.HasValue)
                processObj.ExitCode = exitCode.Value;

            if (!string.IsNullOrEmpty(arguments))
                processObj.Arguments = arguments;

            return processObj;
        }

        public static void EnrichParentProcess(WintapMessage message, ProcessHash pidHashGenerator)
        {
            if (message?.Process == null || message.Process.ParentPID <= 0 || pidHashGenerator == null)
            {
                return;
            }

            // Don't clobber an already-attributed parent hash.
            if (!string.IsNullOrWhiteSpace(message.Process.ParentPidHash))
            {
                return;
            }

            ProcReader.ProcessInfo parentInfo = ProcReader.ReadProcessInfo((uint)message.Process.ParentPID);
            if (!parentInfo.Exists)
            {
                // Leave ParentPidHash unset so EventChannel can still attempt resolver-based parent resolution.
                message.Process.ParentPidHash = "";
                message.Process.ParentProcessName = "Unknown";
                return;
            }

            DateTime parentStartUtc = parentInfo.StartTimeUtc == default
                ? DateTime.FromFileTimeUtc(message.EventTime)
                : parentInfo.StartTimeUtc.ToUniversalTime();

            message.Process.ParentPidHash = pidHashGenerator.GenPidHash(message.Process.ParentPID, parentStartUtc.ToFileTimeUtc());
            message.Process.ParentProcessName = ExtractProcessName(parentInfo.ExecutablePath, parentInfo.Name);

            // Breadcrumb for downstream debugging.
            message.Process.Arguments = string.IsNullOrWhiteSpace(message.Process.Arguments)
                ? "PARENT_HASH_SRC=proc"
                : message.Process.Arguments + " PARENT_HASH_SRC=proc";
        }

        /// <summary>
        /// Extract process name from command line
        /// Example: "bash -c ls" → "bash"
        /// Example: "/usr/bin/bash -c ls" → "bash"
        /// </summary>
        public static string ExtractProcessNameFromCmdline(string cmdline, string fallback = "unknown-6")
        {
            if (string.IsNullOrWhiteSpace(cmdline))
                return NormalizeFallback(fallback);

            try
            {
                // Get first argument (the executable)
                string firstArg = cmdline.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
                
                // Extract just the filename
                return ExtractProcessName(firstArg, fallback);
            }
            catch
            {
                return NormalizeFallback(fallback);
            }
        }

        /// <summary>
        /// Extract full path from command line
        /// Example: "/usr/bin/bash -c ls" → "/usr/bin/bash"
        /// Example: "bash -c ls" → "bash"
        /// </summary>
        public static string ExtractPathFromCmdline(string cmdline, string fallback = "unknown-7")
        {
            if (string.IsNullOrWhiteSpace(cmdline))
                return NormalizeFallback(fallback);

            try
            {
                // Get first argument (the executable path/name)
                string firstArg = cmdline.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
                return string.IsNullOrWhiteSpace(firstArg) ? NormalizeFallback(fallback) : firstArg;
            }
            catch
            {
                return NormalizeFallback(fallback);
            }
        }

        /// <summary>
        /// Try to read executable path from /proc (might still exist briefly during exit)
        /// </summary>
        public static string GetExecutablePath(int pid, string fallback = null)
        {
            try
            {
                string exePath = $"/proc/{pid}/exe";
                if (File.Exists(exePath))
                {
                    var fileInfo = new FileInfo(exePath);
                    return fileInfo.LinkTarget ?? fileInfo.FullName;
                }
            }
            catch
            {
                // Process already gone or permission denied
            }
            return fallback;
        }
    }
}
