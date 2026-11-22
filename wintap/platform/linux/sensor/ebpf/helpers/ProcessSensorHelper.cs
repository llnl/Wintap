using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Shared helper methods for process sensors
    /// </summary>
    internal static class ProcessSensorHelper
    {
        /// <summary>
        /// Select a basename from executable-path evidence, otherwise observed comm.
        /// A procfs executable alias is not an executable name. Command lines must
        /// use the separate command-line helper, not this path-only method.
        /// </summary>
        public static string ExtractProcessName(string path, string fallback = "unknown")
        {
            string nameFallback = string.IsNullOrWhiteSpace(fallback) ? "unknown" : fallback.Trim();
            if (string.IsNullOrWhiteSpace(path) || IsProcExecutableAlias(path) || IsUnknownPath(path))
                return nameFallback;

            try
            {
                path = path.Trim();
                if (path.EndsWith(" (deleted)", StringComparison.Ordinal))
                    path = path.Substring(0, path.Length - " (deleted)".Length);

                string fileName = Path.GetFileName(path);
                return string.IsNullOrWhiteSpace(fileName) ? nameFallback : fileName;
            }
            catch
            {
                return nameFallback;
            }
        }

        private static bool IsProcExecutableAlias(string path) =>
            Regex.IsMatch(path.Trim(), @"^/proc/(?:[0-9]+|self|thread-self)/(?:task/[0-9]+/)?exe$");

        private static bool IsUnknownPath(string path) =>
            Regex.IsMatch(path.Trim(), @"^unknown(?:-[0-9]+)?$");

        internal static string ResolveExecutablePath(string path, Func<string, string> readLinkTarget = null)
        {
            if (string.IsNullOrWhiteSpace(path) || IsUnknownPath(path)) return null;
            return IsProcExecutableAlias(path) ? ReadExecutableLink(path, readLinkTarget) : path;
        }

        internal static string ReadExecutableLink(string path, Func<string, string> readLinkTarget = null)
        {
            try
            {
                // Readlink does not require the target to still exist (deleted images).
                string target = readLinkTarget != null ? readLinkTarget(path) : new FileInfo(path).LinkTarget;
                return !string.IsNullOrWhiteSpace(target) && Path.IsPathRooted(target) &&
                    !IsProcExecutableAlias(target) ? target : null;
            }
            catch
            {
                // Missing process, exit race, permission denial, or non-link.
                return null;
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
            string arguments = null,
            string commandLineSource = null,
            string commandLineCaptureStatus = null)
        {
            var processObj = new WintapMessage.ProcessObject
            {
                PID = pid,
                ParentPID = ppid,
                Name = NormalizeFallback(name),
                Path = string.IsNullOrWhiteSpace(path) ? "unknown-5" : path,
                CommandLine = commandLine ?? "",
                CommandLineSource = commandLineSource,
                CommandLineCaptureStatus = commandLineCaptureStatus,
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
            return ReadExecutableLink($"/proc/{pid}/exe") ?? ResolveExecutablePath(fallback);
        }
    }
}
