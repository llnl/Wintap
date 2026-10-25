using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Emits Refresh process events for processes that already existed before the
    /// Linux eBPF process sensors started. This provides the same stream-rundown
    /// behavior as the Windows process startup inventory.
    /// </summary>
    internal class ProcessRundownSensor : BaseSensor
    {
        private readonly ProcessHash pidHashGenerator;

        internal ProcessRundownSensor()
        {
            SensorName = "ProcessRundown";
            pidHashGenerator = new ProcessHash();
        }

        public override bool Start()
        {
            try
            {
                WintapLogger.Log.Append("Linux process rundown starting", LogLevel.Info);

                List<ProcReader.ProcessInfo> processes = ProcReader.EnumerateProcesses()
                    .Where(IsUsableProcess)
                    .OrderBy(p => p.StartTimeUtc == default ? DateTime.MinValue : p.StartTimeUtc)
                    .ThenBy(p => p.Pid)
                    .ToList();

                int sent = 0;
                foreach (ProcReader.ProcessInfo processInfo in processes)
                {
                    WintapMessage message = CreateRefreshMessage(processInfo);
                    if (message == null)
                    {
                        continue;
                    }

                    EventChannel.Send(message);
                    sent++;
                }

                WintapLogger.Log.Append($"Linux process rundown complete. Refreshed {sent} existing processes from /proc", LogLevel.Info);
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Linux process rundown failed: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"Linux process rundown stack trace: {ex.StackTrace}", LogLevel.Debug);
                return false;
            }
        }

        internal static bool IsUsableProcess(ProcReader.ProcessInfo processInfo)
        {
            if (!processInfo.Exists)
            {
                return false;
            }

            return processInfo.Pid <= int.MaxValue;
        }

        internal WintapMessage CreateRefreshMessage(ProcReader.ProcessInfo processInfo)
        {
            if (!IsUsableProcess(processInfo) || processInfo.StartTimeUtc == default)
            {
                // Snapshot time is not process birth; do not fabricate an instance.
                return null;
            }
            DateTime startTimeUtc = processInfo.StartTimeUtc.ToUniversalTime();

            int pid = (int)processInfo.Pid;
            string commandLine = processInfo.CommandLine ?? string.Empty;
            string executablePath = ResolveExecutablePath(processInfo.ExecutablePath);
            if (string.IsNullOrWhiteSpace(executablePath))
            {
                executablePath = !string.IsNullOrWhiteSpace(commandLine)
                    ? ProcessSensorHelper.ExtractPathFromCmdline(commandLine)
                    : processInfo.Name;
            }

            string processName = ProcessSensorHelper.ExtractProcessName(executablePath, processInfo.Name);
            if (string.IsNullOrWhiteSpace(processName) || processName.StartsWith("unknown", StringComparison.OrdinalIgnoreCase))
            {
                processName = ProcessSensorHelper.ExtractProcessNameFromCmdline(commandLine, processInfo.Name);
            }

            var message = new WintapMessage(startTimeUtc, pid, WintapMessage.MessageTypeEnum.Process)
            {
                ActivityType = WintapMessage.ActivityTypeEnum.Refresh,
                PidHash = pidHashGenerator.GenPidHash(pid, startTimeUtc.ToFileTimeUtc()),
                ProcessName = processName,
                ProcessPath = executablePath
            };

            message.Process = ProcessSensorHelper.CreateProcessObject(
                pid: pid,
                ppid: processInfo.PPid,
                name: processName,
                path: executablePath,
                commandLine: commandLine,
                user: processInfo.Username ?? processInfo.Uid.ToString(),
                arguments: BuildArguments(processInfo)
            );

            ProcessSensorHelper.EnrichParentProcess(message, pidHashGenerator);

            return message;
        }

        private static string ResolveExecutablePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            try
            {
                if (path.StartsWith("/proc/", StringComparison.OrdinalIgnoreCase))
                {
                    var fileInfo = new FileInfo(path);
                    var linkTarget = fileInfo.ResolveLinkTarget(returnFinalTarget: true);
                    if (linkTarget != null)
                    {
                        return linkTarget.FullName;
                    }
                }
            }
            catch
            {
                // Process may have exited or access can be denied.
            }

            return path;
        }

        private static string BuildArguments(ProcReader.ProcessInfo processInfo)
        {
            List<string> args = new List<string>();

            if (!string.IsNullOrWhiteSpace(processInfo.Cwd))
            {
                args.Add("CWD=" + processInfo.Cwd);
            }

            if (!string.IsNullOrWhiteSpace(processInfo.Home))
            {
                args.Add("HOME=" + processInfo.Home);
            }

            if (!string.IsNullOrWhiteSpace(processInfo.Shell))
            {
                args.Add("SHELL=" + processInfo.Shell);
            }

            return args.Count == 0 ? null : string.Join(" ", args);
        }
    }
}
