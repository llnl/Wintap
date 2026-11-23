using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.Collections.Generic;
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
        private readonly Func<IEnumerable<ProcReader.ProcessInfo>> enumerateProcesses;
        private readonly Action<WintapMessage> emit;
        private readonly Func<DateTime> utcNow;
        private readonly Action<string, LogLevel> log;
        private readonly ProcessRefreshSchedule refreshSchedule;
        private PeriodicProcessRefreshScheduler refreshScheduler;

        internal ProcessRundownSensor(
            Func<IEnumerable<ProcReader.ProcessInfo>> enumerateProcesses = null,
            Action<WintapMessage> emit = null,
            Func<DateTime> utcNow = null,
            ProcessRefreshSchedule refreshSchedule = null,
            Action<string, LogLevel> log = null)
        {
            SensorName = "ProcessRundown";
            pidHashGenerator = new ProcessHash();
            this.enumerateProcesses = enumerateProcesses ?? ProcReader.EnumerateProcesses;
            this.emit = emit ?? EventChannel.Send;
            this.utcNow = utcNow ?? (() => DateTime.UtcNow);
            this.refreshSchedule = refreshSchedule;
            this.log = log ?? ((message, level) => WintapLogger.Log.Append(message, level));
        }

        public override bool Start()
        {
            try
            {
                bool started = RunSnapshot("startup rundown");
                if (!started)
                    return false;

                refreshScheduler = new PeriodicProcessRefreshScheduler(
                    refreshSchedule ?? ProcessRefreshSchedule.FromConfig(),
                    () => RunSnapshot("periodic inventory"),
                    utcNow,
                    log);
                refreshScheduler.Start();
                return started;
            }
            catch (Exception ex)
            {
                log($"Linux process rundown failed: {ex.Message}", LogLevel.Error);
                log($"Linux process rundown stack trace: {ex.StackTrace}", LogLevel.Debug);
                return false;
            }
        }

        public override void Stop()
        {
            refreshScheduler?.Dispose();
            refreshScheduler = null;
        }

        internal bool RunSnapshot(string reason)
        {
            try
            {
                DateTime observationUtc = utcNow().ToUniversalTime();
                log($"Linux process {reason} starting at {observationUtc:O}", LogLevel.Info);
                List<ProcReader.ProcessInfo> processes = enumerateProcesses()
                    .Where(IsUsableProcess)
                    .OrderBy(p => p.StartTimeUtc == default ? DateTime.MinValue : p.StartTimeUtc)
                    .ThenBy(p => p.Pid)
                    .ToList();

                int sent = 0;
                foreach (ProcReader.ProcessInfo processInfo in processes)
                {
                    WintapMessage message = CreateRefreshMessage(processInfo, observationUtc);
                    if (message == null)
                        continue;

                    emit(message);
                    sent++;
                }

                log($"Linux process {reason} complete. Refreshed {sent} existing processes from /proc; observed_at={observationUtc:O}", LogLevel.Info);
                return true;
            }
            catch (Exception ex)
            {
                log($"Linux process {reason} failed: {ex.Message}", LogLevel.Error);
                log($"Linux process {reason} stack trace: {ex.StackTrace}", LogLevel.Debug);
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
            return CreateRefreshMessage(processInfo, utcNow().ToUniversalTime());
        }

        internal WintapMessage CreateRefreshMessage(ProcReader.ProcessInfo processInfo, DateTime observationUtc)
        {
            if (!IsUsableProcess(processInfo) || processInfo.StartTimeUtc == default)
            {
                // Snapshot time is not process birth; do not fabricate an instance.
                return null;
            }
            DateTime startTimeUtc = processInfo.StartTimeUtc.ToUniversalTime();

            int pid = (int)processInfo.Pid;
            string commandLine = processInfo.CommandLine ?? string.Empty;
            string resolvedExecutablePath = ProcessSensorHelper.ResolveExecutablePath(processInfo.ExecutablePath);
            string executablePath = resolvedExecutablePath ?? "unknown-5";
            string processName = ProcessSensorHelper.ExtractProcessName(executablePath, processInfo.Name);

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
                arguments: BuildArguments(processInfo),
                commandLineSource: processInfo.CommandLineSource,
                commandLineCaptureStatus: processInfo.CommandLineCaptureStatus
            );
            message.Process.ExecutablePathSource = resolvedExecutablePath != null
                ? "procfs-exe" : "unavailable";
            message.Process.ObservationTimeFileTimeUtc = observationUtc.ToUniversalTime().ToFileTimeUtc();
            message.Process.ObservationClockDomain = "userspace-utc";
            message.Process.ObservationRunId = RuntimeCapabilities.GetCaptureRunId();

            ProcessSensorHelper.EnrichParentProcess(message, pidHashGenerator);

            return message;
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
