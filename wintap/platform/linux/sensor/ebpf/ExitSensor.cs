using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared.helpers;
using gov.llnl.wintap.platform.linux.infrastructure;
using System;
using System.Runtime.InteropServices;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// eBPF-based process exit sensor using sched_process_exit tracepoint
    /// </summary>
    internal class ExitSensor : BaseEbpfSensor
    {
        private ProcessHash _pidHashGenerator;
        private LifecycleShadowWriter shadow;
        private long monotonicOffset;
        private bool retainExitEvidence;
        private long exitEvidenceRetained, exitEvidenceRejected;
        protected override string BpfObjectFileName => "exit_tracer.bpf.o";
        protected override string[] FallbackBpfObjectFileNames => new[] { "exit_tracepoint.bpf.o" };
        protected override string BpfProgramName => "trace_process_exit";

        internal ExitSensor()
        {
            SensorName = "ExitProcess";
            _pidHashGenerator = new ProcessHash();
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        protected override bool OnStarting()
        {
            monotonicOffset = KernelTimestampConverter.ComputeMonotonicToRealtimeOffsetNanoseconds();
            retainExitEvidence = string.Equals(Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_EXIT_IDENTITY_RECOVERY"), "true", StringComparison.OrdinalIgnoreCase);
            WintapLogger.Log.Append($"Experimental exit identity recovery: enabled={retainExitEvidence}; bounded historical identity cache; no synthetic Start", LogLevel.Info);
            string path = Environment.GetEnvironmentVariable("WINTAP_EXPERIMENT_LIFECYCLE_SHADOW_PATH");
            if (!string.IsNullOrWhiteSpace(path)) shadow = new LifecycleShadowWriter(path);
            return true;
        }

        protected override void OnStopping()
        {
            WintapLogger.Log.Append($"Experimental exit identity recovery cumulative: retained={exitEvidenceRetained},rejected={exitEvidenceRejected}", LogLevel.Info);
            shadow?.Dispose();
            shadow = null;
        }

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                var starts = LinuxLifecycleEvidence.ReadStartTimes(data, size.ToUInt64());
                var evt = Marshal.PtrToStructure<ExitEvent>(data); // legacy 48-byte prefix

                DateTime exitUtc = KernelTimestampConverter.ToUtcDateTime(evt.TimestampNs, monotonicOffset);

                // Prefer resolver data so Stop events match the original Start PidHash.
                var resolved = EventChannel.GetProcessHistory((int)evt.Pid, exitUtc);

                // Best-effort /proc read (may still be available briefly during exit).
                var procData = ProcReader.ReadProcessInfo(evt.Pid);

                string processName = resolved?.ProcessName ?? evt.GetComm() ?? "unknown";
                string commandLine = resolved?.CommandLine ?? "";
                string userName = resolved?.UserName ?? "unknown";
                string processPath = resolved?.ProcessPath ?? "";
                int ppid = resolved?.ParentProcessId ?? (int)evt.PPid;

                // Fallback to /proc when resolver doesn't have details.
                if (resolved == null || string.IsNullOrWhiteSpace(processPath) || string.IsNullOrWhiteSpace(commandLine))
                {
                    if (procData.Exists)
                    {
                        if (ppid <= 0)
                        {
                            ppid = procData.PPid;
                        }

                        if (string.IsNullOrWhiteSpace(commandLine))
                        {
                            commandLine = procData.CommandLine ?? "";
                        }

                        if (string.IsNullOrWhiteSpace(userName) || userName == "unknown")
                        {
                            userName = procData.Username ?? userName;
                        }

                        if (string.IsNullOrWhiteSpace(processPath))
                        {
                            processPath = procData.ExecutablePath ?? processPath;
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(userName) ||
                    string.Equals(userName, "unknown", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(userName, "unknown-3", StringComparison.OrdinalIgnoreCase))
                {
                    userName = ProcReader.LookupUsername(evt.Uid);
                }

                var message = new WintapMessage(
                    exitUtc,
                    (int)evt.Pid,
                    WintapMessage.MessageTypeEnum.Process
                );

                message.ActivityType = WintapMessage.ActivityTypeEnum.Stop;

                message.Process = ProcessSensorHelper.CreateProcessObject(
                    pid: (int)evt.Pid,
                    ppid: ppid,
                    name: processName,
                    path: processPath,
                    commandLine: commandLine,
                    user: userName,
                    exitCode: evt.ExitCode
                );

                DateTime? kernelStart = ProcReader.TryConvertBootNsToUtc(starts.BootNs);
                DateTime? canonicalStart = LinuxLifecycleEvidence.SelectBirthStart(kernelStart, procData.StartTimeUtc);
                string liveHash = !kernelStart.HasValue && string.IsNullOrWhiteSpace(resolved?.PidHash)
                    ? EventChannel.GetStablePidHash((int)evt.Pid, exitUtc) : null;
                string identitySource = !string.IsNullOrWhiteSpace(resolved?.PidHash) ? "history" :
                    !string.IsNullOrWhiteSpace(liveHash) ? "live-resolver" :
                    kernelStart.HasValue ? "kernel-start" : procData.StartTimeUtc != default ? "proc-start" : "unresolved";
                message.PidHash = LinuxLifecycleEvidence.SelectExitHash(resolved?.PidHash, liveHash,
                    canonicalStart, start => _pidHashGenerator.GenPidHash(message.PID, start),
                    _pidHashGenerator.GenPidHash(-1, 0));
                message.ProcessName = processName;
                bool evidenceRetained = retainExitEvidence && resolved == null && kernelStart.HasValue &&
                    EventChannel.RetainExitIdentityEvidence(message, kernelStart.Value);
                if (retainExitEvidence && resolved == null)
                {
                    if (evidenceRetained) System.Threading.Interlocked.Increment(ref exitEvidenceRetained);
                    else System.Threading.Interlocked.Increment(ref exitEvidenceRejected);
                    message.Process.Arguments = "PROC_LIFECYCLE=exit-only;PROC_EXIT_EVIDENCE=" + (evidenceRetained ? "retained" : "unavailable");
                }
                shadow?.TryWrite(LinuxLifecycleEvidence.Classify(message.PID,
                    identitySource == "unresolved" ? null : message.PidHash, identitySource,
                    processName, evt.Uid, evt.TimestampNs, starts.MonotonicNs, starts.BootNs) with
                    { ExitEvidenceRetained = evidenceRetained,
                      LifecycleCoverage = resolved == null ? "exit-only" : "not-assessed" });

                // Prefer parent's PidHash from resolver, else populate via /proc.
                if (!string.IsNullOrWhiteSpace(resolved?.ParentPidHash))
                {
                    message.Process.ParentPidHash = resolved.ParentPidHash;
                }
                else
                {
                    ProcessSensorHelper.EnrichParentProcess(message, _pidHashGenerator);
                }

                // Unregister from resolver (process is terminating)
//                _processResolver?.UnregisterProcess((int)evt.Pid);

                EventChannel.Send(message);
                return 0;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} event handler error: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"{SensorName} stack trace: {ex.StackTrace}", LogLevel.Debug);
                return -1;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct ExitEvent
    {
        public uint Pid;
        public uint PPid;
        public uint Uid;
        public uint Gid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Comm;

        public ulong TimestampNs;
        public int ExitCode;

        public string GetComm() => StructHelper.GetString(Comm);
    }
}
