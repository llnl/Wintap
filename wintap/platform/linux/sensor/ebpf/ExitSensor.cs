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
        protected override string BpfObjectFileName => "exit_tracer.bpf.o";
        protected override string[] FallbackBpfObjectFileNames => new[] { "exit_tracepoint.bpf.o" };
        protected override string BpfProgramName => "trace_process_exit";

        internal ExitSensor()
        {
            SensorName = "ExitProcess";
            _pidHashGenerator = new ProcessHash();
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                var evt = Marshal.PtrToStructure<ExitEvent>(data);

                DateTime exitUtc = DateTime.UtcNow;

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

                // Stable PidHash: use resolver PidHash if available; else try /proc start time; else fall back to exit time.
                if (!string.IsNullOrWhiteSpace(resolved?.PidHash))
                {
                    message.PidHash = resolved.PidHash;
                }
                else
                {
                    // The process may have exited before its Clone/Execve
                    // Start event is registered. Ask the resolver for its
                    // live /proc-derived stable identity before using an
                    // exit-time fallback, which would create a Stop-only
                    // process identity.
                    string livePidHash = EventChannel.GetStablePidHash((int)evt.Pid, exitUtc);
                    if (!string.IsNullOrWhiteSpace(livePidHash))
                    {
                        message.PidHash = livePidHash;
                    }
                    else
                    {
                        var startUtc = procData.StartTimeUtc != default ? procData.StartTimeUtc.ToUniversalTime() : exitUtc;
                        message.PidHash = _pidHashGenerator?.GenPidHash(message.PID, startUtc.ToFileTimeUtc()) ?? "";
                    }
                }
                message.ProcessName = processName;

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
