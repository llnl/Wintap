using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared.helpers;
using gov.llnl.wintap.platform.linux.infrastructure;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Linq;

namespace gov.llnl.wintap.platform.linux.collect
{
    internal class ExecveSensor : BaseEbpfSensor
    {
        private const int _SC_CLK_TCK = 2;
        private ProcessHash _pidHashGenerator;
        private readonly System.Collections.Generic.List<IntPtr> _additionalLinks = new System.Collections.Generic.List<IntPtr>();
        private static DateTimeOffset? _cachedBootUtc;
        private static long? _cachedClockTicksPerSecond;

        protected override string BpfObjectFileName => "execve_tracer.bpf.o";
        protected override string[] FallbackBpfObjectFileNames => new[] { "execve_tracepoint.bpf.o" };
        protected override string BpfProgramName => "trace_execve_entry";

        internal ExecveSensor()
        {
            SensorName = "ExecveProcess";
            _pidHashGenerator = new ProcessHash();
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        protected override bool OnStarting()
        {
            // BaseEbpfSensor attaches the primary sys_enter_execve tracepoint program.
            // Attach execveat as well to improve coverage for callers that use execveat.
            try
            {
                var extraPrograms = new[]
                {
                    "trace_execveat_entry",
                    "trace_sched_process_exec",
                };

                foreach (var programName in extraPrograms)
                {
                    IntPtr link = AttachProgram(programName);
                    if (link == IntPtr.Zero) continue;

                    _additionalLinks.Add(link);
                    WintapLogger.Log.Append($"{SensorName} attached '{programName}'", LogLevel.Info);
                }

                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} error attaching extra exec programs: {ex.Message}", LogLevel.Warn);
                return true; // best-effort: keep execve working
            }
        }

        protected override void OnStopping()
        {
            foreach (var link in _additionalLinks)
            {
                try
                {
                    if (link != IntPtr.Zero)
                        LibBpf.bpf_link__destroy(link);
                }
                catch { }
            }
            _additionalLinks.Clear();
        }

        /// <summary>
        /// Resolves /proc symlinks to actual executable paths
        /// </summary>
        private static string ResolveExecutablePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("/proc/"))
            {
                return path;
            }

            try
            {
                // Use .NET's FileInfo to resolve the symlink
                var fileInfo = new FileInfo(path);
                
                // ResolveLinkTarget available in .NET 6+
                // If you're on an older version, see alternative below
                var linkTarget = fileInfo.ResolveLinkTarget(returnFinalTarget: true);
                
                if (linkTarget != null)
                {
                    return linkTarget.FullName;
                }
            }
            catch (Exception ex)
            {
                // Process may have already exited, or permission denied
                // Log at debug level since this is expected behavior
                WintapLogger.Log.Append(
                    $"Could not resolve symlink {path}: {ex.Message}", 
                    LogLevel.Debug);
            }

            return path; // Return original if resolution fails
        }

        private static DateTimeOffset? TryGetBootUtc()
        {
            try
            {
                if (!OperatingSystem.IsLinux())
                    return null;

                if (_cachedBootUtc != null)
                    return _cachedBootUtc;

                foreach (string line in File.ReadLines("/proc/stat"))
                {
                    if (!line.StartsWith("btime ", StringComparison.Ordinal))
                        continue;

                    string value = line.Substring("btime ".Length).Trim();
                    if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long bootUnixSeconds))
                        return null;

                    _cachedBootUtc = DateTimeOffset.FromUnixTimeSeconds(bootUnixSeconds);
                    return _cachedBootUtc;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private static long GetClockTicksPerSecond()
        {
            if (_cachedClockTicksPerSecond != null)
                return _cachedClockTicksPerSecond.Value;

            long ticks = sysconf(_SC_CLK_TCK);
            _cachedClockTicksPerSecond = ticks > 0 ? ticks : 100;
            return _cachedClockTicksPerSecond.Value;
        }

        private static long? TryConvertBootNsToFileTimeUtc(ulong startNs)
        {
            var bootUtc = TryGetBootUtc();
            if (bootUtc == null)
                return null;

            try
            {
                // /proc/<pid>/stat exposes start time in clock ticks after boot.
                // Round eBPF nanoseconds to the same basis so parent hashes match
                // ProcessRundown/ProcReader-derived PidHash values.
                long ticksPerSecond = GetClockTicksPerSecond();
                ulong startTicks = (startNs * (ulong)ticksPerSecond) / 1_000_000_000UL;
                var startUtc = bootUtc.Value.AddTicks(
                    checked((long)(startTicks * (ulong)TimeSpan.TicksPerSecond / (ulong)ticksPerSecond)));
                return startUtc.UtcDateTime.ToFileTimeUtc();
            }
            catch
            {
                return null;
            }
        }

        [DllImport("libc")]
        private static extern long sysconf(int name);

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                var evt = Marshal.PtrToStructure<ExecveEvent>(data);
                if (evt.Comm == null || evt.Filename == null) return 0;

                // Enrich with /proc data
                var procData = ProcReader.ReadProcessInfo(evt.Pid);
                
                string rawFilename = evt.GetFilename();
                string rawComm = evt.GetComm();
                string rawCmdline = procData.CommandLine;
                
                // Resolve /proc symlinks FIRST
                string resolvedFilename = ResolveExecutablePath(rawFilename);
                
                // Build executable path with multiple fallbacks
                // Use the resolved filename instead of raw
                string executablePath = !string.IsNullOrWhiteSpace(resolvedFilename) ? resolvedFilename
                                      : !string.IsNullOrWhiteSpace(procData.ExecutablePath) ? procData.ExecutablePath
                                      : !string.IsNullOrWhiteSpace(rawCmdline) ? ProcessSensorHelper.ExtractPathFromCmdline(rawCmdline)
                                      : "unknown-1";
                
                // Extract process name with comm as fallback
                string processName = ProcessSensorHelper.ExtractProcessName(executablePath, rawComm);
                int parentPid = procData.PPid > 0 ? procData.PPid : (int)evt.PPid;
                
                // Final safety: if process name is STILL empty, try cmdline
                if (string.IsNullOrWhiteSpace(processName) || processName == "unknown-1")
                {
                    processName = ProcessSensorHelper.ExtractProcessNameFromCmdline(rawCmdline, "unknown-2");
                }

                // Use process start time for EventTime so PidHash is stable and matches
                // other lifecycle events (clone/exit) and handles PID reuse correctly.
                DateTime startUtc = procData.StartTimeUtc != default
                    ? procData.StartTimeUtc.ToUniversalTime()
                    : evt.StartTime != 0 && TryConvertBootNsToFileTimeUtc(evt.StartTime) is long startFileTimeUtc
                        ? DateTime.FromFileTimeUtc(startFileTimeUtc)
                        : DateTime.UtcNow;
                startUtc = ProcReader.NormalizeStartTimeUtc(startUtc);

                var message = new WintapMessage(startUtc, (int)evt.Pid, WintapMessage.MessageTypeEnum.Process);
                message.ActivityType = WintapMessage.ActivityTypeEnum.Start;

                string userName = !string.IsNullOrWhiteSpace(procData.Username)
                    ? procData.Username
                    : ProcReader.LookupUsername(evt.Uid);

                message.Process = ProcessSensorHelper.CreateProcessObject(
                    pid: (int)evt.Pid,
                    ppid: parentPid,
                    name: processName,
                    path: executablePath,
                    commandLine: rawCmdline ?? "",
                    user: userName,
                    arguments: !string.IsNullOrEmpty(procData.Home) 
                        ? $"HOME={procData.Home} SHELL={procData.Shell}" 
                        : null
                );

                // Breadcrumb for start-event source.
                if ((evt.Flags & 0x80000000u) != 0)
                {
                    message.Process.Arguments = string.IsNullOrWhiteSpace(message.Process.Arguments)
                        ? "PROC_START_SRC=sched_exec"
                        : message.Process.Arguments + " PROC_START_SRC=sched_exec";
                }
                else
                {
                    // execve vs execveat: keep the raw flags around for debugging.
                    message.Process.Arguments = string.IsNullOrWhiteSpace(message.Process.Arguments)
                        ? $"PROC_START_SRC=execve_or_execveat FLAGS=0x{evt.Flags:x8}"
                        : message.Process.Arguments + $" PROC_START_SRC=execve_or_execveat FLAGS=0x{evt.Flags:x8}";
                }

                message.PidHash = _pidHashGenerator?.GenPidHash(message.PID, message.EventTime) ?? "";
                message.ProcessName = processName;
                ProcessSensorHelper.EnrichParentProcess(message, _pidHashGenerator);

                // Best-effort parent attribution without /proc. This is a fallback for cases
                // where the parent exits before userspace can read /proc/<ppid>.
                if (message.Process.ParentPID > 0 && string.IsNullOrWhiteSpace(message.Process.ParentPidHash) && evt.ParentStartNs != 0)
                {
                    var parentFileTimeUtc = TryConvertBootNsToFileTimeUtc(evt.ParentStartNs);
                    if (parentFileTimeUtc != null)
                    {
                        message.Process.ParentPidHash = _pidHashGenerator.GenPidHash(message.Process.ParentPID, parentFileTimeUtc.Value);
                        var parentComm = evt.GetParentComm();
                        message.Process.ParentProcessName = !string.IsNullOrWhiteSpace(parentComm) ? parentComm : "Unknown";
                        message.Process.Arguments = string.IsNullOrWhiteSpace(message.Process.Arguments)
                            ? "PARENT_HASH_SRC=ebpf"
                            : message.Process.Arguments + " PARENT_HASH_SRC=ebpf";
                    }
                }

                EventChannel.Send(message);
                return 0;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} error: {ex.Message}", LogLevel.Error);
                return -1;
            }
        }

    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct ExecveEvent
    {
        public uint Pid;
        public uint PPid;
        public uint Uid;
        public uint Gid;
        public uint Sid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Comm;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ParentComm;

        public ulong ParentStartNs;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] Filename;

        public ulong TimestampNs;
        public uint ExitCode;
        public uint Flags;
        public ulong StartTime;
        public ulong Capabilities;
        public uint SeccompMode;

        public string GetComm() => StructHelper.GetString(Comm);
        public string GetParentComm() => StructHelper.GetString(ParentComm);
        public string GetFilename() => StructHelper.GetString(Filename);
    }
}
