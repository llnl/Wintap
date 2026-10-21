using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared.helpers;
using gov.llnl.wintap.platform.linux.infrastructure;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// eBPF-based process creation sensor using fork/vfork/clone
    /// Captures when processes are cloned (before execve)
    /// </summary>
    internal class CloneSensor : BaseEbpfSensor
    {
        private ProcessHash _pidHashGenerator;
        private readonly System.Collections.Generic.List<IntPtr> _additionalLinks = new System.Collections.Generic.List<IntPtr>();
        private const ulong CloneThreadFlag = 0x00010000UL;
        private const ulong VforkSentinelFlags = 0xFFFFFFFFFFFFFFFFUL;
        protected override string BpfObjectFileName => "clone_tracer.bpf.o";
        protected override string BpfProgramName => "trace_process_fork";

        internal CloneSensor()
        {
            SensorName = "CloneProcess";
            _pidHashGenerator = new ProcessHash();
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        protected override bool OnStarting()
        {
            // BaseEbpfSensor attaches the primary sched_process_fork tracepoint program.
            // Attach clone/vfork syscall tracepoints too for best-effort clone_flags.
            try
            {
                var extraPrograms = new[]
                {
                    "trace_sys_enter_clone",
                    "trace_sys_enter_vfork",
                };

                foreach (var programName in extraPrograms)
                {
                    IntPtr prog = LibBpf.bpf_object__find_program_by_name(BpfObject, programName);
                    if (prog == IntPtr.Zero)
                    {
                        WintapLogger.Log.Append($"{SensorName} program '{programName}' not found", LogLevel.Debug);
                        continue;
                    }

                    IntPtr link = LibBpf.bpf_program__attach(prog);
                    if (link == IntPtr.Zero)
                    {
                        WintapLogger.Log.Append($"{SensorName} failed to attach program '{programName}'", LogLevel.Warn);
                        continue;
                    }

                    _additionalLinks.Add(link);
                    WintapLogger.Log.Append($"{SensorName} attached '{programName}'", LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} error attaching clone/vfork: {ex.Message}", LogLevel.Warn);
            }

            return true;
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
                var fileInfo = new FileInfo(path);
                var linkTarget = fileInfo.ResolveLinkTarget(returnFinalTarget: true);
                
                if (linkTarget != null)
                {
                    return linkTarget.FullName;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append(
                    $"Could not resolve symlink {path}: {ex.Message}", 
                    LogLevel.Debug);
            }

            return path;
        }

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                var evt = Marshal.PtrToStructure<CloneEvent>(data);

                // sched_process_fork fires for thread creation too. Those task IDs are
                // not process identities and should not pollute the pidhash cache.
                if (IsThreadClone(evt.CloneFlags))
                {
                    return 0;
                }
                
                // Read parent process info from /proc
                var parentProcData = ProcReader.ReadProcessInfo(evt.ParentPid);

                // Read child process info (may not be available yet if process executes quickly)
                var childProcData = ProcReader.ReadProcessInfo(evt.ChildPid);

                // Resolve any /proc paths
                string childExePath = ResolveExecutablePath(childProcData.ExecutablePath);
                string parentExePath = ResolveExecutablePath(parentProcData.ExecutablePath);

                // Determine executable path (prefer child, fallback to parent)
                string executablePath = !string.IsNullOrWhiteSpace(childExePath)
                                      ? childExePath
                                      : !string.IsNullOrWhiteSpace(parentExePath)
                                      ? parentExePath
                                      : evt.GetParentComm()
                                      ?? "unknown";

                string processName = ProcessSensorHelper.ExtractProcessName(executablePath, evt.GetParentComm());

                // Use the child start time for a stable PidHash. For a very
                // short-lived child /proc may be gone by callback time; retain
                // the kernel fork timestamp rather than assigning callback
                // time, which would make earlier file/network events appear to
                // predate their process identity.
                DateTime startUtc = childProcData.StartTimeUtc != default
                    ? childProcData.StartTimeUtc.ToUniversalTime()
                    : (ProcReader.TryConvertBootNsToUtc(evt.TimestampNs) ?? DateTime.UtcNow);
                startUtc = ProcReader.NormalizeStartTimeUtc(startUtc);

                var message = new WintapMessage(
                    startUtc,
                    (int)evt.ChildPid,
                    WintapMessage.MessageTypeEnum.Process
                );

                message.ActivityType = WintapMessage.ActivityTypeEnum.Start;

                message.Process = ProcessSensorHelper.CreateProcessObject(
                    pid: (int)evt.ChildPid,
                    ppid: (int)evt.ParentPid,
                    name: processName,
                    path: executablePath,
                    commandLine: childProcData.CommandLine != "" 
                                 ? childProcData.CommandLine 
                                 : (parentProcData.CommandLine ?? ""),
                    user: parentProcData.Username ?? "unknown"
                );

                message.PidHash = _pidHashGenerator?.GenPidHash(message.PID, message.EventTime) ?? "";
                message.ProcessName = processName;
                ProcessSensorHelper.EnrichParentProcess(message, _pidHashGenerator);

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

        private static bool IsThreadClone(ulong cloneFlags)
        {
            if (cloneFlags == 0 || cloneFlags == VforkSentinelFlags)
            {
                return false;
            }

            return (cloneFlags & CloneThreadFlag) == CloneThreadFlag;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct CloneEvent
    {
        public uint ParentPid;
        public uint ParentUid;
        public uint ParentGid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ParentComm;

        public uint ChildPid;
        public ulong TimestampNs;
        public ulong CloneFlags;

        public string GetParentComm() => StructHelper.GetString(ParentComm);
    }
}
