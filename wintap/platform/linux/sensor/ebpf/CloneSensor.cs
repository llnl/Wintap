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
        private long monotonicOffset;
        private readonly System.Collections.Generic.List<IntPtr> _additionalLinks = new System.Collections.Generic.List<IntPtr>();
        private const ulong CloneThreadFlag = 0x00010000UL;
        private const ulong VforkSentinelFlags = 0xFFFFFFFFFFFFFFFFUL;
        protected override string BpfObjectFileName => "clone_core_tracer.bpf.o";
        protected override string[] FallbackBpfObjectFileNames => new[] { "clone_tracer.bpf.o" };
        protected override string BpfProgramName => "trace_process_fork";

        internal CloneSensor()
        {
            SensorName = "CloneProcess";
            _pidHashGenerator = new ProcessHash();
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        protected override bool OnStarting()
        {
            monotonicOffset = KernelTimestampConverter.ComputeMonotonicToRealtimeOffsetNanoseconds();
            RuntimeCapabilities.Feature(CapabilityKey, "threadClassification", LoadedTier == "core" ? "kernel-child-pid-tgid" : "best-effort-syscall-flags");
            RuntimeCapabilities.Feature(CapabilityKey, "birthIdentity", LoadedTier == "core" ? "kernel-task-boottime-or-proc" : "proc-or-explicit-unknown");
            if (LoadedTier != "core")
                WintapLogger.Log.Append("CLONE_DATA_QUALITY: tracepoint fallback uses best-effort syscall flags; absent hooks or failed flag reads can classify threads as process births. Zero flags are not proof of a process. Review HOST RuntimeCapabilitiesJson.", LogLevel.Warn);
            // CO-RE classifies the child directly; these optional programs exist
            // only in the tracepoint fallback for best-effort clone flags.
            try
            {
                var extraPrograms = new[]
                {
                    "trace_sys_enter_clone",
                    "trace_sys_enter_clone3",
                    "trace_sys_enter_vfork",
                };

                foreach (var programName in extraPrograms)
                {
                    IntPtr link = AttachProgram(programName, applicable: LoadedTier != "core");
                    if (link == IntPtr.Zero) continue;

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
                ulong kernelStartNs = LinuxLifecycleEvidence.ReadCloneStart(data, size.ToUInt64());
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

                DateTime? startUtc = LinuxLifecycleEvidence.SelectBirthStart(
                    ProcReader.TryConvertBootNsToUtc(kernelStartNs), childProcData.StartTimeUtc);
                if (startUtc.HasValue) startUtc = ProcReader.NormalizeStartTimeUtc(startUtc.Value);
                // Legacy/fallback events without /proc birth retain their
                // occurrence timestamp, but must not turn it into identity.
                DateTime occurrenceUtc = KernelTimestampConverter.ToUtcDateTime(evt.TimestampNs, monotonicOffset);

                var message = new WintapMessage(
                    startUtc ?? occurrenceUtc,
                    (int)evt.ChildPid,
                    WintapMessage.MessageTypeEnum.Process
                );

                message.ActivityType = WintapMessage.ActivityTypeEnum.Start;

                string userName = !string.IsNullOrWhiteSpace(childProcData.Username)
                    ? childProcData.Username
                    : !string.IsNullOrWhiteSpace(parentProcData.Username)
                        ? parentProcData.Username
                        : ProcReader.LookupUsername(evt.ParentUid);

                message.Process = ProcessSensorHelper.CreateProcessObject(
                    pid: (int)evt.ChildPid,
                    ppid: (int)evt.ParentPid,
                    name: processName,
                    path: executablePath,
                    commandLine: childProcData.CommandLine != "" 
                                 ? childProcData.CommandLine 
                                 : (parentProcData.CommandLine ?? ""),
                    user: userName
                );

                // Distinguish inherited birth metadata from a later exec image.
                // Raw observations remain separate; resolver state must not be
                // downgraded by the independent clone poller arriving late.
                message.Process.Arguments = "PROC_START_SRC=sched_fork" +
                    (startUtc.HasValue ? "" : ";PROC_IDENTITY=unresolved-no-start");

                message.PidHash = startUtc.HasValue
                    ? _pidHashGenerator.GenPidHash(message.PID, startUtc.Value.ToFileTimeUtc())
                    : _pidHashGenerator.GenPidHash(-1, 0);
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
