/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Reflection;

namespace gov.llnl.wintap.collect.models
{

    /// <summary>
    /// Represents a unified message structure for capturing system events including 
    /// process activity, network connections, file operations, registry changes, and system metrics.
    /// </summary>
    public class WintapMessage
    {
        public enum FailureCodeType { ERROR_INSUFFICIENT_RESOURCES, ERROR_TOO_MANY_ADDRESSES, ERROR_ADDRESS_EXISTS, ERROR_INVALID_ADDRESS, ERROR_OTHER, ERROR_TIMEWAIT_ADDRESS_EXIST };
        public enum MessageTypeEnum
        {
            // Core system events
            Process,
            ProcessPartial,
            Thread,

            // Network events
            TcpConnection,
            UdpPacket,

            // File system events
            File,

            // Registry events
            Registry,

            // Module events
            ImageLoad,

            // UI/Session events
            UI,
            SessionChange,

            // API and system calls
            ApiCall,
            WMI,

            // Monitoring and performance
            CpuTrigger,      // Was MICROSOFT_WINDOWS_CPU_TRIGGER
            MemoryMap,

            // Configuration
            GroupPolicy,     // Was MICROSOFT_WINDOWS_GROUP_POLICY

            // Logging
            EventLogEvent,
            GenericMessage,

            // Alerts and notifications
            WintapAlert,

            // Platform-specific (Linux)
            Sysdig,
            SELinuxAvc,
            SELinuxTransition,
            SELinuxInteraction
        }
        public enum ActivityTypeEnum { Start, Stop, Refresh, Rundown, Load, Unload, PsSetLoadImageNotifyRoutine, TerminateProcess, CreateSymbolicLink, SetThreadContext, OpenProcess, OpenThread, Read, Write, Open, Close, Delete, DeleteValue, CreateKey, DeleteKey, EventWritten, HighCpuUsage, TcpIpAccept, TcpIpRecv, TcpIpTCPCopy, TcpIpReconnect, TcpIpRetransmit, TcpIpDisconnect, TcpIpARPCopy, TcpIpDupACK, TcpIpFullACK, TcpIpPartACK, TcpIpConnect, TcpIpSend, TcpIpFail, TcpIpRecvIPV6, TcpIpSendIPV6, UdpIpFail, UdpIpSend, UdpIpRecv, Other, MemCommit, MemFree, MemReserve }; 
        public enum DirectionEnum { INBOUND, OUTBOUND };
        public enum StateEnum { ESTABLISHED, SYN_SENT, SYN_RECEIVED, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSED, CLOSE_WAIT, LAST_ACK, LISTEN, CLOSING }; 
        /// <summary>Includes QWORD for REG_QWORD and NONE when no value data is available.</summary>
        public enum DataTypeEnum { STRING, DWORD, BINARY, MULTI_SZ, EXPAND_SZ, QWORD, NONE };

        [Flags]
        public enum PageProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum PageStateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum PageTypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        public WintapMessage(DateTime eventTime, int processId, MessageTypeEnum eventSourceName)
        {
            this.EventTime = eventTime.ToFileTimeUtc();
            this.PID = processId;
            this.MessageType = eventSourceName;
            this.ReceiveTime = DateTime.Now.ToFileTimeUtc();
            this.ActivityId = "";
            this.CorrelationId = "";
        }

        public MessageTypeEnum MessageType { get; set; }
        public long EventTime { get; set; }
        public long ReceiveTime { get; set; }
        public int PID { get; set; }
        public string PidHash { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public ActivityTypeEnum ActivityType { get; set; }
        public string CorrelationId { get; set; }
        public string ActivityId { get; set; }
        public string AgentId { get; set; }
        public ProcessObject Process { get; set; }
        public TcpConnectionObject TcpConnection { get; set; }
        public UdpPacketObject UdpPacket { get; set; }
        public ImageLoadObject ImageLoad { get; set; }
        public FileActivityObject File { get; set; }
        public RegActivityObject Registry { get; set; }
        public SessionChangeObject SessionChange { get; set; }
        public UIData UI { get; set; }
        public GenericMessageObject GenericMessage { get; set; }
        public WmiActivityObject WMI { get; set; }
        public ThreadStartObject Thread { get; set; }
        public EventlogEventObject EventLogEvent { get; set; }
        public MicrosoftWindowsCpuTriggerData CpuTrigger { get; set; }
        public MicrosoftWindowsGroupPolicyData GroupPolicy { get; set; }
        public ApiCallData ApiCall { get; set; }
        public MemoryMapData MemoryMap { get; set; }
        public SysdigEventData Sysdig { get; set; }
        public SELinuxAvcData SELinuxAvc { get; set; }
        public SELinuxTransitionData SELinuxTransition { get; set; }
        public SELinuxInteractionData SELinuxInteraction { get; set; }
        public WintapAlertData WintapAlert { get; set; }

        public class ProcessObject : WintapBase
        {
            public int ParentPID { get; set; }
            public string ParentPidHash { get; set; }
            public string ParentProcessName { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public string CommandLine { get; set; }
            public string Arguments { get; set; }
            public string User { get; set; }
            public long ExitCode { get; set; }
            public long CPUCycleCount { get; set; }
            public int CPUUtilization { get; set; }
            public long CommitCharge { get; set; }
            public long CommitPeak { get; set; }
            public long ReadOperationCount { get; set; }
            public long WriteOperationCount { get; set; }
            public long ReadTransferKiloBytes { get; set; }
            public long WriteTransferKiloBytes { get; set; }
            public int HardFaultCount { get; set; }
            public int TokenElevationType { get; set; }
            public int PID { get; set; }
            public string UniqueProcessKey { get; set; }
            public string MD5 { get; set; }
            public string SHA2 { get; set; }
        }

        public class TcpConnectionObject : WintapBase
        {
            public DirectionEnum Direction { get; set; }
            public string SourceAddress { get; set; }
            public int SourcePort { get; set; }
            public string DestinationAddress { get; set; }
            public int DestinationPort { get; set; }
            public StateEnum State { get; set; }
            public int MaxSegSize { get; set; }
            public int RcvWin { get; set; }
            public int RcvWinScale { get; set; }
            public int SackOpt { get; set; }
            public int SeqNo { get; set; }
            public long PacketSize { get; set; }
            public int SendWinScale { get; set; }
            public int TimestampOption { get; set; }
            public int WinScaleOption { get; set; }
            public int EndTime { get; set; }
            public int StartTime { get; set; }
            public FailureCodeType FailureCode { get; set; }
            public int PID { get; set; }
        }

        public class UdpPacketObject : WintapBase
        {
            public string SourceAddress { get; set; }
            public int SourcePort { get; set; }
            public string DestinationAddress { get; set; }
            public int DestinationPort { get; set; }
            public long PacketSize { get; set; }
            public FailureCodeType FailureCode { get; set; }
            public int PID { get; set; }
        }

        public class ImageLoadObject : WintapBase
        {
            public string FileName { get; set; }
            public long BuildTime { get; set; }
            public int ImageChecksum { get; set; }
            public int ImageSize { get; set; }
            public int PID { get; set; }
            public string DefaultBase { get; set; }  // Default base address.
            public string ImageBase { get; set; } // Base address of the application in which the image is loaded.
            public string MD5 { get; set; }
        }

        public class FileActivityObject : WintapBase
        {
            public string Path { get; set; }
            public int BytesRequested { get; set; }
            public int PID { get; set; }

            /// <summary>
            /// Number of raw file events this row represents. 1 for ordinary
            /// per-event rows (the default, including senders that never set
            /// it); N for short-interval aggregation summary rows that fold N
            /// repeats of the same (pid, path, op). Downstream aggregations
            /// must SUM this field rather than COUNT rows.
            /// </summary>
            public int EventCount { get; set; } = 1;

            /// <summary>
            /// FileTime UTC of the earliest raw event in this row's interval.
            /// 0 means unset (sender predates aggregation); consumers fall
            /// back to the message EventTime.
            /// </summary>
            public long FirstSeenEventTime { get; set; }

            /// <summary>
            /// FileTime UTC of the latest raw event in this row's interval.
            /// 0 means unset; consumers fall back to the message EventTime.
            /// </summary>
            public long LastSeenEventTime { get; set; }
        }

        public class RegActivityObject : WintapBase
        {
            public string Path { get; set; }
            public DataTypeEnum DataType { get; set; }
            public string ValueName { get; set; }
            public string Data { get; set; }
            public string PreviousData { get; set; }
            public DataTypeEnum PreviousDataType { get; set; }
            public int PID { get; set; }
        }

        public class FocusChangeObject : WintapBase
        {
            
            public int PID { get; set; }
        }

        public class SessionChangeObject : WintapBase
        {
            public string UserName { get; set; }
            public string Description { get; set; }
            public int PID { get; set; }
        }

        public class UIData : WintapBase
        {
            public int SessionId { get; set; }
            public int DisplayTimeMS { get; set; }
            public int OldProcessId { get; set; }
        }

        public class GenericMessageObject : WintapBase
        {
            public string ProviderId { get; set; }
            public string ProviderName { get; set; }
            public string EventName { get; set; }
            public int PID { get; set; }
            public DateTime EventTime { get; set; }
            public string Payload { get; set; }
            public int TargetProcessId { get; set; }
        }

        public class WmiActivityObject : WintapBase
        {
            public int ClientProcessId { get; set; }
            public int CreatedProcessId { get; set; }
            public string CommandLine { get; set; }
            public int OperationId { get; set; }
            public string Operation { get; set; }
            public string User { get; set; }
            public bool IsLocal { get; set; }
            public string ProcessName { get; set; }
            public int ResultCode { get; set; }
        }

        public class ThreadStartObject : WintapBase
        {
            public int SourcePid { get; set; }
            public int TargetPid { get; set; }
            public string SourceName { get; set; }
            public string TargetName { get; set; }
            public int TargetParentPid { get; set; }
            public int SourceParentPid { get; set; }
            public int PID { get; set; }
        }

        public class EventlogEventObject : WintapBase
        {
            public string LogName { get; set; }
            public string LogSource { get; set; }
            public int EventId { get; set; }
            public string EventMessage { get; set; }
            public int PID { get; set; }
        }

        public class ProcessMetricObject : WintapBase
        {
            public string HostName { get; set; }
            public int CpuCoreCount { get; set; }
            public long CPUSpeed { get; set; }
            public string ProcessPath { get; set; }
            public string ProcessName { get; set; }
            public long CpuTimeIncrementInMs { get; set; }
            public int TimeSinceLastCheckInMs { get; set; }
            public string EventMessage { get; set; }
            public int PID { get; set; }
        }

        public class AppUsageMetric : WintapBase
        {
            public string ComputerName { get; set; }
            public string UserName { get; set; }
            public string AppName { get; set; }
            public string AppPath { get; set; }
            public int PID { get; set; }
            public DateTime Timestamp { get; set; }
            public string AggregationStartTime { get; set; }
            public int AggregationDurationMS { get; set; }
            public int InFocusDurationMS { get; set; }
            public int FocusLostCount { get; set; }
            public int NewProcessCount { get; set; }
            public int UserActiveDurationMS { get; set; }
            public int UserOrDisplayActiveDurationMS { get; set; }
            public int UserActiveTransitionCount { get; set; }
            public int InputSec { get; set; }
            public int KeyboardInputSec { get; set; }
            public int MouseInputSec { get; set; }
            public int TouchInputSec { get; set; }
            public int PenInputSec { get; set; }
            public int HidInputSec { get; set; }
            public int WindowWidth { get; set; }
            public int WindowHeight { get; set; }
            public int InteractiveTimeoutPeriodMS { get; set; }
            public int AggregationPeriodMS { get; set; }
            public int SummaryRounds { get; set; }
            public int SpeechRecognitionSec { get; set; }
            public int GameInputSec { get; set; }
            public int BackgroundMouseSec { get; set; }
            public int AudioInMS { get; set; }
            public int AudioOutMS { get; set; }
        }

        public class MicrosoftWindowsCpuTriggerData : WintapBase
        {
            public string EventName { get; set; }
            public int PID { get; set; }
            public string ComputerName { get; set; }
            public string UserName { get; set; }
            public string AppName { get; set; }
            public string AppPath { get; set; }
            public string AppDescription { get; set; }
            public DateTime Timestamp { get; set; }
            public int AppCpuPercentage { get; set; }
            public int TotalCpuPercentage { get; set; }
            public Boolean OnBatteryPower { get; set; }
            public Boolean UserBusy { get; set; }
            public int TotalCpuPercentageAllCores { get; set; }
            public int TotalCpuPercentageOneCore { get; set; }
            public int AppCpuPercentageOneCore { get; set; }
        }

        public class MemInfoWSData : WintapBase
        {
            public long WorkingSetPageCount { get; set; }
            public long CommitPageCount { get; set; }
            public long VirtualSizeInPages { get; set; }
            public long PrivateWorkingSetPageCount { get; set; }
            public long StoreSizePageCount { get; set; }
            public long StoredPageCount { get; set; }
            public long CommitDebtInPages { get; set; }
            public long SharedCommitInPages { get; set; }
            public string Flags { get; set; }
            public string BaseAddress { get; set; }
            public long Length { get; set; }
            public string ProcessName { get; set; }
            public string VirtualAddress { get; set; }
            public string ProgramCounter { get; set; }
            public int ByteCount { get; set; }
            public long ReadOffset { get; set; }
            public double ElapsedTimeMSec { get; set; }
        }

        public class MemoryEventData : WintapBase
        {
            public int ThreadId { get; set; }
            public string Payload { get; set; }
        }

        public class MicrosoftWindowsGroupPolicyData : WintapBase
        {
            public string FormattedMessage { get; set; }
        }

        public class MicrosoftWindowsBitLockerAPIData : WintapBase
        {
            public string FormattedMessage { get; set; }
            public string IdentificationGUID { get; set; }
            public string VolumeName { get; set; }
            public string VolumeMountPoint { get; set; }
        }

        public class WintapAlertData : WintapBase
        {
            public enum AlertNameEnum { EVENT_DROP, SYSTEM_UTILIZATION, PROCESS_TREE, OTHER }
            public AlertNameEnum AlertName { get; set; }
            public string AlertDescription { get; set; }
        }

        public class ApiCallData : WintapBase
        {
            private string providerName;
            private int threadId;
            private int targetPid;
            private uint? desiredAccess;
            private uint returnCode;
            private string linkSourceName;
            private string linkTargetName;
            private long? notifyRoutineAddress;
            private uint? targetThreatId;

            public ApiCallData(string _providerName, int _targetPid, uint? _desiredAccess, uint _returnCode, string _linkSourceName, string _linkTargetName, long? _notifyRoutineAddress, uint? _targetThreatId, int _threadId, string _targetProcessName, string _desiredAccessString)
            {
                providerName = _providerName;
                targetPid = _targetPid;
                desiredAccess = _desiredAccess;
                returnCode = _returnCode;
                linkSourceName = _linkSourceName;
                linkTargetName = _linkTargetName;
                notifyRoutineAddress = _notifyRoutineAddress;
                targetThreatId = _targetThreatId;
                threadId = _threadId;
                TargetProcessName = _targetProcessName;
                DesiredAccessString = _desiredAccessString;
            }

            public string ProviderName
            {
                get { return providerName; }
            }

            public int? TargetPid
            {
                get { return targetPid; }
            }

            public string TargetProcessName { get; set; }

            public uint? DesiredAccess
            {
                get { return desiredAccess; }
            }

            public uint ReturnCode
            {
                get { return returnCode; }
            }

            public string LinkSourceName
            {
                get { return linkSourceName; }
            }

            public string LinkTargetName
            {
                get { return linkTargetName; }
            }

            public long? NotifyRoutineAddress
            {
                get { return notifyRoutineAddress; }
            }

            public uint? TargetThreatId
            {
                get { return targetThreatId; }
            }

            public int ThreadId
            {
                get { return threadId; }
            }

            public string DesiredAccessString { get; set; }
        }

        public class MemoryMapData : WintapBase
        {
            public string Description { get; set; }
            public string BaseAddress { get; set; }
            public string AllocationBaseAddress { get; set; }
            public PageProtectEnum AllocationProtect { get; set; }
            public long RegionSize { get; set; }
            public PageProtectEnum PageProtect { get; set; }
            public PageTypeEnum PageType { get; set; }
            public bool MZHeaderPresent { get; set; }
        }

        public class SysdigEventData : WintapBase
        {
            public int evt_cpu { get; set; }
            public string evt_dir { get; set; }
            public string evt_info { get; set; }
            public int evt_num { get; set; }
            public long evt_outputtime { get; set; }
            public string evt_type { get; set; }
            public string proc_name { get; set; }
            public int thread_tid { get; set; }
        }

        public class SELinuxAvcData : WintapBase
        {
            public string SContext { get; set; }
            public string TContext { get; set; }
            public string TClass { get; set; }
            public long RequestedMask { get; set; }
            public long DeniedMask { get; set; }
            public long AuditedMask { get; set; }
            public string RequestedPerms { get; set; }
            public string DeniedPerms { get; set; }
            public int Result { get; set; }
            public bool Enforcing { get; set; }
            public int PolicyEpoch { get; set; }
            public int EventCount { get; set; } = 1;
            public long FirstSeenEventTime { get; set; }
            public long LastSeenEventTime { get; set; }
            public int PID { get; set; }
        }

        public class SELinuxTransitionData : WintapBase
        {
            public long OldSid { get; set; }
            public long NewSid { get; set; }
            public string OldContext { get; set; }
            public string NewContext { get; set; }
            public string ExeFile { get; set; }
            public int PolicyEpoch { get; set; }
            public int EventCount { get; set; } = 1;
            public long FirstSeenEventTime { get; set; }
            public long LastSeenEventTime { get; set; }
            public int PID { get; set; }
        }

        public class SELinuxInteractionData : WintapBase
        {
            public long SSid { get; set; }
            public long TSid { get; set; }
            public string SContext { get; set; }
            public string TContext { get; set; }
            public string TClass { get; set; }
            public string Permission { get; set; }
            public long RequestedMask { get; set; }
            public int EventCount { get; set; } = 1;
            public long FirstSeenEventTime { get; set; }
            public long LastSeenEventTime { get; set; }
            public bool Novel { get; set; }
            public int PolicyEpoch { get; set; }
            public int PID { get; set; }
        }

        public abstract class WintapBase
        {
            public ExpandoObject ToDynamic()
            {
                var expando = new ExpandoObject();
                var expandoDic = (IDictionary<string, object>)expando;
                foreach (PropertyInfo propertyInfo in this.GetType().GetProperties())
                {
                    var value = propertyInfo.GetValue(this, null);

                    // Parquet does not have native support for .NET enum types,
                    // converting enums to strings when creating ExpandoObject for parquet compat
                    if (value != null && value.GetType().IsEnum)
                    {
                        value = value.ToString();
                    }

                    expandoDic.Add(propertyInfo.Name, value);
                }
                return expando;
            }
        }
    }
}
