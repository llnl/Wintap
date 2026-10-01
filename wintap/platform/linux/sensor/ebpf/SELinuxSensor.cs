using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// SELinux capture skeleton for sel-02. It attaches the SELinux eBPF
    /// tracer, decodes ring records, and emits SELinux WintapMessages.
    /// </summary>
    internal class SELinuxSensor : BaseEbpfSensor
    {
        private readonly List<IntPtr> _additionalLinks = new List<IntPtr>();
        private readonly long _monotonicToRealtimeOffsetNs;
        private readonly ProcessHash _pidHashGenerator = new ProcessHash();
        private readonly long[] _consumedByRecordType = new long[4];
        private readonly long[] _decodeErrorsByRecordType = new long[4];
        private readonly SELinuxSidResolver _sidResolver = new SELinuxSidResolver();
        private SELinuxPermissionDecoder _permissionDecoder = new SELinuxPermissionDecoder();
        private int _statsMapFd = -1;
        private int _interactionMapFd = -1;
        private Timer? _counterLogTimer;
        private Timer? _interactionFlushTimer;
        private Timer? _policyPollTimer;
        private int _sampleLogsRemaining = 10;
        private string _interactionAttachMode = "none";
        private long _policyLastWriteTicks;
        private long _policyEpoch;
        private long _interactionFlushRows;
        private long _interactionFlushEvents;
        private long _interactionFlushZeroDelta;
        private long _interactionFlushErrors;
        private long _interactionFlushIterations;
        private long _resolveHits;
        private long _resolveMisses;
        private long _unknownPermissionMasks;
        private long _policyReloads;
        private long _messagesSent;
        private long _messageSendErrors;
        private long _interactionSummaryMessages;
        private readonly object _unknownPermissionLock = new object();
        private readonly Dictionary<string, long> _unknownPermissionBuckets = new Dictionary<string, long>(StringComparer.Ordinal);

        private const uint RecordAvc = 1;
        private const uint RecordTransition = 2;
        private const uint RecordInteraction = 3;

        private const int HeaderRecordTypeOffset = 0;
        private const int HeaderPidOffset = 4;
        private const int HeaderTgidOffset = 8;
        private const int HeaderUidOffset = 12;
        private const int HeaderCommOffset = 16;
        private const int HeaderTimestampOffset = 32;

        private const int AvcRequestedOffset = 40;
        private const int AvcDeniedOffset = 44;
        private const int AvcAuditedOffset = 48;
        private const int AvcResultOffset = 52;
        private const int AvcSContextOffset = 56;
        private const int AvcTContextOffset = 312;
        private const int AvcTClassOffset = 568;
        private const int AvcFlagsOffset = 600;

        private const int TransitionOldSidOffset = 40;
        private const int TransitionNewSidOffset = 44;
        private const int TransitionFilenameOffset = 48;

        private const int InteractionSSidOffset = 40;
        private const int InteractionTSidOffset = 44;
        private const int InteractionTClassOffset = 48;
        private const int InteractionRequestedOffset = 52;
        private const int InteractionCountOffset = 56;
        private const int InteractionFirstTimestampOffset = 64;
        private const int InteractionLastTimestampOffset = 72;
        private const int InteractionFirstCommOffset = 80;
        private const int InteractionFirstPidOffset = 96;
        private const int InteractionNovelOffset = 100;
        private const int InteractionKeySize = 16;
        private const int InteractionValueSize = 56;
        private const int InteractionValueCountOffset = 0;
        private const int InteractionValueEmittedAtFlushOffset = 8;
        private const int InteractionValueFirstTimestampOffset = 16;
        private const int InteractionValueLastTimestampOffset = 24;
        private const int InteractionValueFirstPidOffset = 32;
        private const int InteractionValueFirstCommOffset = 36;

        protected override string BpfObjectFileName => "selinux_tracer.bpf.o";
        protected override string BpfProgramName => "tp_avc_audit";

        internal SELinuxSensor()
        {
            SensorName = "SELinux";
            _monotonicToRealtimeOffsetNs = ComputeMonotonicToRealtimeOffsetNs();
        }

        public override bool Start()
        {
            if (!IsSELinuxPresent())
            {
                WintapLogger.Log.Append("SELinux sensor disabled: /sys/fs/selinux/enforce is not present", LogLevel.Warn);
                return false;
            }

            LogSELinuxStartupCensus();

            if (!base.Start())
            {
                return false;
            }

            try
            {
                TryAttachProgram("k_bprm_commit");

                if (TryAttachProgram("k_avc_noaudit"))
                {
                    _interactionAttachMode = "avc_has_perm_noaudit";
                }
                else
                {
                    WintapLogger.Log.Append($"{SensorName} falling back from avc_has_perm_noaudit to avc_has_perm wrapper; inode fast-path coverage may be incomplete", LogLevel.Warn);
                    if (TryAttachProgram("k_avc_perm"))
                    {
                        _interactionAttachMode = "avc_has_perm";
                    }
                }

                WintapLogger.Log.Append($"{SensorName} attached {_additionalLinks.Count + 1} programs total", LogLevel.Info);
                _counterLogTimer = new Timer(_ => SafeLogCounters(), null, 10_000, 60_000);
                int flushMs = Math.Max(1, GetConfiguredFlushSeconds()) * 1000;
                _interactionFlushTimer = new Timer(_ => SafeFlushInteractions(), null, flushMs, flushMs);
                _policyPollTimer = new Timer(_ => SafePollPolicyEpoch(), null, 5_000, 5_000);
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} error attaching additional programs: {ex.Message}", LogLevel.Error);
                Stop();
                return false;
            }
        }

        protected override bool OnStarting()
        {
            _permissionDecoder = SELinuxPermissionDecoder.LoadFromSelinuxFs();
            _policyLastWriteTicks = GetPolicyLastWriteTicks();
            WintapLogger.Log.Append($"{SensorName} permission decoder loaded classes={_permissionDecoder.ClassCount},permissions={_permissionDecoder.PermissionCount},policy_epoch={Interlocked.Read(ref _policyEpoch)}", LogLevel.Info);
            InitializeStatsMap();
            InitializeInteractionMap();
            InitializeSelfPidFilter();
            return true;
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        private bool TryAttachProgram(string progName)
        {
            IntPtr prog = LibBpf.bpf_object__find_program_by_name(BpfObject, progName);
            if (prog == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} program '{progName}' not found", LogLevel.Warn);
                return false;
            }

            IntPtr link = LibBpf.bpf_program__attach(prog);
            long linkError = link == IntPtr.Zero ? -1 : LibBpf.libbpf_get_error(link);
            if (link == IntPtr.Zero || linkError != 0)
            {
                WintapLogger.Log.Append($"{SensorName} failed to attach '{progName}' error={linkError}", LogLevel.Warn);
                return false;
            }

            _additionalLinks.Add(link);
            WintapLogger.Log.Append($"{SensorName} attached '{progName}'", LogLevel.Info);
            return true;
        }

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            uint recordType = 0;
            try
            {
                recordType = ReadUInt32(data, HeaderRecordTypeOffset);
                int recordIndex = GetRecordIndex(recordType);
                CountByRecord(_consumedByRecordType, recordIndex);

                switch (recordType)
                {
                    case RecordAvc:
                        DecodeAvc(data);
                        break;
                    case RecordTransition:
                        DecodeTransition(data);
                        break;
                    case RecordInteraction:
                        DecodeInteraction(data);
                        break;
                    default:
                        CountByRecord(_decodeErrorsByRecordType, 0);
                        break;
                }

                return 0;
            }
            catch (Exception ex)
            {
                CountByRecord(_decodeErrorsByRecordType, GetRecordIndex(recordType));
                WintapLogger.Log.Append($"{SensorName} decode error for record_type={recordType}: {ex.Message}", LogLevel.Error);
                return -1;
            }
        }

        private void DecodeAvc(IntPtr data)
        {
            int pid = ReadInt32(data, HeaderPidOffset);
            string comm = ReadString(data, HeaderCommOffset, 16);
            uint requested = ReadUInt32(data, AvcRequestedOffset);
            uint denied = ReadUInt32(data, AvcDeniedOffset);
            uint audited = ReadUInt32(data, AvcAuditedOffset);
            int result = ReadInt32(data, AvcResultOffset);
            string tclass = ReadString(data, AvcTClassOffset, 32);
            string scontext = ReadString(data, AvcSContextOffset, 256);
            string tcontext = ReadString(data, AvcTContextOffset, 256);
            string requestedPerms = DecodePermissionsByClassName(tclass, requested, out uint requestedUnknown);
            string deniedPerms = DecodePermissionsByClassName(tclass, denied, out uint deniedUnknown);
            if (requestedUnknown != 0 || deniedUnknown != 0)
            {
                Interlocked.Increment(ref _unknownPermissionMasks);
                RecordUnknownPermission(0, requested | denied, requestedUnknown | deniedUnknown, tclass);
            }

            long eventTime = ConvertKernelTimestampToUtcDateTime(ReadUInt64(data, HeaderTimestampOffset)).ToFileTimeUtc();
            var message = CreateMessage(pid, eventTime, WintapMessage.MessageTypeEnum.SELinuxAvc, comm);
            message.SELinuxAvc = new WintapMessage.SELinuxAvcData
            {
                SContext = scontext,
                TContext = tcontext,
                TClass = tclass,
                RequestedMask = requested,
                DeniedMask = denied,
                AuditedMask = audited,
                RequestedPerms = requestedPerms,
                DeniedPerms = deniedPerms,
                Result = result,
                Enforcing = IsSELinuxEnforcing(),
                PolicyEpoch = unchecked((int)Interlocked.Read(ref _policyEpoch)),
                EventCount = 1,
                FirstSeenEventTime = eventTime,
                LastSeenEventTime = eventTime,
                PID = pid,
            };
            SendMessage(message);

            // The tracepoint stream has context strings but not numeric SIDs;
            // keep these strings available for future R3 expansion once a SID
            // source is paired with them.
            if (!ShouldLogSample())
            {
                return;
            }

            WintapLogger.Log.Append(
                $"{SensorName} sample avc pid={pid} comm={comm} requested=0x{requested:x} requested_perms={requestedPerms} denied=0x{denied:x} denied_perms={deniedPerms} audited=0x{audited:x} result={result} tclass={tclass} scontext_present={!string.IsNullOrEmpty(scontext)} tcontext_present={!string.IsNullOrEmpty(tcontext)} flags=0x{ReadUInt32(data, AvcFlagsOffset):x}",
                LogLevel.Info);
        }

        private void DecodeTransition(IntPtr data)
        {
            uint oldSid = ReadUInt32(data, TransitionOldSidOffset);
            uint newSid = ReadUInt32(data, TransitionNewSidOffset);
            int pid = unchecked((int)ReadUInt32(data, HeaderPidOffset));
            string comm = ReadString(data, HeaderCommOffset, 16);
            string oldContext = _sidResolver.ResolveKnown(oldSid, out bool oldHit);
            CountResolve(oldHit);
            string newContext = _sidResolver.ResolveSource(newSid, pid, out bool hit);
            CountResolve(hit);
            long eventTime = ConvertKernelTimestampToUtcDateTime(ReadUInt64(data, HeaderTimestampOffset)).ToFileTimeUtc();
            string filename = ReadString(data, TransitionFilenameOffset, 256);
            var message = CreateMessage(pid, eventTime, WintapMessage.MessageTypeEnum.SELinuxTransition, comm);
            message.SELinuxTransition = new WintapMessage.SELinuxTransitionData
            {
                OldSid = oldSid,
                NewSid = newSid,
                OldContext = oldContext,
                NewContext = newContext,
                ExeFile = filename,
                PolicyEpoch = unchecked((int)Interlocked.Read(ref _policyEpoch)),
                EventCount = 1,
                FirstSeenEventTime = eventTime,
                LastSeenEventTime = eventTime,
                PID = pid,
            };
            SendMessage(message);

            if (!ShouldLogSample())
            {
                return;
            }

            WintapLogger.Log.Append(
                $"{SensorName} sample transition pid={pid} comm={comm} old_sid={oldSid} new_sid={newSid} old_context_resolved={oldHit} new_context_resolved={hit} new_context_present={!string.IsNullOrEmpty(newContext)} filename={filename}",
                LogLevel.Info);
        }

        private void DecodeInteraction(IntPtr data)
        {
            uint ssid = ReadUInt32(data, InteractionSSidOffset);
            uint tsid = ReadUInt32(data, InteractionTSidOffset);
            uint tclass = ReadUInt32(data, InteractionTClassOffset);
            uint requested = ReadUInt32(data, InteractionRequestedOffset);
            int firstPid = ReadInt32(data, InteractionFirstPidOffset);
            string scontext = _sidResolver.ResolveSource(ssid, firstPid, out bool sourceHit);
            CountResolve(sourceHit);
            string tcontext = _sidResolver.ResolveKnown(tsid, out bool targetHit);
            CountResolve(targetHit);
            string className = _permissionDecoder.GetClassName(tclass);
            string permissions = _permissionDecoder.DecodePermissions(tclass, requested, out uint unknownBits);
            if (unknownBits != 0)
            {
                Interlocked.Increment(ref _unknownPermissionMasks);
                RecordUnknownPermission(tclass, requested, unknownBits, className);
            }

            long eventTime = ConvertKernelTimestampToUtcDateTime(ReadUInt64(data, HeaderTimestampOffset)).ToFileTimeUtc();
            EmitInteractionMessages(
                pid: unchecked((int)ReadUInt32(data, HeaderPidOffset)),
                eventTime: eventTime,
                ssid: ssid,
                tsid: tsid,
                scontext: scontext,
                tcontext: tcontext,
                tclass: className,
                permissionList: permissions,
                requestedMask: requested,
                eventCount: 1,
                firstSeenEventTime: eventTime,
                lastSeenEventTime: eventTime,
                novel: true,
                processName: ReadString(data, HeaderCommOffset, 16));

            if (!ShouldLogSample())
            {
                return;
            }

            WintapLogger.Log.Append(
                $"{SensorName} sample interaction pid={ReadUInt32(data, HeaderPidOffset)} comm={ReadString(data, HeaderCommOffset, 16)} ssid={ssid} tsid={tsid} tclass={tclass} class={className} requested=0x{requested:x} perms={permissions} scontext_resolved={sourceHit} scontext_present={!string.IsNullOrEmpty(scontext)} tcontext_resolved={targetHit} tcontext_present={!string.IsNullOrEmpty(tcontext)} count={ReadUInt64(data, InteractionCountOffset)} novel={ReadUInt32(data, InteractionNovelOffset)} first_pid={firstPid} first_comm={ReadString(data, InteractionFirstCommOffset, 16)}",
                LogLevel.Info);
        }

        private bool ShouldLogSample()
        {
            while (true)
            {
                int current = Volatile.Read(ref _sampleLogsRemaining);
                if (current <= 0)
                {
                    return false;
                }

                if (Interlocked.CompareExchange(ref _sampleLogsRemaining, current - 1, current) == current)
                {
                    return true;
                }
            }
        }

        private void InitializeStatsMap()
        {
            IntPtr statsMap = LibBpf.bpf_object__find_map_by_name(BpfObject, "selinux_stats");
            if (statsMap == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} stats map not found", LogLevel.Warn);
                return;
            }

            _statsMapFd = LibBpf.bpf_map__fd(statsMap);
            WintapLogger.Log.Append($"{SensorName} stats map initialized fd={_statsMapFd}", LogLevel.Debug);
        }

        private void InitializeInteractionMap()
        {
            IntPtr interactionMap = LibBpf.bpf_object__find_map_by_name(BpfObject, "selinux_interactions");
            if (interactionMap == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} interaction map not found", LogLevel.Warn);
                return;
            }

            _interactionMapFd = LibBpf.bpf_map__fd(interactionMap);
            WintapLogger.Log.Append($"{SensorName} interaction map initialized fd={_interactionMapFd}", LogLevel.Debug);
        }

        private void InitializeSelfPidFilter()
        {
            IntPtr filterMap = LibBpf.bpf_object__find_map_by_name(BpfObject, "selinux_filter_pids");
            if (filterMap == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} self-PID filter map not found", LogLevel.Warn);
                return;
            }

            int filterMapFd = LibBpf.bpf_map__fd(filterMap);
            uint key = 0;
            uint value = (uint)Process.GetCurrentProcess().Id;
            int ret = LibBpf.bpf_map_update_elem(filterMapFd, ref key, ref value, 0);
            if (ret != 0)
            {
                WintapLogger.Log.Append($"{SensorName} failed to set self-PID filter ret={ret}", LogLevel.Warn);
                return;
            }

            WintapLogger.Log.Append($"{SensorName} self-PID filter set to pid={value}", LogLevel.Info);
        }

        private void SafeLogCounters()
        {
            try
            {
                LogCounters();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} counter log error: {ex.Message}", LogLevel.Debug);
            }
        }

        private void LogCounters()
        {
            string user = BuildAndResetUserCounterSummary();
            string kernel = BuildKernelCounterSummary();
            long flushRows = Interlocked.Exchange(ref _interactionFlushRows, 0);
            long flushEvents = Interlocked.Exchange(ref _interactionFlushEvents, 0);
            long flushZeroDelta = Interlocked.Exchange(ref _interactionFlushZeroDelta, 0);
            long flushErrors = Interlocked.Exchange(ref _interactionFlushErrors, 0);
            long flushIterations = Interlocked.Exchange(ref _interactionFlushIterations, 0);
            long resolveHits = Interlocked.Exchange(ref _resolveHits, 0);
            long resolveMisses = Interlocked.Exchange(ref _resolveMisses, 0);
            long unknownPerms = Interlocked.Exchange(ref _unknownPermissionMasks, 0);
            long policyReloads = Interlocked.Exchange(ref _policyReloads, 0);
            long messagesSent = Interlocked.Exchange(ref _messagesSent, 0);
            long sendErrors = Interlocked.Exchange(ref _messageSendErrors, 0);
            long summaryMessages = Interlocked.Exchange(ref _interactionSummaryMessages, 0);
            string unknownPermissionSummary = BuildAndResetUnknownPermissionSummary();
            string flush = $"rows={flushRows},events={flushEvents},zero_delta={flushZeroDelta},iterations={flushIterations},errors={flushErrors}";
            string resolver = $"hit={resolveHits},miss={resolveMisses},learned={_sidResolver.LearnedCount}";
            WintapLogger.Log.Append($"{SensorName} counters (last ~60s): interaction_hook={_interactionAttachMode},links={_additionalLinks.Count + 1},policy_epoch={Interlocked.Read(ref _policyEpoch)} user=[{user}] kernel=[{kernel}] flush=[{flush}] resolver=[{resolver}] messages=[sent={messagesSent},send_errors={sendErrors},interaction_summaries={summaryMessages}] unknown_perm_masks={unknownPerms} unknown_perm_top=[{unknownPermissionSummary}] policy_reloads={policyReloads}", LogLevel.Info);
        }

        private WintapMessage CreateMessage(int pid, long fileTimeUtc, WintapMessage.MessageTypeEnum messageType, string processName)
        {
            var message = new WintapMessage(DateTime.FromFileTimeUtc(fileTimeUtc), pid, messageType)
            {
                ActivityType = WintapMessage.ActivityTypeEnum.Other,
                ActivityId = string.Empty,
                CorrelationId = string.Empty,
                ProcessName = string.IsNullOrWhiteSpace(processName) ? "unknown" : processName,
                PidHash = string.Empty,
            };
            EventChannel.TryPopulateCurrentProcessIdentity(message);
            if (string.IsNullOrWhiteSpace(message.PidHash))
            {
                message.PidHash = _pidHashGenerator.GenPidHash(pid, fileTimeUtc);
            }
            return message;
        }

        private void EmitInteractionMessages(int pid, long eventTime, uint ssid, uint tsid,
                                             string scontext, string tcontext, string tclass,
                                             string permissionList, uint requestedMask,
                                             int eventCount, long firstSeenEventTime,
                                             long lastSeenEventTime, bool novel,
                                             string processName)
        {
            string[] permissions = string.IsNullOrWhiteSpace(permissionList)
                ? new[] { $"0x{requestedMask:x}" }
                : permissionList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            foreach (string permission in permissions)
            {
                var message = CreateMessage(pid, eventTime, WintapMessage.MessageTypeEnum.SELinuxInteraction, processName);
                message.SELinuxInteraction = new WintapMessage.SELinuxInteractionData
                {
                    SSid = ssid,
                    TSid = tsid,
                    SContext = scontext,
                    TContext = tcontext,
                    TClass = tclass,
                    Permission = permission,
                    RequestedMask = requestedMask,
                    EventCount = eventCount,
                    FirstSeenEventTime = firstSeenEventTime,
                    LastSeenEventTime = lastSeenEventTime,
                    Novel = novel,
                    PolicyEpoch = unchecked((int)Interlocked.Read(ref _policyEpoch)),
                    PID = pid,
                };
                SendMessage(message);
            }
        }

        private void SendMessage(WintapMessage message)
        {
            try
            {
                EventChannel.Send(message);
                Interlocked.Increment(ref _messagesSent);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _messageSendErrors);
                WintapLogger.Log.Append($"{SensorName} failed to send message type={message.MessageType}: {ex.Message}", LogLevel.Error);
            }
        }

        private string DecodePermissionsByClassName(string className, uint mask, out uint unknownBits)
        {
            unknownBits = 0;
            if (mask == 0)
            {
                return string.Empty;
            }

            if (!_permissionDecoder.TryGetClassIndex(className, out uint classIndex))
            {
                unknownBits = mask;
                return $"0x{mask:x}";
            }

            return _permissionDecoder.DecodePermissions(classIndex, mask, out unknownBits);
        }

        private void RecordUnknownPermission(uint tclass, uint requested, uint unknownBits, string className)
        {
            string key = $"class={className}({tclass}),requested=0x{requested:x},unknown=0x{unknownBits:x}";
            lock (_unknownPermissionLock)
            {
                _unknownPermissionBuckets.TryGetValue(key, out long count);
                _unknownPermissionBuckets[key] = count + 1;
            }
        }

        private string BuildAndResetUnknownPermissionSummary()
        {
            lock (_unknownPermissionLock)
            {
                if (_unknownPermissionBuckets.Count == 0)
                {
                    return string.Empty;
                }

                var entries = new List<KeyValuePair<string, long>>(_unknownPermissionBuckets);
                entries.Sort((left, right) =>
                {
                    int countCompare = right.Value.CompareTo(left.Value);
                    return countCompare != 0 ? countCompare : string.CompareOrdinal(left.Key, right.Key);
                });

                int count = Math.Min(entries.Count, 5);
                var parts = new List<string>();
                for (int i = 0; i < count; i++)
                {
                    parts.Add($"{entries[i].Key}:count={entries[i].Value}");
                }

                _unknownPermissionBuckets.Clear();
                return string.Join(" | ", parts);
            }
        }

        private void SafeFlushInteractions()
        {
            try
            {
                FlushInteractions();
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _interactionFlushErrors);
                WintapLogger.Log.Append($"{SensorName} interaction flush error: {ex.Message}", LogLevel.Error);
            }
        }

        private void FlushInteractions()
        {
            if (_interactionMapFd < 0)
            {
                return;
            }

            IntPtr currentKey = IntPtr.Zero;
            IntPtr nextKey = Marshal.AllocHGlobal(InteractionKeySize);
            IntPtr lookupKey = Marshal.AllocHGlobal(InteractionKeySize);
            IntPtr value = Marshal.AllocHGlobal(InteractionValueSize);
            try
            {
                int iterations = 0;
                while (LibBpf.bpf_map_get_next_key(_interactionMapFd, currentKey, nextKey) == 0)
                {
                    iterations++;
                    Interlocked.Increment(ref _interactionFlushIterations);
                    if (iterations > 20000)
                    {
                        Interlocked.Increment(ref _interactionFlushErrors);
                        WintapLogger.Log.Append($"{SensorName} interaction flush stopped after {iterations} iterations", LogLevel.Warn);
                        break;
                    }

                    CopyMemory(nextKey, lookupKey, InteractionKeySize);
                    if (LibBpf.bpf_map_lookup_elem(_interactionMapFd, lookupKey, value) == 0)
                    {
                        ulong count = ReadUInt64(value, InteractionValueCountOffset);
                        ulong emittedAtFlush = ReadUInt64(value, InteractionValueEmittedAtFlushOffset);
                        if (count > emittedAtFlush)
                        {
                            ulong delta = count - emittedAtFlush;
                            uint ssid = ReadUInt32(lookupKey, 0);
                            uint tsid = ReadUInt32(lookupKey, 4);
                            uint tclass = ReadUInt32(lookupKey, 8);
                            uint requested = ReadUInt32(lookupKey, 12);
                            int firstPid = ReadInt32(value, InteractionValueFirstPidOffset);
                            string scontext = _sidResolver.ResolveSource(ssid, firstPid, out bool sourceHit);
                            CountResolve(sourceHit);
                            string tcontext = _sidResolver.ResolveKnown(tsid, out bool targetHit);
                            CountResolve(targetHit);
                            string permissions = _permissionDecoder.DecodePermissions(tclass, requested, out uint unknownBits);
                            if (unknownBits != 0)
                            {
                                Interlocked.Increment(ref _unknownPermissionMasks);
                                RecordUnknownPermission(tclass, requested, unknownBits, _permissionDecoder.GetClassName(tclass));
                            }

                            long firstSeen = ConvertKernelTimestampToUtcDateTime(ReadUInt64(value, InteractionValueFirstTimestampOffset)).ToFileTimeUtc();
                            long lastSeen = ConvertKernelTimestampToUtcDateTime(ReadUInt64(value, InteractionValueLastTimestampOffset)).ToFileTimeUtc();
                            string firstComm = ReadString(value, InteractionValueFirstCommOffset, 16);
                            EmitInteractionMessages(
                                pid: firstPid,
                                eventTime: firstSeen,
                                ssid: ssid,
                                tsid: tsid,
                                scontext: scontext,
                                tcontext: tcontext,
                                tclass: _permissionDecoder.GetClassName(tclass),
                                permissionList: permissions,
                                requestedMask: requested,
                                eventCount: unchecked((int)Math.Min(delta, (ulong)int.MaxValue)),
                                firstSeenEventTime: firstSeen,
                                lastSeenEventTime: lastSeen,
                                novel: false,
                                processName: firstComm);
                            Interlocked.Increment(ref _interactionSummaryMessages);

                            WriteUInt64(value, InteractionValueEmittedAtFlushOffset, count);
                            if (LibBpf.bpf_map_update_elem(_interactionMapFd, lookupKey, value, 0) == 0)
                            {
                                Interlocked.Increment(ref _interactionFlushRows);
                                Interlocked.Add(ref _interactionFlushEvents, unchecked((long)delta));
                            }
                            else
                            {
                                Interlocked.Increment(ref _interactionFlushErrors);
                            }
                        }
                        else
                        {
                            Interlocked.Increment(ref _interactionFlushZeroDelta);
                        }
                    }

                    if (currentKey == IntPtr.Zero)
                    {
                        currentKey = Marshal.AllocHGlobal(InteractionKeySize);
                    }
                    CopyMemory(nextKey, currentKey, InteractionKeySize);
                }
            }
            finally
            {
                if (currentKey != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(currentKey);
                }
                Marshal.FreeHGlobal(nextKey);
                Marshal.FreeHGlobal(lookupKey);
                Marshal.FreeHGlobal(value);
            }
        }

        private void SafePollPolicyEpoch()
        {
            try
            {
                long ticks = GetPolicyLastWriteTicks();
                long previous = Interlocked.Read(ref _policyLastWriteTicks);
                if (ticks == 0 || previous == 0 || ticks == previous)
                {
                    return;
                }

                Interlocked.Exchange(ref _policyLastWriteTicks, ticks);
                long epoch = Interlocked.Increment(ref _policyEpoch);
                Interlocked.Increment(ref _policyReloads);
                _sidResolver.Clear();
                DeleteInteractionMapEntries();
                WintapLogger.Log.Append($"{SensorName} policy reload detected; policy_epoch={epoch}, learned SID cache cleared, interaction map cleared", LogLevel.Warn);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} policy poll error: {ex.Message}", LogLevel.Debug);
            }
        }

        private void DeleteInteractionMapEntries()
        {
            if (_interactionMapFd < 0)
            {
                return;
            }

            IntPtr currentKey = IntPtr.Zero;
            IntPtr nextKey = Marshal.AllocHGlobal(InteractionKeySize);
            try
            {
                int iterations = 0;
                while (LibBpf.bpf_map_get_next_key(_interactionMapFd, currentKey, nextKey) == 0)
                {
                    iterations++;
                    if (iterations > 20000)
                    {
                        break;
                    }

                    LibBpf.bpf_map_delete_elem(_interactionMapFd, nextKey);
                    currentKey = IntPtr.Zero;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(nextKey);
            }
        }

        private static int GetConfiguredFlushSeconds()
        {
            int configured = ConfigManager.GetValue<int>("WINTAP_SELINUX_FLUSH_SEC");
            return configured > 0 ? configured : 30;
        }

        private static long GetPolicyLastWriteTicks()
        {
            try
            {
                return File.GetLastWriteTimeUtc("/sys/fs/selinux/policy").Ticks;
            }
            catch
            {
                return 0;
            }
        }

        private void CountResolve(bool hit)
        {
            if (hit)
            {
                Interlocked.Increment(ref _resolveHits);
            }
            else
            {
                Interlocked.Increment(ref _resolveMisses);
            }
        }

        private string BuildAndResetUserCounterSummary()
        {
            var parts = new List<string>();
            for (int i = 0; i < _consumedByRecordType.Length; i++)
            {
                long consumed = Interlocked.Exchange(ref _consumedByRecordType[i], 0);
                long errors = Interlocked.Exchange(ref _decodeErrorsByRecordType[i], 0);
                if (consumed > 0 || errors > 0)
                {
                    parts.Add($"{RecordName(i)}:consumed={consumed},decode_errors={errors}");
                }
            }

            return string.Join("; ", parts);
        }

        private string BuildKernelCounterSummary()
        {
            if (_statsMapFd < 0)
            {
                return string.Empty;
            }

            var parts = new List<string>();
            AddKernelCounter(parts, 1, "avc_emitted");
            AddKernelCounter(parts, 2, "transition_emitted");
            AddKernelCounter(parts, 3, "interaction_novel");
            AddKernelCounter(parts, 4, "interaction_folded");
            AddKernelCounter(parts, 17, "avc_ring_fail");
            AddKernelCounter(parts, 18, "transition_ring_fail");
            AddKernelCounter(parts, 19, "interaction_ring_fail");
            AddKernelCounter(parts, 33, "avc_self_drop");
            AddKernelCounter(parts, 34, "transition_self_drop");
            AddKernelCounter(parts, 35, "interaction_self_drop");
            AddKernelCounter(parts, 49, "string_truncated");
            AddKernelCounter(parts, 50, "force_wakeup");
            return string.Join(",", parts);
        }

        private void AddKernelCounter(List<string> parts, uint key, string name)
        {
            if (LibBpf.bpf_map_lookup_elem(_statsMapFd, ref key, out ulong value) == 0 && value > 0)
            {
                parts.Add($"{name}={value}");
            }
        }

        private static string RecordName(int index)
        {
            return index switch
            {
                1 => "avc",
                2 => "transition",
                3 => "interaction",
                _ => "unknown",
            };
        }

        private static int GetRecordIndex(uint recordType)
        {
            return recordType >= 1 && recordType <= 3 ? (int)recordType : 0;
        }

        private static void CountByRecord(long[] counters, int index)
        {
            Interlocked.Increment(ref counters[index]);
        }

        private static uint ReadUInt32(IntPtr data, int offset)
        {
            return unchecked((uint)Marshal.ReadInt32(data, offset));
        }

        private static int ReadInt32(IntPtr data, int offset)
        {
            return Marshal.ReadInt32(data, offset);
        }

        private static ulong ReadUInt64(IntPtr data, int offset)
        {
            return unchecked((ulong)Marshal.ReadInt64(data, offset));
        }

        private static string ReadString(IntPtr data, int offset, int maxBytes)
        {
            byte[] buffer = new byte[maxBytes];
            Marshal.Copy(IntPtr.Add(data, offset), buffer, 0, maxBytes);
            int length = Array.IndexOf(buffer, (byte)0);
            if (length < 0)
            {
                length = maxBytes;
            }
            return length == 0 ? string.Empty : Encoding.UTF8.GetString(buffer, 0, length).TrimEnd('\0', '\r', '\n', ' ', '\t');
        }

        private static void WriteUInt64(IntPtr data, int offset, ulong value)
        {
            Marshal.WriteInt64(data, offset, unchecked((long)value));
        }

        private static void CopyMemory(IntPtr source, IntPtr destination, int length)
        {
            byte[] buffer = new byte[length];
            Marshal.Copy(source, buffer, 0, length);
            Marshal.Copy(buffer, 0, destination, length);
        }

        private static bool IsSELinuxPresent()
        {
            return File.Exists("/sys/fs/selinux/enforce");
        }

        private static bool IsSELinuxEnforcing()
        {
            try
            {
                return File.ReadAllText("/sys/fs/selinux/enforce").Trim() == "1";
            }
            catch
            {
                return false;
            }
        }

        private void LogSELinuxStartupCensus()
        {
            string mode = "unknown";
            try
            {
                string enforce = File.ReadAllText("/sys/fs/selinux/enforce").Trim();
                mode = enforce == "1" ? "enforcing" : enforce == "0" ? "permissive" : enforce;
            }
            catch { }

            bool tracepointVisible = File.Exists("/sys/kernel/tracing/events/avc/selinux_audited/format") ||
                                     File.Exists("/sys/kernel/debug/tracing/events/avc/selinux_audited/format");
            bool btfPresent = File.Exists("/sys/kernel/btf/vmlinux");
            WintapLogger.Log.Append($"{SensorName} startup census: mode={mode}, btf_present={btfPresent}, selinux_audited_tracepoint_visible={tracepointVisible}", LogLevel.Info);
        }

        private DateTime ConvertKernelTimestampToUtcDateTime(ulong timestampNs)
        {
            long realtimeNs = unchecked((long)timestampNs) + _monotonicToRealtimeOffsetNs;
            long ticks = realtimeNs / 100;
            return DateTime.UnixEpoch.AddTicks(ticks).ToUniversalTime();
        }

        private static long ComputeMonotonicToRealtimeOffsetNs()
        {
            try
            {
                long realtimeNs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000L;
                long monotonicNs = Stopwatch.GetTimestamp() * 1_000_000_000L / Stopwatch.Frequency;
                return realtimeNs - monotonicNs;
            }
            catch
            {
                return 0;
            }
        }

        protected override void OnStopping()
        {
            _counterLogTimer?.Dispose();
            _counterLogTimer = null;
            _interactionFlushTimer?.Dispose();
            _interactionFlushTimer = null;
            _policyPollTimer?.Dispose();
            _policyPollTimer = null;
            SafeFlushInteractions();
            SafeLogCounters();

            foreach (IntPtr link in _additionalLinks)
            {
                if (link != IntPtr.Zero)
                {
                    LibBpf.bpf_link__destroy(link);
                }
            }
            _additionalLinks.Clear();
        }
    }
}
