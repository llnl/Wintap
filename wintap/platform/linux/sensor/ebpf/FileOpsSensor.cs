using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.shared.helpers;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Unified file operations sensor - tracks open/read/write/close/mmap/unlink
    /// Attaches MULTIPLE eBPF programs from one .bpf.o file
    /// </summary>
    internal class FileOpsSensor : BaseEbpfSensor
    {
        private ConcurrentDictionary<int, ConcurrentDictionary<uint, string>> _fdToPath;
        private List<IntPtr> _additionalLinks;
        private readonly string? _dataRoot;
        private readonly string? _normalizedDataRoot;
        private readonly int _sendQueueCapacity;
        private BlockingCollection<QueuedFileEvent> _sendQueue;
        private Thread? _sendWorker;
        private int _statsMapFd = -1;
        private int _policyStatsMapFd = -1;
        private readonly List<string> _denyCommRules = new List<string>();
        private readonly ulong[] _policyStatsLast = new ulong[128];
        private readonly bool _lowercasePaths;
        private readonly long _monotonicToRealtimeOffsetNs;

        private const uint FileOpOpen = 1;
        private const uint FileOpRead = 2;
        private const uint FileOpWrite = 3;
        private const uint FileOpClose = 4;
        private const uint FileOpMmap = 5;
        private const uint FileOpUnlink = 6;
        // Directory-handle open: internal record that feeds the dir-identity
        // index; never becomes a WintapMessage.
        private const uint FileOpDirOpen = 7;
        private const int OpSlots = 8;

        private const uint FileRecordPath = 1;
        private const uint FileRecordFd = 2;
        private const int RecordTypeOffset = 0;
        private const int CommonPidOffset = 4;
        private const int CommonCommOffset = 8;
        private const int FdRecordTimestampOffset = 24;
        private const int FdRecordFdOffset = 32;
        private const int FdRecordBytesOffset = 36;
        private const int FdRecordOpTypeOffset = 40;
        private const int PathRecordFilenameOffset = 24;
        private const int PathRecordTimestampOffset = 280;
        private const int PathRecordFdOffset = 288;
        private const int PathRecordBytesOffset = 292;
        private const int PathRecordOpTypeOffset = 296;
        private const int PathRecordDirFdOffset = 300;
        private const int PathRecordFileInoOffset = 304;
        private const int PathRecordDirInoOffset = 312;
        private const int PathRecordFileDevOffset = 320;
        private const int PathRecordDirDevOffset = 324;
        private const int PathRecordMntNsOffset = 328;
        private const int FdRecordFileInoOffset = 48;
        private const int FdRecordFileDevOffset = 56;
        private const int AtFdcwd = -100;

        [DllImport("libc", SetLastError = true)]
        private static extern long readlink(string path, byte[] buffer, UIntPtr bufferSize);

        private readonly long[] _userConsumedByOp = new long[OpSlots];
        private readonly long[] _userEmittedByOp = new long[OpSlots];
        private readonly long[] _userNoPathDropsByOp = new long[OpSlots];
        private readonly long[] _userDataRootDropsByOp = new long[OpSlots];
        private readonly long[] _userEtlDropsByOp = new long[OpSlots];
        private readonly long[] _userParquetDropsByOp = new long[OpSlots];
        private readonly long[] _userFallbackHitsByOp = new long[OpSlots];
        private readonly long[] _userFallbackMissesByOp = new long[OpSlots];
        private long _droppedSys;
        private long _droppedProc;
        private long _droppedDev;
        private long _queueDrops;
        private long _queueHighWatermark;
        private long _relativeOpenResolves;
        private long _relativeOpenResolveMisses;
        private long _relativeOpenResolvedViaFd;
        private long _relativeOpenResolvedViaDirFd;
        private long _relativeOpenResolvedViaCwd;
        private long _relativeOpenOpenedFdLookupMisses;
        private long _relativeOpenDirFdLookupMisses;
        private long _relativeOpenCwdLookupMisses;
        private long _relativeOpenUnsupportedDirFd;
        private long _relativeOpenResolvedViaDirIndex;
        private long _relativeOpenDirIndexMisses;
        private long _relativeOpenMissProducerDead;
        private long _relativeOpenMissProducerAlive;
        private long _dirOpenConsumed;
        private long _dirOpenIndexed;
        private long _dirOpenUnresolved;

        // Global directory-identity index: (mnt_ns, s_dev, i_ino) -> absolute
        // dir path, learned from DIR_OPEN records. Identity-keyed (never
        // (pid, fd)) so it survives fd close and producer exit, and is shared
        // across processes. LRU-bounded (fop-13d) and namespace-qualified
        // (fop-13c); capacity via WINTAP_FILEOPS_DIR_INDEX_MAX.
        private readonly DirIdentityIndex _dirIdentityIndex;

        // fop-11: short-interval emit-first aggregation (pid, path, op).
        private readonly FileOpsAggregator _aggregator;
        private readonly bool _aggregationEnabled;
        private readonly int _aggregationWindowMs;
        private System.Threading.Timer _aggregationFlushTimer;
        private System.Threading.Timer _counterLogTimer;
        private long _aggFirstEmits;
        private long _aggSummaryEnqueueFailures;
        private long _aggBytesClamped;

        // Kernel event timestamp -> userspace ring-buffer callback latency.
        // Keep fixed buckets so long captures can distinguish normal scheduling
        // jitter from records retained in the ring for seconds or minutes.
        private readonly long[] _deliveryLatencyBuckets = new long[7];
        private long _deliveryLatencySamples;
        private long _deliveryLatencyTotalNs;
        private long _deliveryLatencyMaxNs;

        // P3: sampled sender-path cost (every Nth EventChannel.Send).
        private const int SendSampleInterval = 64;
        private long _sendSampleCounter;
        private long _sendSampleTicks;
        private long _sendProcessResolveSampleTicks;
        private long _sendHealthSampleTicks;
        private long _sendEsperSampleTicks;
        private long _sendSampleCount;
        private long _sendSampleMaxTicks;
        private long _sendProcessResolveSampleMaxTicks;
        private long _sendHealthSampleMaxTicks;
        private long _sendEsperSampleMaxTicks;
        private readonly object _sendTimingLock = new object();
        private long _nextCounterLogTickMs;
        private readonly object _measurementLock = new object();
        private readonly Dictionary<string, MeasurementAggregate> _emitByComm = new Dictionary<string, MeasurementAggregate>(StringComparer.Ordinal);
        private readonly Dictionary<string, MeasurementAggregate> _emitByPrefix = new Dictionary<string, MeasurementAggregate>(StringComparer.Ordinal);
        private readonly Dictionary<(int Pid, string Path), long> _recentOpenSeenMs = new Dictionary<(int Pid, string Path), long>();
        private long _openDuplicateWindowTotal;
        private long _openDuplicateWindowHits;
        private int _duplicatePruneCountdown = 1024;

        private const int MeasurementTopN = 5;
        private const int MaxMeasurementBuckets = 128;
        private const int MaxDuplicateKeys = 16384;
        private const long DuplicateOpenWindowMs = 1000;

        protected override string BpfObjectFileName => "file_ops_tracer.bpf.o";
        protected override string[] FallbackBpfObjectFileNames => new[] { "file_ops_tracepoint.bpf.o" };
        protected override string BpfProgramName => "trace_openat";  // First program

        internal FileOpsSensor()
        {
            SensorName = "FileOps";
            _fdToPath = new ConcurrentDictionary<int, ConcurrentDictionary<uint, string>>();
            _additionalLinks = new List<IntPtr>();
            _sendQueueCapacity = GetConfiguredQueueCapacity();
            _sendQueue = new BlockingCollection<QueuedFileEvent>(new ConcurrentQueue<QueuedFileEvent>(), _sendQueueCapacity);
            _lowercasePaths = OperatingSystem.IsWindows();
            _monotonicToRealtimeOffsetNs = KernelTimestampConverter.ComputeMonotonicToRealtimeOffsetNanoseconds();

            try
            {
                _dataRoot = ConfigManager.GetValue<string>("WINTAP_DATA_ROOT");
                _normalizedDataRoot = NormalizeConfiguredPath(_dataRoot);
            }
            catch
            {
                _dataRoot = null;
                _normalizedDataRoot = null;
            }

            _nextCounterLogTickMs = Environment.TickCount64 + 60_000;

            _dirIdentityIndex = new DirIdentityIndex(GetConfiguredDirIndexMaxEntries());
            _aggregationEnabled = GetConfiguredAggregationEnabled();
            _aggregationWindowMs = GetConfiguredAggregationWindowMs();
            if (_aggregationEnabled)
            {
                _aggregator = new FileOpsAggregator(
                    _aggregationWindowMs,
                    GetConfiguredAggregationMaxKeys(),
                    EmitAggregateSummary);
            }
        }

        private static int GetConfiguredDirIndexMaxEntries()
        {
            try
            {
                int configured = ConfigManager.GetValue<int>("WINTAP_FILEOPS_DIR_INDEX_MAX");
                if (configured > 0)
                {
                    return configured;
                }
            }
            catch { }
            // Raised from 16384 after field bundle 041718 showed filesystem
            // walks pinning the cap; ~10 MB worst case at 65536 entries.
            return 65536;
        }

        private static bool GetConfiguredAggregationEnabled()
        {
            try
            {
                string value = ConfigManager.GetValue<string>("WINTAP_FILEOPS_AGG_ENABLED");
                if (!string.IsNullOrEmpty(value) &&
                    (string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) || value == "0"))
                {
                    return false;
                }
            }
            catch { }
            return true;
        }

        private static int GetConfiguredAggregationWindowMs()
        {
            try
            {
                int configured = ConfigManager.GetValue<int>("WINTAP_FILEOPS_AGG_WINDOW_MS");
                if (configured > 0)
                {
                    return configured;
                }
            }
            catch { }
            return 1000;
        }

        private static int GetConfiguredAggregationMaxKeys()
        {
            try
            {
                int configured = ConfigManager.GetValue<int>("WINTAP_FILEOPS_AGG_MAX_KEYS");
                if (configured > 0)
                {
                    return configured;
                }
            }
            catch { }
            return 32768;
        }

        public override bool Start()
        {
            RuntimeCapabilities.Feature(CapabilityKey, "aggregationEnabled", _aggregationEnabled);
            RuntimeCapabilities.Feature(CapabilityKey, "aggregationWindowMs", _aggregationWindowMs);
            RuntimeCapabilities.Feature(CapabilityKey, "aggregationMaxKeys", GetConfiguredAggregationMaxKeys());
            RuntimeCapabilities.Feature(CapabilityKey, "directoryIndexMaxEntries", GetConfiguredDirIndexMaxEntries());
            // Call base to attach first program (trace_openat)
            if (!base.Start())
                return false;

            StartSendWorker();

            InitializeStatsMap();
            InitializeSelfPidFilter();
            if (!InitializeDenyCommPolicy())
            {
                Stop();
                return false;
            }
            RuntimeCapabilities.Feature(CapabilityKey, "denyComms", _denyCommRules.ToArray());
            RuntimeCapabilities.Feature(CapabilityKey, "sendQueueCapacity", _sendQueueCapacity);
            RuntimeCapabilities.Feature(CapabilityKey, "sendQueueDropPolicy", "drop-newest");

            // Attach additional programs from the same .bpf.o file
            try
            {
                var programNames = new[]
                {
                    // Support both openat(2) and legacy open(2) paths.
                    // Program names in libbpf are limited to 15 chars (BPF_OBJ_NAME_LEN-1);
                    // keep these short so lookups work reliably across distros.
                    "t_openat_ent",
                    "t_open_ent",
                    "t_open_exit",
                    "t_read_ent",
                    "t_write_ent",
                    "t_close",
                    "t_mmap",
                    "t_unlinkat",
                    "t_unlink",
                };

                foreach (var progName in programNames)
                {
                    IntPtr link = AttachProgram(progName);
                    if (link == IntPtr.Zero) continue;

                    _additionalLinks.Add(link);
                    WintapLogger.Log.Append($"{SensorName} attached '{progName}'", LogLevel.Info);
                }

                WintapLogger.Log.Append($"{SensorName} attached {_additionalLinks.Count + 1} programs total", LogLevel.Info);
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} error attaching additional programs: {ex.Message}", LogLevel.Error);
                Stop();
                return false;
            }
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                uint recordType = ReadUInt32(data, RecordTypeOffset);
                bool isPathRecord = recordType == FileRecordPath;
                bool isFdRecord = recordType == FileRecordFd;
                if (!isPathRecord && !isFdRecord)
                {
                    return 0;
                }

                uint opType = ReadUInt32(data, isPathRecord ? PathRecordOpTypeOffset : FdRecordOpTypeOffset);
                int opIndex = GetOpIndex(opType);
                CountByOp(_userConsumedByOp, opIndex);

                int pid = (int)ReadUInt32(data, CommonPidOffset);
                uint fd = ReadUInt32(data, isPathRecord ? PathRecordFdOffset : FdRecordFdOffset);
                uint bytes = ReadUInt32(data, isPathRecord ? PathRecordBytesOffset : FdRecordBytesOffset);
                int dirfd = isPathRecord ? ReadInt32(data, PathRecordDirFdOffset) : 0;
                ulong timestampNs = ReadUInt64(data, isPathRecord ? PathRecordTimestampOffset : FdRecordTimestampOffset);
                RecordDeliveryLatency(timestampNs);
                uint fileDev = ReadUInt32(data, isPathRecord ? PathRecordFileDevOffset : FdRecordFileDevOffset);
                ulong fileIno = ReadUInt64(data, isPathRecord ? PathRecordFileInoOffset : FdRecordFileInoOffset);
                uint dirDev = isPathRecord ? ReadUInt32(data, PathRecordDirDevOffset) : 0;
                ulong dirIno = isPathRecord ? ReadUInt64(data, PathRecordDirInoOffset) : 0;
                uint mntNs = isPathRecord ? ReadUInt32(data, PathRecordMntNsOffset) : 0;
                string rawFilePath = isPathRecord ? ReadNullTerminatedString(data, PathRecordFilenameOffset, 256) : "";
                string filePath = rawFilePath;

                // Directory-handle opens are internal: they teach the
                // dir-identity index and never become WintapMessages.
                if (isPathRecord && opType == FileOpDirOpen)
                {
                    HandleDirOpenRecord(pid, fd, dirfd, rawFilePath, mntNs, fileDev, fileIno, dirDev, dirIno);
                    MaybeLogCounters();
                    return 0;
                }

                if (isPathRecord && opType == FileOpOpen)
                {
                    filePath = ResolveOpenPath(pid, fd, dirfd, mntNs, dirDev, dirIno, filePath);
                }
                
                // Resolve file path for FD-based operations (read/write/close/mmap)
                if (string.IsNullOrEmpty(filePath))
                {
                    filePath = opType == FileOpClose
                        ? GetCachedPathFromFd(pid, fd)
                        : GetPathFromFd(pid, fd, opIndex);
                }

                if (opType == FileOpClose)
                {
                    RemoveFdPath(pid, fd);
                }
                
                // Skip if still no path
                if (string.IsNullOrEmpty(filePath))
                {
                    CountByOp(_userNoPathDropsByOp, opIndex);
                    MaybeLogCounters();
                    return 0;
                }

                filePath = NormalizeFilePath(filePath);

                // Drop pseudo-filesystem activity early; these are high-volume and
                // rarely useful for host telemetry, and they can overwhelm the pipeline.
                if (IsPseudoPath(filePath, out PseudoPathBucket bucket))
                {
                    CountPseudoDrop(bucket);
                    MaybeLogCounters();
                    return 0;
                }

                // Avoid self-feedback and noise from our own data root. This can
                // overwhelm the serializer and destroy signal quality.
                if (!string.IsNullOrEmpty(_normalizedDataRoot))
                {
                    if (filePath.StartsWith(_normalizedDataRoot, StringComparison.Ordinal))
                    {
                        CountByOp(_userDataRootDropsByOp, opIndex);
                        MaybeLogCounters();
                        return 0;
                    }
                }
                
                // Skip .etl files (feedback loop prevention)
                if (filePath.EndsWith(".etl"))
                {
                    CountByOp(_userEtlDropsByOp, opIndex);
                    MaybeLogCounters();
                    return 0;
                }

                // Skip parquet writes as well; these are high-volume and not
                // interesting for host telemetry.
                if (filePath.EndsWith(".parquet") || filePath.EndsWith(".parquet.active"))
                {
                    CountByOp(_userParquetDropsByOp, opIndex);
                    MaybeLogCounters();
                    return 0;
                }

                // Map eBPF op_type to ActivityType
                WintapMessage.ActivityTypeEnum activityType = opType switch
                {
                    1 => WintapMessage.ActivityTypeEnum.Open,
                    2 => WintapMessage.ActivityTypeEnum.Read,
                    3 => WintapMessage.ActivityTypeEnum.Write,
                    4 => WintapMessage.ActivityTypeEnum.Close,
                    5 => WintapMessage.ActivityTypeEnum.Read,   // mmap is like read
                    6 => WintapMessage.ActivityTypeEnum.Delete,
                    _ => WintapMessage.ActivityTypeEnum.Other
                };

                // Store FD -> Path mapping for open operations
                if (opType == FileOpOpen)
                {
                    StoreFdPath(pid, fd, filePath);
                }
                
                var message = new WintapMessage(
                    ConvertKernelTimestampToUtcDateTime(timestampNs),
                    pid,
                    WintapMessage.MessageTypeEnum.File
                );

                message.ActivityType = activityType;
                
                message.File = new WintapMessage.FileActivityObject
                {
                    Path = filePath,
                    BytesRequested = (int)bytes,
                    PID = pid
                };

                message.ActivityId = "";
                message.CorrelationId = "";
                message.PidHash = "";
                message.ProcessName = ReadNullTerminatedString(data, CommonCommOffset, 16) ?? "unknown";

                // Stamp current-process identity while the producer is still live,
                // so deep sender backlog does not turn short-lived processes into
                // resolver misses later.
                EventChannel.TryPopulateCurrentProcessIdentity(message);

                // fop-11: emit-first aggregation. The first occurrence of a
                // (pid, path, op) key in a window flows through unchanged;
                // repeats inside the window fold into a summary row emitted at
                // window expiry, carrying the identity stamped above.
                if (_aggregator != null &&
                    _aggregator.TryAbsorb(pid, filePath, opType, bytes, timestampNs,
                                          message.ProcessName, message.PidHash,
                                          Environment.TickCount64))
                {
                    MaybeLogCounters();
                    return 0;
                }

                message.File.EventCount = 1;
                message.File.FirstSeenEventTime = message.EventTime;
                message.File.LastSeenEventTime = message.EventTime;

                if (TryEnqueueMessage(message, opIndex))
                {
                    Interlocked.Increment(ref _aggFirstEmits);
                    RecordMeasurement(opIndex, opType, pid, message.ProcessName, filePath, Environment.TickCount64);
                }

                MaybeLogCounters();
                return 0;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} event handler error: {ex.Message}", LogLevel.Error);
                return -1;
            }
        }

        private enum PseudoPathBucket
        {
            Sys,
            Proc,
            Dev,
        }

        private static bool IsPseudoPath(string normalizedLowerPath, out PseudoPathBucket bucket)
        {
            // normalizedLowerPath is expected to be already lowercased.
            if (string.IsNullOrEmpty(normalizedLowerPath))
            {
                bucket = PseudoPathBucket.Proc;
                return false;
            }

            // Keep comparisons simple and cheap; these paths are extremely common.
            if (normalizedLowerPath == "/sys" || normalizedLowerPath.StartsWith("/sys/", StringComparison.Ordinal))
            {
                bucket = PseudoPathBucket.Sys;
                return true;
            }
            if (normalizedLowerPath == "/proc" || normalizedLowerPath.StartsWith("/proc/", StringComparison.Ordinal))
            {
                bucket = PseudoPathBucket.Proc;
                return true;
            }
            if (normalizedLowerPath == "/dev" || normalizedLowerPath.StartsWith("/dev/", StringComparison.Ordinal))
            {
                bucket = PseudoPathBucket.Dev;
                return true;
            }

            bucket = PseudoPathBucket.Proc;
            return false;
        }

        private void CountPseudoDrop(PseudoPathBucket bucket)
        {
            switch (bucket)
            {
                case PseudoPathBucket.Sys:
                    Interlocked.Increment(ref _droppedSys);
                    break;
                case PseudoPathBucket.Proc:
                    Interlocked.Increment(ref _droppedProc);
                    break;
                case PseudoPathBucket.Dev:
                    Interlocked.Increment(ref _droppedDev);
                    break;
            }
        }

        private void MaybeLogCounters()
        {
            long now = Environment.TickCount64;
            long next = Interlocked.Read(ref _nextCounterLogTickMs);
            if (now < next)
            {
                return;
            }

            // Win the race to log for this interval.
            if (Interlocked.CompareExchange(ref _nextCounterLogTickMs, now + 60_000, next) != next)
            {
                return;
            }

            long sys = Interlocked.Exchange(ref _droppedSys, 0);
            long proc = Interlocked.Exchange(ref _droppedProc, 0);
            long dev = Interlocked.Exchange(ref _droppedDev, 0);
            long queueDrops = Interlocked.Exchange(ref _queueDrops, 0);
            long queueHighWatermark = Interlocked.Exchange(ref _queueHighWatermark, 0);
            long relativeOpenResolves = Interlocked.Exchange(ref _relativeOpenResolves, 0);
            long relativeOpenResolveMisses = Interlocked.Exchange(ref _relativeOpenResolveMisses, 0);
            long relativeOpenResolvedViaFd = Interlocked.Exchange(ref _relativeOpenResolvedViaFd, 0);
            long relativeOpenResolvedViaDirFd = Interlocked.Exchange(ref _relativeOpenResolvedViaDirFd, 0);
            long relativeOpenResolvedViaCwd = Interlocked.Exchange(ref _relativeOpenResolvedViaCwd, 0);
            long relativeOpenOpenedFdLookupMisses = Interlocked.Exchange(ref _relativeOpenOpenedFdLookupMisses, 0);
            long relativeOpenDirFdLookupMisses = Interlocked.Exchange(ref _relativeOpenDirFdLookupMisses, 0);
            long relativeOpenCwdLookupMisses = Interlocked.Exchange(ref _relativeOpenCwdLookupMisses, 0);
            long relativeOpenUnsupportedDirFd = Interlocked.Exchange(ref _relativeOpenUnsupportedDirFd, 0);
            int queueDepth = _sendQueue.Count;
            long total = sys + proc + dev;
            string userSummary = BuildAndResetUserCounterSummary();
            string kernelSummary = BuildKernelCounterSummary();
            string policySummary = BuildPolicyCounterSummary();
            string measurementSummary = BuildAndResetMeasurementSummary();
            string deliverySummary = BuildAndResetDeliveryLatencySummary();
            long relativeOpenResolvedViaDirIndex = Interlocked.Exchange(ref _relativeOpenResolvedViaDirIndex, 0);
            long relativeOpenDirIndexMisses = Interlocked.Exchange(ref _relativeOpenDirIndexMisses, 0);
            long relativeOpenMissProducerDead = Interlocked.Exchange(ref _relativeOpenMissProducerDead, 0);
            long relativeOpenMissProducerAlive = Interlocked.Exchange(ref _relativeOpenMissProducerAlive, 0);
            long dirOpenConsumed = Interlocked.Exchange(ref _dirOpenConsumed, 0);
            long dirOpenIndexed = Interlocked.Exchange(ref _dirOpenIndexed, 0);
            long dirOpenUnresolved = Interlocked.Exchange(ref _dirOpenUnresolved, 0);
            long dirIndexEvictions = _dirIdentityIndex.TakeEvictions();
            string resolutionSummary = $"relative_open_resolved={relativeOpenResolves},relative_open_resolve_miss={relativeOpenResolveMisses},resolved_fd={relativeOpenResolvedViaFd},resolved_dir_index={relativeOpenResolvedViaDirIndex},resolved_dirfd={relativeOpenResolvedViaDirFd},resolved_cwd={relativeOpenResolvedViaCwd},opened_fd_lookup_miss={relativeOpenOpenedFdLookupMisses},dir_index_miss={relativeOpenDirIndexMisses},dirfd_lookup_miss={relativeOpenDirFdLookupMisses},cwd_lookup_miss={relativeOpenCwdLookupMisses},unsupported_dirfd={relativeOpenUnsupportedDirFd},miss_producer_dead={relativeOpenMissProducerDead},miss_producer_alive={relativeOpenMissProducerAlive},dir_open_consumed={dirOpenConsumed},dir_open_indexed={dirOpenIndexed},dir_open_unresolved={dirOpenUnresolved},dir_index_size={_dirIdentityIndex.Count},dir_index_evictions={dirIndexEvictions}";
            string queueSummary = $"depth={queueDepth},high_water={queueHighWatermark},drops={queueDrops},capacity={_sendQueueCapacity},policy=drop_newest";
            long aggFirstEmits = Interlocked.Exchange(ref _aggFirstEmits, 0);
            long aggSummaryFailures = Interlocked.Exchange(ref _aggSummaryEnqueueFailures, 0);
            long aggBytesClamped = Interlocked.Exchange(ref _aggBytesClamped, 0);
            long aggFlushCount = 0;
            long aggFlushTicks = 0;
            long aggMaxFlushTicks = 0;
            _aggregator?.TakeFlushTiming(out aggFlushCount, out aggFlushTicks, out aggMaxFlushTicks);
            long aggFlushAverageUs = aggFlushCount > 0
                ? (aggFlushTicks * 1_000_000L) / (System.Diagnostics.Stopwatch.Frequency * aggFlushCount)
                : 0;
            long aggFlushMaxUs = aggMaxFlushTicks * 1_000_000L / System.Diagnostics.Stopwatch.Frequency;
            int fdCachePidCount = _fdToPath.Count;
            int fdCacheEntryCount = 0;
            foreach (ConcurrentDictionary<uint, string> fdMap in _fdToPath.Values)
            {
                fdCacheEntryCount += fdMap.Count;
            }
            string aggSummary = _aggregator == null
                ? "enabled=false"
                : $"enabled=true,window_ms={_aggregationWindowMs},first_emits={aggFirstEmits},repeats_folded={_aggregator.TakeRepeatsFolded()},summaries={_aggregator.TakeSummariesEmitted()},cap_bypass={_aggregator.TakeCapBypass()},entries={_aggregator.EntryCount},flushes={aggFlushCount},flush_avg_us={aggFlushAverageUs},flush_max_us={aggFlushMaxUs},summary_enqueue_fail={aggSummaryFailures},bytes_clamped={aggBytesClamped}";
            long sendSampleTicks;
            long sendProcessResolveSampleTicks;
            long sendHealthSampleTicks;
            long sendEsperSampleTicks;
            long sendSampleCount;
            long sendSampleMaxTicks;
            long sendProcessResolveSampleMaxTicks;
            long sendHealthSampleMaxTicks;
            long sendEsperSampleMaxTicks;
            lock (_sendTimingLock)
            {
                sendSampleTicks = _sendSampleTicks;
                sendProcessResolveSampleTicks = _sendProcessResolveSampleTicks;
                sendHealthSampleTicks = _sendHealthSampleTicks;
                sendEsperSampleTicks = _sendEsperSampleTicks;
                sendSampleCount = _sendSampleCount;
                sendSampleMaxTicks = _sendSampleMaxTicks;
                sendProcessResolveSampleMaxTicks = _sendProcessResolveSampleMaxTicks;
                sendHealthSampleMaxTicks = _sendHealthSampleMaxTicks;
                sendEsperSampleMaxTicks = _sendEsperSampleMaxTicks;
                _sendSampleTicks = 0;
                _sendProcessResolveSampleTicks = 0;
                _sendHealthSampleTicks = 0;
                _sendEsperSampleTicks = 0;
                _sendSampleCount = 0;
                _sendSampleMaxTicks = 0;
                _sendProcessResolveSampleMaxTicks = 0;
                _sendHealthSampleMaxTicks = 0;
                _sendEsperSampleMaxTicks = 0;
            }
            long sendSampleAvgUs = sendSampleCount > 0
                ? (sendSampleTicks * 1_000_000L) / (System.Diagnostics.Stopwatch.Frequency * sendSampleCount)
                : 0;
            long sendProcessResolveAvgUs = AverageSampleMicroseconds(sendProcessResolveSampleTicks, sendSampleCount);
            long sendHealthAvgUs = AverageSampleMicroseconds(sendHealthSampleTicks, sendSampleCount);
            long sendEsperAvgUs = AverageSampleMicroseconds(sendEsperSampleTicks, sendSampleCount);
            string senderSummary = $"send_sample_avg_us={sendSampleAvgUs},send_sample_max_us={TicksToMicroseconds(sendSampleMaxTicks)},resolve_avg_us={sendProcessResolveAvgUs},resolve_max_us={TicksToMicroseconds(sendProcessResolveSampleMaxTicks)},health_avg_us={sendHealthAvgUs},health_max_us={TicksToMicroseconds(sendHealthSampleMaxTicks)},esper_avg_us={sendEsperAvgUs},esper_max_us={TicksToMicroseconds(sendEsperSampleMaxTicks)},samples={sendSampleCount},interval={SendSampleInterval}";

            if (total <= 0 && queueDrops <= 0 && queueDepth <= 0 && queueHighWatermark <= 0 && fdCacheEntryCount <= 0 && string.IsNullOrEmpty(userSummary) && string.IsNullOrEmpty(kernelSummary) && string.IsNullOrEmpty(measurementSummary))
            {
                return;
            }

            WintapLogger.Log.Append(
                $"{SensorName} counters (last ~60s): pseudo=/sys:{sys},/proc:{proc},/dev:{dev},total:{total} queue=[{queueSummary}] fd_cache=[pids={fdCachePidCount},entries={fdCacheEntryCount}] policy=[{policySummary}] agg=[{aggSummary}] sender=[{senderSummary}] delivery=[{deliverySummary}] user=[{userSummary}] resolve=[{resolutionSummary}] measure=[{measurementSummary}] kernel=[{kernelSummary}]",
                LogLevel.Info);
        }

        private void RecordDeliveryLatency(ulong timestampNs)
        {
            long eventRealtimeNs;
            long nowRealtimeNs;
            try
            {
                eventRealtimeNs = checked((long)timestampNs + _monotonicToRealtimeOffsetNs);
                nowRealtimeNs = checked((DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) * 100L);
            }
            catch
            {
                return;
            }

            long latencyNs = Math.Max(0, nowRealtimeNs - eventRealtimeNs);
            int bucket = latencyNs switch
            {
                <= 1_000_000L => 0,
                <= 10_000_000L => 1,
                <= 100_000_000L => 2,
                <= 1_000_000_000L => 3,
                <= 10_000_000_000L => 4,
                <= 60_000_000_000L => 5,
                _ => 6,
            };

            Interlocked.Increment(ref _deliveryLatencyBuckets[bucket]);
            Interlocked.Increment(ref _deliveryLatencySamples);
            Interlocked.Add(ref _deliveryLatencyTotalNs, latencyNs);

            long observedMax = Interlocked.Read(ref _deliveryLatencyMaxNs);
            while (latencyNs > observedMax)
            {
                long observed = Interlocked.CompareExchange(ref _deliveryLatencyMaxNs, latencyNs, observedMax);
                if (observed == observedMax)
                {
                    break;
                }
                observedMax = observed;
            }
        }

        private string BuildAndResetDeliveryLatencySummary()
        {
            long samples = Interlocked.Exchange(ref _deliveryLatencySamples, 0);
            long totalNs = Interlocked.Exchange(ref _deliveryLatencyTotalNs, 0);
            long maxNs = Interlocked.Exchange(ref _deliveryLatencyMaxNs, 0);
            var buckets = new long[_deliveryLatencyBuckets.Length];
            for (int i = 0; i < buckets.Length; i++)
            {
                buckets[i] = Interlocked.Exchange(ref _deliveryLatencyBuckets[i], 0);
            }

            long averageUs = samples > 0 ? totalNs / samples / 1_000L : 0;
            return $"samples={samples},avg_us={averageUs},max_us={maxNs / 1_000L},le_1ms={buckets[0]},le_10ms={buckets[1]},le_100ms={buckets[2]},le_1s={buckets[3]},le_10s={buckets[4]},le_60s={buckets[5]},gt_60s={buckets[6]}";
        }

        private static uint ReadUInt32(IntPtr data, int offset)
        {
            return unchecked((uint)Marshal.ReadInt32(data, offset));
        }

        private static long AverageSampleMicroseconds(long ticks, long count)
        {
            return count > 0
                ? (ticks * 1_000_000L) / (System.Diagnostics.Stopwatch.Frequency * count)
                : 0;
        }

        private static long TicksToMicroseconds(long ticks)
        {
            return ticks * 1_000_000L / System.Diagnostics.Stopwatch.Frequency;
        }

        private static ulong ReadUInt64(IntPtr data, int offset)
        {
            return unchecked((ulong)Marshal.ReadInt64(data, offset));
        }

        private static int ReadInt32(IntPtr data, int offset)
        {
            return Marshal.ReadInt32(data, offset);
        }

        private static string ReadNullTerminatedString(IntPtr data, int offset, int maxBytes)
        {
            byte[] buffer = new byte[maxBytes];
            Marshal.Copy(IntPtr.Add(data, offset), buffer, 0, maxBytes);
            int length = Array.IndexOf(buffer, (byte)0);
            if (length < 0)
            {
                length = maxBytes;
            }
            return length == 0 ? "" : Encoding.UTF8.GetString(buffer, 0, length);
        }

        private static int GetOpIndex(uint opType)
        {
            return opType >= 1 && opType < OpSlots ? (int)opType : 0;
        }

        private static string OpName(int opIndex)
        {
            return opIndex switch
            {
                1 => "open",
                2 => "read",
                3 => "write",
                4 => "close",
                5 => "mmap",
                6 => "unlink",
                7 => "dir_open",
                _ => "other",
            };
        }

        private static void CountByOp(long[] counters, int opIndex)
        {
            Interlocked.Increment(ref counters[opIndex]);
        }

        private static long TakeByOp(long[] counters, int opIndex)
        {
            return Interlocked.Exchange(ref counters[opIndex], 0);
        }

        private string BuildAndResetUserCounterSummary()
        {
            var parts = new List<string>();
            for (int i = 0; i < OpSlots; i++)
            {
                long consumed = TakeByOp(_userConsumedByOp, i);
                long emitted = TakeByOp(_userEmittedByOp, i);
                long noPath = TakeByOp(_userNoPathDropsByOp, i);
                long dataRoot = TakeByOp(_userDataRootDropsByOp, i);
                long etl = TakeByOp(_userEtlDropsByOp, i);
                long parquet = TakeByOp(_userParquetDropsByOp, i);
                long fallbackHit = TakeByOp(_userFallbackHitsByOp, i);
                long fallbackMiss = TakeByOp(_userFallbackMissesByOp, i);
                long total = consumed + emitted + noPath + dataRoot + etl + parquet + fallbackHit + fallbackMiss;
                if (total > 0)
                {
                    parts.Add($"{OpName(i)}:consumed={consumed},emitted={emitted},no_path={noPath},data_root={dataRoot},etl={etl},parquet={parquet},fallback_hit={fallbackHit},fallback_miss={fallbackMiss}");
                }
            }

            EventChannel.TakeFileProcessCacheCounters(out long cacheHits, out long cacheMisses);
            if (cacheHits > 0 || cacheMisses > 0)
            {
                parts.Add($"process_cache:hit={cacheHits},miss={cacheMisses}");
            }

            EventChannel.TakeHistoricalProcessCacheCounters(
                out long historicalHits,
                out long historicalMisses,
                out long historicalEvictions,
                out int historicalEntries);
            if (historicalHits > 0 || historicalMisses > 0 || historicalEntries > 0)
            {
                parts.Add($"process_history_cache:hit={historicalHits},miss={historicalMisses},entries={historicalEntries},evictions={historicalEvictions}");
            }

            return string.Join("; ", parts);
        }

        private void RecordMeasurement(int opIndex, uint opType, int pid, string processName, string filePath, long observedAtMs)
        {
            lock (_measurementLock)
            {
                IncrementAggregate(_emitByComm, NormalizeCommBucket(processName), opIndex, "(other)");
                IncrementAggregate(_emitByPrefix, GetPathPrefixBucket(filePath), opIndex, "(other)");

                if (opType == FileOpOpen)
                {
                    _openDuplicateWindowTotal++;
                    var key = (pid, filePath);
                    if (_recentOpenSeenMs.TryGetValue(key, out long lastSeenMs) && observedAtMs - lastSeenMs <= DuplicateOpenWindowMs)
                    {
                        _openDuplicateWindowHits++;
                    }

                    _recentOpenSeenMs[key] = observedAtMs;
                    if (--_duplicatePruneCountdown <= 0)
                    {
                        PruneDuplicateState(observedAtMs);
                        _duplicatePruneCountdown = 1024;
                    }
                }
            }
        }

        private string BuildAndResetMeasurementSummary()
        {
            lock (_measurementLock)
            {
                PruneDuplicateState(Environment.TickCount64);

                string commSummary = FormatTopMeasurement("comm_top", _emitByComm);
                string prefixSummary = FormatTopMeasurement("prefix_top", _emitByPrefix);
                long duplicateTotal = _openDuplicateWindowTotal;
                long duplicateHits = _openDuplicateWindowHits;
                string duplicateSummary = duplicateTotal > 0
                    ? $"open_dup:total={duplicateTotal},repeat={duplicateHits},repeat_pct={(duplicateHits * 100.0) / duplicateTotal:0.0},window_ms={DuplicateOpenWindowMs}"
                    : string.Empty;

                _emitByComm.Clear();
                _emitByPrefix.Clear();
                _openDuplicateWindowTotal = 0;
                _openDuplicateWindowHits = 0;

                var parts = new List<string>();
                if (!string.IsNullOrEmpty(commSummary))
                {
                    parts.Add(commSummary);
                }

                if (!string.IsNullOrEmpty(prefixSummary))
                {
                    parts.Add(prefixSummary);
                }

                if (!string.IsNullOrEmpty(duplicateSummary))
                {
                    parts.Add(duplicateSummary);
                }

                return string.Join("; ", parts);
            }
        }

        private static string NormalizeCommBucket(string processName)
        {
            return string.IsNullOrWhiteSpace(processName) ? "unknown" : processName.Trim().ToLowerInvariant();
        }

        private static string GetPathPrefixBucket(string normalizedPath)
        {
            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                return "(empty)";
            }

            if (!normalizedPath.StartsWith("/", StringComparison.Ordinal))
            {
                return "(relative)";
            }

            if (normalizedPath.StartsWith("/home/", StringComparison.Ordinal))
            {
                return "/home/*";
            }

            int nextSlash = normalizedPath.IndexOf('/', 1);
            return nextSlash > 0 ? normalizedPath.Substring(0, nextSlash) : normalizedPath;
        }

        private void IncrementAggregate(Dictionary<string, MeasurementAggregate> aggregates, string key, int opIndex, string overflowBucket)
        {
            if (!aggregates.TryGetValue(key, out MeasurementAggregate aggregate))
            {
                if (aggregates.Count >= MaxMeasurementBuckets)
                {
                    key = overflowBucket;
                    if (!aggregates.TryGetValue(key, out aggregate))
                    {
                        aggregate = new MeasurementAggregate();
                        aggregates[key] = aggregate;
                    }
                }
                else
                {
                    aggregate = new MeasurementAggregate();
                    aggregates[key] = aggregate;
                }
            }

            aggregate.Add(opIndex);
        }

        private void PruneDuplicateState(long nowMs)
        {
            long cutoffMs = nowMs - DuplicateOpenWindowMs;
            var staleKeys = new List<(int Pid, string Path)>();
            foreach (KeyValuePair<(int Pid, string Path), long> entry in _recentOpenSeenMs)
            {
                if (entry.Value < cutoffMs)
                {
                    staleKeys.Add(entry.Key);
                }
            }

            for (int i = 0; i < staleKeys.Count; i++)
            {
                _recentOpenSeenMs.Remove(staleKeys[i]);
            }

            if (_recentOpenSeenMs.Count <= MaxDuplicateKeys)
            {
                return;
            }

            staleKeys.Clear();
            foreach (KeyValuePair<(int Pid, string Path), long> entry in _recentOpenSeenMs)
            {
                staleKeys.Add(entry.Key);
                if (_recentOpenSeenMs.Count - staleKeys.Count <= MaxDuplicateKeys)
                {
                    break;
                }
            }

            for (int i = 0; i < staleKeys.Count; i++)
            {
                _recentOpenSeenMs.Remove(staleKeys[i]);
            }
        }

        private static string FormatTopMeasurement(string label, Dictionary<string, MeasurementAggregate> aggregates)
        {
            if (aggregates.Count == 0)
            {
                return string.Empty;
            }

            var ranked = new List<KeyValuePair<string, MeasurementAggregate>>(aggregates);
            ranked.Sort((left, right) =>
            {
                int totalCompare = right.Value.Total.CompareTo(left.Value.Total);
                return totalCompare != 0 ? totalCompare : string.CompareOrdinal(left.Key, right.Key);
            });

            var parts = new List<string>();
            int count = Math.Min(MeasurementTopN, ranked.Count);
            for (int i = 0; i < count; i++)
            {
                KeyValuePair<string, MeasurementAggregate> entry = ranked[i];
                parts.Add($"{entry.Key}:total={entry.Value.Total},open={entry.Value.Get(FileOpOpen)},read={entry.Value.Get(FileOpRead)},write={entry.Value.Get(FileOpWrite)},close={entry.Value.Get(FileOpClose)},mmap={entry.Value.Get(FileOpMmap)},unlink={entry.Value.Get(FileOpUnlink)}");
            }

            return parts.Count == 0 ? string.Empty : $"{label}={string.Join(" | ", parts)}";
        }

        private void StartSendWorker()
        {
            _sendWorker = new Thread(ProcessSendQueue)
            {
                IsBackground = true,
                Name = $"{SensorName}-Sender"
            };
            _sendWorker.Start();

            // Policy counters must remain observable even when every matching
            // event is suppressed before reaching the userspace callback.
            _counterLogTimer = new System.Threading.Timer(
                _ => { try { MaybeLogCounters(); } catch { } },
                null, 1000, 1000);

            if (_aggregator != null)
            {
                int flushPeriodMs = Math.Max(250, _aggregationWindowMs / 2);
                _aggregationFlushTimer = new System.Threading.Timer(
                    _ => { try { _aggregator.FlushExpired(Environment.TickCount64); } catch { } },
                    null, flushPeriodMs, flushPeriodMs);
            }
        }

        private void ProcessSendQueue()
        {
            while (true)
            {
                try
                {
                    if (!_sendQueue.TryTake(out QueuedFileEvent queued, 100))
                    {
                        if (_sendQueue.IsCompleted)
                        {
                            return;
                        }

                        continue;
                    }

                    if ((Interlocked.Increment(ref _sendSampleCounter) & (SendSampleInterval - 1)) == 0)
                    {
                        long startTicks = System.Diagnostics.Stopwatch.GetTimestamp();
                        EventChannel.SendMeasured(queued.Message, out EventChannel.EventSendTiming timing);
                        long totalTicks = System.Diagnostics.Stopwatch.GetTimestamp() - startTicks;
                        lock (_sendTimingLock)
                        {
                            _sendSampleTicks += totalTicks;
                            _sendProcessResolveSampleTicks += timing.ProcessResolveTicks;
                            _sendHealthSampleTicks += timing.HealthTicks;
                            _sendEsperSampleTicks += timing.EsperTicks;
                            _sendSampleCount++;
                            _sendSampleMaxTicks = Math.Max(_sendSampleMaxTicks, totalTicks);
                            _sendProcessResolveSampleMaxTicks = Math.Max(_sendProcessResolveSampleMaxTicks, timing.ProcessResolveTicks);
                            _sendHealthSampleMaxTicks = Math.Max(_sendHealthSampleMaxTicks, timing.HealthTicks);
                            _sendEsperSampleMaxTicks = Math.Max(_sendEsperSampleMaxTicks, timing.EsperTicks);
                        }
                    }
                    else
                    {
                        EventChannel.Send(queued.Message);
                    }
                    CountByOp(_userEmittedByOp, queued.OpIndex);
                    MaybeLogCounters();
                }
                catch (InvalidOperationException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"{SensorName} send worker error: {ex.Message}", LogLevel.Error);
                    Thread.Sleep(100);
                }
            }
        }

        private static WintapMessage.ActivityTypeEnum MapOpToActivityType(uint opType)
        {
            return opType switch
            {
                1 => WintapMessage.ActivityTypeEnum.Open,
                2 => WintapMessage.ActivityTypeEnum.Read,
                3 => WintapMessage.ActivityTypeEnum.Write,
                4 => WintapMessage.ActivityTypeEnum.Close,
                5 => WintapMessage.ActivityTypeEnum.Read,   // mmap is like read (A4 deferred)
                6 => WintapMessage.ActivityTypeEnum.Delete,
                _ => WintapMessage.ActivityTypeEnum.Other
            };
        }

        // fop-11 summary rows: repeats only (the first occurrence was emitted
        // per-event with EventCount=1, so SUM(EventCount) downstream equals
        // the raw event count). Identity comes from the first occurrence,
        // never from flush-time resolution.
        private void EmitAggregateSummary(FileOpsAggregator.AggregateEntry entry)
        {
            try
            {
                DateTime firstUtc = ConvertKernelTimestampToUtcDateTime(entry.FirstRepeatNs);
                DateTime lastUtc = entry.LastRepeatNs >= entry.FirstRepeatNs
                    ? ConvertKernelTimestampToUtcDateTime(entry.LastRepeatNs)
                    : firstUtc;

                int bytesClamped;
                if (entry.BytesSum > int.MaxValue)
                {
                    bytesClamped = int.MaxValue;
                    Interlocked.Increment(ref _aggBytesClamped);
                }
                else
                {
                    bytesClamped = (int)Math.Max(entry.BytesSum, 0);
                }

                var message = new WintapMessage(firstUtc, entry.Pid, WintapMessage.MessageTypeEnum.File)
                {
                    ActivityType = MapOpToActivityType(entry.OpType),
                    ActivityId = "",
                    CorrelationId = "",
                    PidHash = entry.PidHash ?? "",
                    ProcessName = entry.ProcessName ?? "unknown",
                };
                message.File = new WintapMessage.FileActivityObject
                {
                    Path = entry.Path,
                    BytesRequested = bytesClamped,
                    PID = entry.Pid,
                    EventCount = entry.RepeatCount,
                    FirstSeenEventTime = firstUtc.ToFileTimeUtc(),
                    LastSeenEventTime = lastUtc.ToFileTimeUtc(),
                };

                if (!TryEnqueueMessage(message, GetOpIndex(entry.OpType)))
                {
                    Interlocked.Increment(ref _aggSummaryEnqueueFailures);
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _aggSummaryEnqueueFailures);
                WintapLogger.Log.Append($"{SensorName} aggregate summary emit error: {ex.Message}", LogLevel.Error);
            }
        }

        private bool TryEnqueueMessage(WintapMessage message, int opIndex)
        {
            if (_sendQueue.IsAddingCompleted)
            {
                return false;
            }

            if (_sendQueue.TryAdd(new QueuedFileEvent(message, opIndex)))
            {
                UpdateQueueHighWatermark(_sendQueue.Count);
                return true;
            }

            Interlocked.Increment(ref _queueDrops);
            EventChannel.AddDroppedEvents(1);
            return false;
        }

        private void UpdateQueueHighWatermark(int currentDepth)
        {
            long observed = currentDepth;
            while (true)
            {
                long current = Interlocked.Read(ref _queueHighWatermark);
                if (observed <= current)
                {
                    return;
                }

                if (Interlocked.CompareExchange(ref _queueHighWatermark, observed, current) == current)
                {
                    return;
                }
            }
        }

        private static int GetConfiguredQueueCapacity()
        {
            int configured = ConfigManager.GetValue<int>("WINTAP_FILEOPS_MAX_QUEUE_EVENTS");
            // Default raised from 131072 after the 2026-08-25 field experiment:
            // burst backlog reached ~437k with zero drops at 4x capacity.
            return configured > 0 ? configured : 524288;
        }

        private string ResolveOpenPath(int pid, uint fd, int dirfd, uint mntNs, uint dirDev, ulong dirIno, string rawPath)
        {
            if (string.IsNullOrWhiteSpace(rawPath) || IsAbsolutePath(rawPath))
            {
                return rawPath;
            }

            try
            {
                string resolved = ReadLinkTarget($"/proc/{pid}/fd/{fd}");
                if (!string.IsNullOrEmpty(resolved) && IsAbsolutePath(resolved))
                {
                    Interlocked.Increment(ref _relativeOpenResolves);
                    Interlocked.Increment(ref _relativeOpenResolvedViaFd);
                    return resolved;
                }
            }
            catch { }

            Interlocked.Increment(ref _relativeOpenOpenedFdLookupMisses);

            // Race-free step: base-directory identity captured in-kernel at
            // event time, resolved against the learned dir index. Works even
            // after the producer has exited.
            if (dirDev != 0 || dirIno != 0)
            {
                if (_dirIdentityIndex.TryGet(mntNs, dirDev, dirIno, out string dirBasePath))
                {
                    try
                    {
                        string joined = Path.GetFullPath(rawPath, dirBasePath);
                        if (IsAbsolutePath(joined))
                        {
                            Interlocked.Increment(ref _relativeOpenResolves);
                            Interlocked.Increment(ref _relativeOpenResolvedViaDirIndex);
                            return joined;
                        }
                    }
                    catch { }
                }
                else
                {
                    Interlocked.Increment(ref _relativeOpenDirIndexMisses);
                }
            }

            if (dirfd == AtFdcwd)
            {
                if (TryResolveRelativePathAgainstBase($"/proc/{pid}/cwd", rawPath, out string resolvedFromCwd))
                {
                    Interlocked.Increment(ref _relativeOpenResolves);
                    Interlocked.Increment(ref _relativeOpenResolvedViaCwd);
                    return resolvedFromCwd;
                }

                Interlocked.Increment(ref _relativeOpenCwdLookupMisses);
            }
            else if (dirfd >= 0)
            {
                if (TryResolveRelativePathAgainstBase($"/proc/{pid}/fd/{dirfd}", rawPath, out string resolvedFromDirFd))
                {
                    Interlocked.Increment(ref _relativeOpenResolves);
                    Interlocked.Increment(ref _relativeOpenResolvedViaDirFd);
                    return resolvedFromDirFd;
                }

                Interlocked.Increment(ref _relativeOpenDirFdLookupMisses);
            }
            else
            {
                Interlocked.Increment(ref _relativeOpenUnsupportedDirFd);
            }

            Interlocked.Increment(ref _relativeOpenResolveMisses);

            // fop-13a miss-cause split: distinguish producer-dead (nothing in
            // /proc can ever work) from producer-alive (fds closed early).
            try
            {
                if (Directory.Exists($"/proc/{pid}"))
                {
                    Interlocked.Increment(ref _relativeOpenMissProducerAlive);
                }
                else
                {
                    Interlocked.Increment(ref _relativeOpenMissProducerDead);
                }
            }
            catch { }

            return rawPath;
        }

        private void HandleDirOpenRecord(int pid, uint fd, int dirfd, string rawPath, uint mntNs, uint dev, ulong ino, uint baseDev, ulong baseIno)
        {
            Interlocked.Increment(ref _dirOpenConsumed);

            // The directory's own identity arrives in the file id fields; the
            // identity of the base dirfd it was opened relative to arrives in
            // the dir id fields.
            if (dev == 0 && ino == 0)
            {
                // Fallback tier emits zeros; nothing to index.
                return;
            }

            string path = rawPath?.Trim() ?? "";
            if (!IsAbsolutePath(path))
            {
                // Resolve a relative directory open through the same chain:
                // its own fd first (directory handles typically outlive the
                // decode window), then the base-directory index.
                string resolved = "";
                try
                {
                    resolved = ReadLinkTarget($"/proc/{pid}/fd/{fd}");
                }
                catch { }

                if (string.IsNullOrEmpty(resolved) || !IsAbsolutePath(resolved))
                {
                    resolved = "";
                    if ((baseDev != 0 || baseIno != 0) &&
                        _dirIdentityIndex.TryGet(mntNs, baseDev, baseIno, out string basePath))
                    {
                        try
                        {
                            string joined = Path.GetFullPath(path, basePath);
                            if (IsAbsolutePath(joined))
                            {
                                resolved = joined;
                            }
                        }
                        catch { }
                    }
                }

                if (string.IsNullOrEmpty(resolved))
                {
                    Interlocked.Increment(ref _dirOpenUnresolved);
                    return;
                }

                path = resolved;
            }

            path = NormalizeFilePath(path);
            if (string.IsNullOrEmpty(path))
            {
                Interlocked.Increment(ref _dirOpenUnresolved);
                return;
            }

            _dirIdentityIndex.Put(mntNs, dev, ino, path);
            Interlocked.Increment(ref _dirOpenIndexed);
        }

        private bool TryResolveRelativePathAgainstBase(string procLinkPath, string rawRelativePath, out string resolvedPath)
        {
            resolvedPath = string.Empty;
            try
            {
                string basePath = ReadLinkTarget(procLinkPath);
                if (string.IsNullOrEmpty(basePath) || !IsAbsolutePath(basePath))
                {
                    return false;
                }

                resolvedPath = Path.GetFullPath(rawRelativePath, basePath);
                return IsAbsolutePath(resolvedPath);
            }
            catch
            {
                resolvedPath = string.Empty;
                return false;
            }
        }

        private string NormalizeConfiguredPath(string? path)
        {
            return string.IsNullOrWhiteSpace(path) ? null : NormalizeFilePath(path);
        }

        private static bool IsAbsolutePath(string path)
        {
            return !string.IsNullOrEmpty(path) && path[0] == '/';
        }

        private DateTime ConvertKernelTimestampToUtcDateTime(ulong timestampNs)
        {
            return KernelTimestampConverter.ToUtcDateTime(timestampNs, _monotonicToRealtimeOffsetNs);
        }

        private void InitializeStatsMap()
        {
            try
            {
                IntPtr map = LibBpf.bpf_object__find_map_by_name(BpfObject, "fileops_stats");
                if (map == IntPtr.Zero)
                {
                    WintapLogger.Log.Append($"{SensorName} fileops_stats map not found", LogLevel.Debug);
                    return;
                }

                _statsMapFd = LibBpf.bpf_map__fd(map);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} could not initialize stats map: {ex.Message}", LogLevel.Warn);
                _statsMapFd = -1;
            }
        }

        private bool InitializeDenyCommPolicy()
        {
            IReadOnlyList<string> configuredRules;
            try
            {
                configuredRules = FileOpsDenyPolicy.Parse(ConfigManager.GetValue<string>("WINTAP_FILEOPS_DENY_COMMS"));
            }
            catch (ArgumentException ex)
            {
                WintapLogger.Log.Append($"{SensorName} deny policy rejected: {ex.Message}", LogLevel.Error);
                return false;
            }

            if (configuredRules.Count == 0)
            {
                WintapLogger.Log.Append($"{SensorName} deny policy disabled", LogLevel.Info);
                return true;
            }

            try
            {
                IntPtr policyMap = LibBpf.bpf_object__find_map_by_name(BpfObject, "fileops_deny_comms");
                IntPtr policyStatsMap = LibBpf.bpf_object__find_map_by_name(BpfObject, "fileops_policy_stats");
                if (policyMap == IntPtr.Zero || policyStatsMap == IntPtr.Zero)
                {
                    WintapLogger.Log.Append($"{SensorName} deny policy maps are unavailable in the loaded BPF object", LogLevel.Error);
                    return false;
                }

                int policyMapFd = LibBpf.bpf_map__fd(policyMap);
                _policyStatsMapFd = LibBpf.bpf_map__fd(policyStatsMap);
                if (policyMapFd < 0 || _policyStatsMapFd < 0)
                {
                    WintapLogger.Log.Append($"{SensorName} deny policy map descriptors are invalid", LogLevel.Error);
                    return false;
                }

                for (int index = 0; index < configuredRules.Count; index++)
                {
                    byte[] key = new byte[16];
                    System.Text.Encoding.UTF8.GetBytes(configuredRules[index], 0, configuredRules[index].Length, key, 0);
                    uint ruleId = (uint)(index + 1);
                    GCHandle handle = GCHandle.Alloc(key, GCHandleType.Pinned);
                    try
                    {
                        if (LibBpf.bpf_map_update_elem(policyMapFd, handle.AddrOfPinnedObject(), ref ruleId, 0) != 0)
                        {
                            WintapLogger.Log.Append($"{SensorName} could not install deny policy rule {ruleId} ({configuredRules[index]})", LogLevel.Error);
                            return false;
                        }
                    }
                    finally
                    {
                        handle.Free();
                    }

                    _denyCommRules.Add(configuredRules[index]);
                }

                WintapLogger.Log.Append($"{SensorName} deny policy enabled rules=[{string.Join(",", _denyCommRules)}]", LogLevel.Warn);
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} deny policy initialization failed: {ex.Message}", LogLevel.Error);
                return false;
            }
        }

        private string BuildPolicyCounterSummary()
        {
            if (_denyCommRules.Count == 0)
            {
                return "enabled=false";
            }

            var rules = new List<string>();
            for (int ruleIndex = 0; ruleIndex < _denyCommRules.Count; ruleIndex++)
            {
                var operations = new List<string>();
                for (int opIndex = 1; opIndex < OpSlots; opIndex++)
                {
                    uint statKey = (uint)(((ruleIndex + 1) * 8) + opIndex);
                    ulong current = LookupCounter(_policyStatsMapFd, statKey);
                    ulong previous = _policyStatsLast[statKey];
                    ulong delta = current >= previous ? current - previous : current;
                    _policyStatsLast[statKey] = current;
                    if (delta > 0)
                    {
                        operations.Add($"{OpName(opIndex)}={delta}");
                    }
                }

                if (operations.Count > 0)
                {
                    rules.Add($"rule{ruleIndex + 1}:{_denyCommRules[ruleIndex]}({string.Join(",", operations)})");
                }
            }

            return rules.Count == 0
                ? $"enabled=true,rules={_denyCommRules.Count},suppressed_attempts=0"
                : $"enabled=true,rules={_denyCommRules.Count},suppressed_attempts={string.Join(";", rules)}";
        }

        private string BuildKernelCounterSummary()
        {
            if (_statsMapFd < 0)
            {
                return "";
            }

            var parts = new List<string>();
            for (int i = 1; i < OpSlots; i++)
            {
                ulong emitted = LookupKernelCounter((uint)i);
                ulong ringFail = LookupKernelCounter((uint)(i + 16));
                ulong selfDrop = LookupKernelCounter((uint)(i + 32));
                ulong nonRegularDrop = LookupKernelCounter((uint)(i + 56));
                ulong pseudoDrop = LookupKernelCounter((uint)(i + 64));
                if (emitted > 0 || ringFail > 0 || selfDrop > 0 || nonRegularDrop > 0 || pseudoDrop > 0)
                {
                    parts.Add($"{OpName(i)}:emitted_total={emitted},ring_fail_total={ringFail},self_drop_total={selfDrop},nonregular_drop_total={nonRegularDrop},pseudo_drop_total={pseudoDrop}");
                }
            }
            ulong forceWakeup = LookupKernelCounter(48);
            if (forceWakeup > 0)
            {
                parts.Add($"force_wakeup_total={forceWakeup}");
            }
            return string.Join("; ", parts);
        }

        private void InitializeSelfPidFilter()
        {
            try
            {
                IntPtr map = LibBpf.bpf_object__find_map_by_name(BpfObject, "fileops_filter_pids");
                if (map == IntPtr.Zero)
                {
                    WintapLogger.Log.Append($"{SensorName} fileops_filter_pids map not found", LogLevel.Debug);
                    return;
                }

                int mapFd = LibBpf.bpf_map__fd(map);
                uint key = 0;
                uint value = (uint)Math.Max(StateManager.WintapPID, 0);
                int result = LibBpf.bpf_map_update_elem(mapFd, ref key, ref value, 0);
                if (result != 0)
                {
                    WintapLogger.Log.Append($"{SensorName} could not set self PID filter to {value}: {result}", LogLevel.Warn);
                    return;
                }

                WintapLogger.Log.Append($"{SensorName} kernel self PID filter set to {value}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} could not initialize self PID filter: {ex.Message}", LogLevel.Warn);
            }
        }

        private ulong LookupKernelCounter(uint key)
        {
            return LookupCounter(_statsMapFd, key);
        }

        private static ulong LookupCounter(int mapFd, uint key)
        {
            try
            {
                return mapFd >= 0 && LibBpf.bpf_map_lookup_elem(mapFd, ref key, out ulong value) == 0 ? value : 0;
            }
            catch
            {
                return 0;
            }
        }

        private void StoreFdPath(int pid, uint fd, string path)
        {
            var fdMap = _fdToPath.GetOrAdd(pid, _ => new ConcurrentDictionary<uint, string>());
            fdMap[fd] = path;
        }

        private string GetPathFromFd(int pid, uint fd, int opIndex)
        {
            string cachedPath = GetCachedPathFromFd(pid, fd);
            if (!string.IsNullOrEmpty(cachedPath))
                return cachedPath;
            
            // Try reading from /proc as fallback
            try
            {
                var fdPath = $"/proc/{pid}/fd/{fd}";
                string resolved = ReadLinkTarget(fdPath);
                if (!string.IsNullOrEmpty(resolved))
                {
                    StoreFdPath(pid, fd, resolved);
                    CountByOp(_userFallbackHitsByOp, opIndex);
                    return resolved;
                }
            }
            catch { }

            CountByOp(_userFallbackMissesByOp, opIndex);
            
            return "";
        }

        private static string ReadLinkTarget(string path)
        {
            byte[] buffer = new byte[4096];
            long length = readlink(path, buffer, (UIntPtr)buffer.Length);
            if (length <= 0 || length > buffer.Length)
            {
                return "";
            }

            return Encoding.UTF8.GetString(buffer, 0, (int)length);
        }

        private string GetCachedPathFromFd(int pid, uint fd)
        {
            if (_fdToPath.TryGetValue(pid, out var fdMap) && fdMap.TryGetValue(fd, out var path))
                return path;

            return "";
        }

        private static string NormalizeFilePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return "";

            string p = path.Trim();

            // /proc/<pid>/fd/<n> targets often include " (deleted)"; strip to
            // keep stable matching for short-lived temp files.
            const string deletedSuffix = " (deleted)";
            if (p.EndsWith(deletedSuffix, StringComparison.Ordinal))
            {
                p = p.Substring(0, p.Length - deletedSuffix.Length);
            }

            return _NormalizePathCase(p);
        }

        private string NormalizePathCaseInstance(string path)
        {
            return _lowercasePaths ? path.ToLowerInvariant() : path;
        }

        private static string _NormalizePathCase(string path)
        {
            return OperatingSystem.IsWindows() ? path.ToLowerInvariant() : path;
        }

        private void RemoveFdPath(int pid, uint fd)
        {
            if (_fdToPath.TryGetValue(pid, out var fdMap))
            {
                fdMap.TryRemove(fd, out _);
                
                // Cleanup empty maps
                if (fdMap.IsEmpty)
                    _fdToPath.TryRemove(pid, out _);
            }
        }

        protected override void OnStopping()
        {
            try
            {
                _counterLogTimer?.Dispose();
                _counterLogTimer = null;
                _aggregationFlushTimer?.Dispose();
                _aggregationFlushTimer = null;
                // Drain pending summaries into the queue before it stops
                // accepting, so shutdown loses no folded repeats.
                _aggregator?.FlushAll();
            }
            catch { }

            try
            {
                _sendQueue.CompleteAdding();
                // Every callback-accepted event must leave the sender queue
                // before ETL begins its final serializer drain.
                WaitForThreadExit(_sendWorker);
            }
            catch { }

            // Cleanup additional program links
            foreach (var link in _additionalLinks)
            {
                if (link != IntPtr.Zero)
                    LibBpf.bpf_link__destroy(link);
            }
            _additionalLinks.Clear();

            // Cleanup FD mappings
            _fdToPath.Clear();
        }

        private readonly struct QueuedFileEvent
        {
            public QueuedFileEvent(WintapMessage message, int opIndex)
            {
                Message = message;
                OpIndex = opIndex;
            }

            public WintapMessage Message { get; }

            public int OpIndex { get; }
        }

        private sealed class MeasurementAggregate
        {
            private readonly long[] _counts = new long[OpSlots];

            public long Total { get; private set; }

            public void Add(int opIndex)
            {
                if (opIndex >= 0 && opIndex < _counts.Length)
                {
                    _counts[opIndex]++;
                }

                Total++;
            }

            public long Get(uint opType)
            {
                int index = GetOpIndex(opType);
                return index >= 0 && index < _counts.Length ? _counts[index] : 0;
            }
        }

    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct FileEvent
    {
        public uint Pid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Comm;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] Filename;

        public ulong TimestampNs;
        public uint Fd;
        public uint Bytes;
        public uint OpType;

        public string GetComm() => StructHelper.GetString(Comm);
        public string GetFilename() => StructHelper.GetString(Filename);
    }
}
