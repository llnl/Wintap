using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared.helpers;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.etl.shared;
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Unified network operations sensor - tracks TCP and UDP activity
    /// </summary>
    internal class NetworkSensor : BaseEbpfSensor
    {
        // Local aggregated diagnostic counters (incremented from ringbuffer diag events)
        private long _diagStore = 0;
        private long _diagHit = 0;
        private long _diagMiss = 0;
        private System.Threading.Thread? _diagReporterThread;
        private System.Threading.CancellationTokenSource? _diagReporterCancel;
        private ProcessHash _pidHashGenerator;
        private List<IntPtr> _additionalLinks;
        private readonly long _monotonicToRealtimeOffsetNs;

        protected override string BpfObjectFileName => "network_ops_tracer.bpf.o";
        protected override string[] FallbackBpfObjectFileNames => new[] { "network_tracepoint.bpf.o" };
        protected override string BpfProgramName => "trace_inet_sock_set_state";

        internal NetworkSensor()
        {
            SensorName = "Network";
            _pidHashGenerator = new ProcessHash();
            _additionalLinks = new List<IntPtr>();
            _monotonicToRealtimeOffsetNs = KernelTimestampConverter.ComputeMonotonicToRealtimeOffsetNanoseconds();
        }

        public override bool Start()
        {
            if (!base.Start())
                return false;

            // Optional: reduce event volume by filtering the tracer to a single PID.
            // This is primarily for validation/benchmark runs.
            bool pidFilterRequested = false;
            bool pidFilterApplied = false;
            try
            {
                var pidStr = ConfigManager.GetValue<string>("WINTAP_NETWORK_CAPTURE_PID");
                pidFilterRequested = !string.IsNullOrWhiteSpace(pidStr);
                if (!string.IsNullOrWhiteSpace(pidStr) && uint.TryParse(pidStr, out var capturePid) && capturePid > 0)
                {
                    IntPtr map = LibBpf.bpf_object__find_map_by_name(BpfObject, "capture_pid");
                    if (map != IntPtr.Zero)
                    {
                        int fd = LibBpf.bpf_map__fd(map);
                        if (fd >= 0)
                        {
                            uint key = 0;
                            uint value = capturePid;
                            // flags=0 => BPF_ANY
                            int rc = LibBpf.bpf_map_update_elem(fd, ref key, ref value, 0);
                            if (rc == 0)
                            {
                                pidFilterApplied = true;
                                WintapLogger.Log.Append($"{SensorName} tracer PID filter enabled: {capturePid}", LogLevel.Info);
                            }
                            else
                                WintapLogger.Log.Append($"{SensorName} failed to set tracer PID filter: rc={rc}", LogLevel.Warn);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} failed to configure PID filter: {ex.Message}", LogLevel.Debug);
            }

            // Receipt records restriction/outcome, not a private PID/config dump.
            RuntimeCapabilities.Feature(CapabilityKey, "pidFilterRequested", pidFilterRequested);
            RuntimeCapabilities.Feature(CapabilityKey, "pidFilterApplied", pidFilterApplied);

            // Start a small diag reporter that logs aggregated ringbuffer diag events.
            // This shells out/persists generic diagnostic messages, so keep it opt-in.
            if (ConfigManager.GetValue<bool>("EnableBpfDiagMonitor"))
            {
                try
                {
                    _diagReporterCancel = new System.Threading.CancellationTokenSource();
                    var ct = _diagReporterCancel.Token;
                    _diagReporterThread = new System.Threading.Thread(() =>
                    {
                        while (!ct.IsCancellationRequested)
                        {
                            try
                            {
                                System.Threading.Thread.Sleep(10000);
                                var s = System.Threading.Interlocked.Read(ref _diagStore);
                                var h = System.Threading.Interlocked.Read(ref _diagHit);
                                var m = System.Threading.Interlocked.Read(ref _diagMiss);
                                WintapLogger.Log.Append($"NetworkSensor aggregated BPF diag (STORE/HIT/MISS) = {s}/{h}/{m}", LogLevel.Info);

                                // Persist a generic message so ETL will serialize these counters
                                try
                                {
                                    var pid = System.Diagnostics.Process.GetCurrentProcess().Id;
                                    var msg = new gov.llnl.wintap.collect.models.WintapMessage(DateTime.UtcNow, pid, gov.llnl.wintap.collect.models.WintapMessage.MessageTypeEnum.GenericMessage);
                                    msg.ActivityType = gov.llnl.wintap.collect.models.WintapMessage.ActivityTypeEnum.Other;
                                    msg.GenericMessage = new gov.llnl.wintap.collect.models.WintapMessage.GenericMessageObject
                                    {
                                        ProviderId = "BPFDiag",
                                        ProviderName = "BPFDiag",
                                        EventName = "DiagCounters",
                                        PID = pid,
                                        EventTime = DateTime.UtcNow,
                                        Payload = $"STORE={s};HIT={h};MISS={m}"
                                    };
                                    gov.llnl.wintap.core.infrastructure.EventChannel.Send(msg);
                                }
                                catch (Exception ex)
                                {
                                    WintapLogger.Log.Append($"Failed to persist BPF diag counters: {ex.Message}", LogLevel.Debug);
                                }
                                // Also append a local CSV for immediate DuckDB queries and persistence
                                try
                                {
                                    var diagDir = Paths.DiagDataPath;
                                    System.IO.Directory.CreateDirectory(diagDir);
                                    var csvPath = System.IO.Path.Combine(diagDir, "diag_counters.csv");
                                    bool writeHeader = !System.IO.File.Exists(csvPath);
                                    using (var sw = new System.IO.StreamWriter(csvPath, true))
                                    {
                                        if (writeHeader)
                                            sw.WriteLine("TimestampUtc,Store,Hit,Miss");
                                        sw.WriteLine($"{DateTime.UtcNow:o},{s},{h},{m}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    WintapLogger.Log.Append($"Failed to write local diag CSV: {ex.Message}", LogLevel.Debug);
                                }
                            }
                            catch { }
                        }
                    }) { IsBackground = true };
                    _diagReporterThread.Start();
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"Failed to start NetworkSensor diag reporter: {ex.Message}", LogLevel.Debug);
                }
            }

            try
            {
                // BaseEbpfSensor attaches only the primary program (BpfProgramName).
                // For network we also need additional tracepoints/kprobes/kretprobes.
                // Attach by BPF function name for compatibility with libbpf builds
                // that do not export bpf_object__find_program_by_title.
                var programs = new[]
                {
                    // syscall tracepoints
                    "trace_sendto",
                    "trace_recvfrom",
                    "trace_recvfrom_exit",
                    "trace_connect",
                    "trace_accept",

                    // TCP lifecycle + send/recv
                    "kprobe__tcp_v4_connect",
                    "kretprobe__tcp_v4_connect",
                    "kprobe__tcp_v6_connect",
                    "kretprobe__tcp_v6_connect",
                    "kprobe__tcp_connect",
                    "kretprobe__tcp_connect",
                    "kprobe__tcp_close",
                    "kretprobe__inet_csk_accept",
                    "kprobe__tcp_sendmsg",
                    "kprobe__tcp_recvmsg",

                    // UDP send/recv (connected + recv peer tuple)
                    "kprobe__udp_sendmsg",
                    "kretprobe__udp_sendmsg",
                    "kprobe__udp_recvmsg",
                    "kretprobe__udp_recvmsg",
                };

                int attached = 0;
                var attachedPrograms = new HashSet<string>();
                foreach (var programName in programs)
                {
                    IntPtr link = AttachProgram(programName, applicable: LoadedTier == "core" || !programName.StartsWith("kprobe") && !programName.StartsWith("kretprobe"));
                    if (link == IntPtr.Zero) continue;

                    _additionalLinks.Add(link);
                    attachedPrograms.Add(programName);
                    attached++;
                }

                // Gate v2 facts on the new object's context-map marker. Mixed
                // older managed/tracer pairs must not claim these corrections.
                bool contractV2 = LoadedTier == "core" &&
                    LibBpf.bpf_object__find_map_by_name(BpfObject, "udp_sendmsg_ctx_map") != IntPtr.Zero;
                RuntimeCapabilities.Feature(CapabilityKey, "networkContractVersion", contractV2 ? 2 : 0);
                if (contractV2)
                {
                    RuntimeCapabilities.Feature(CapabilityKey, "tcpAcceptReturnAttached", attachedPrograms.Contains("kretprobe__inet_csk_accept"));
                    RuntimeCapabilities.Feature(CapabilityKey, "udpSendSuccessReturnAttached", attachedPrograms.Contains("kprobe__udp_sendmsg") && attachedPrograms.Contains("kretprobe__udp_sendmsg"));
                    RuntimeCapabilities.Feature(CapabilityKey, "udpReceiveSuccessReturnAttached", attachedPrograms.Contains("kprobe__udp_recvmsg") && attachedPrograms.Contains("kretprobe__udp_recvmsg"));
                    RuntimeCapabilities.Feature(CapabilityKey, "tcpSendReceiveSampleIntervalMs", 1000);
                    RuntimeCapabilities.Feature(CapabilityKey, "udpSendSampleIntervalMs", 1000);
                    RuntimeCapabilities.Feature(CapabilityKey, "udpConnectedReceiveSampleIntervalMs", 1000);
                    RuntimeCapabilities.Feature(CapabilityKey, "udpPeerBufferReceiveSampleIntervalMs", 0);
                    RuntimeCapabilities.Feature(CapabilityKey, "udpByteMeaning", "successful-protocol-return; not syscall/packet conservation");
                    RuntimeCapabilities.Feature(CapabilityKey, "tcpByteMeaning", "requested-at-entry; sampled; not successful transfer");
                    RuntimeCapabilities.Feature(CapabilityKey, "localAddressMeaning", "best-effort socket address; loopback wildcard interpretation retained");
                }

                WintapLogger.Log.Append($"{SensorName} attached {attached} additional network programs", LogLevel.Info);
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} error attaching programs: {ex.Message}", LogLevel.Error);
                return false;
            }
        }

        protected override LibBpf.RingBufferCallback GetRingBufferCallback() => HandleEvent;

        private int HandleEvent(IntPtr ctx, IntPtr data, UIntPtr size)
        {
            try
            {
                var evt = Marshal.PtrToStructure<NetworkEvent>(data);
                
                if (evt.Comm == null)
                    return 0;

                // Handle in-band diagnostic events emitted by the tracer
                if (evt.Protocol == 0xFF)
                {
                    // opType is the diag code: 0=STORE,1=HIT,2=MISS
                    int diag = evt.OpType;
                    int pid_diag = (int)evt.Pid;
                    uint sk_lo = evt.Bytes; // low 32 bits of socket ptr
                    WintapLogger.Log.Append($"BPF diag event code={diag} pid={pid_diag} sk_lo=0x{sk_lo:x8}", LogLevel.Info);
                    // Maintain local aggregates for quick visibility
                    switch (diag)
                    {
                        case 0: System.Threading.Interlocked.Increment(ref _diagStore); break;
                        case 1: System.Threading.Interlocked.Increment(ref _diagHit); break;
                        case 2: System.Threading.Interlocked.Increment(ref _diagMiss); break;
                    }
                    return 0;
                }

                int pid = (int)evt.Pid;

                // Some kernels/backports can result in protocol being unreliable for
                // certain probe sites. Fall back to op_type classification so TCP
                // connect/accept/disconnect events still flow into the TCP Esper
                // stream and parquet outputs.
                bool isTcp = evt.Protocol == 6 || (evt.OpType >= 1 && evt.OpType <= 5);
                bool isUdp = evt.Protocol == 17 || (evt.OpType == 6 || evt.OpType == 7);

                // Map operation type to activity
                WintapMessage.ActivityTypeEnum activityType = evt.OpType switch
                {
                    1 => WintapMessage.ActivityTypeEnum.TcpIpConnect,
                    2 => WintapMessage.ActivityTypeEnum.TcpIpAccept,
                    3 => WintapMessage.ActivityTypeEnum.TcpIpSend,
                    4 => WintapMessage.ActivityTypeEnum.TcpIpRecv,
                    5 => WintapMessage.ActivityTypeEnum.TcpIpDisconnect,
                    6 => WintapMessage.ActivityTypeEnum.UdpIpSend,
                    7 => WintapMessage.ActivityTypeEnum.UdpIpRecv,
                    _ => WintapMessage.ActivityTypeEnum.Other
                };

                // Create appropriate message type
                var messageType = isTcp
                    ? WintapMessage.MessageTypeEnum.TcpConnection
                    : WintapMessage.MessageTypeEnum.UdpPacket;

                DateTime eventTimeUtc = KernelTimestampConverter.ToUtcDateTime(
                    evt.TimestampNs,
                    _monotonicToRealtimeOffsetNs);
                var message = new WintapMessage(
                    eventTimeUtc,
                    pid,
                    messageType
                );

                message.ActivityType = activityType;
                message.ActivityId = "";
                message.CorrelationId = "";
                // A PID plus callback time is not a process identity. Stamp a
                // stable cache-/proc-derived identity while the owner is live;
                // otherwise leave this empty for the bounded resolver retry.
                message.PidHash = "";
                message.ProcessName = evt.GetComm() ?? "unknown";
                EventChannel.TryPopulateCurrentProcessIdentity(message);

                // Convert network byte order IP to string
                string sourceIp = ConvertIpToString(evt.Saddr);
                string destIp = ConvertIpToString(evt.Daddr);

                if (isTcp)
                {
                    message.TcpConnection = new WintapMessage.TcpConnectionObject
                    {
                        SourceAddress = sourceIp,
                        SourcePort = evt.Sport,
                        DestinationAddress = destIp,
                        DestinationPort = evt.Dport,
                        PacketSize = evt.Bytes,
                        PID = pid
                    };
                }
                else if (isUdp)
                {
                    message.UdpPacket = new WintapMessage.UdpPacketObject
                    {
                        SourceAddress = sourceIp,
                        SourcePort = evt.Sport,
                        DestinationAddress = destIp,
                        DestinationPort = evt.Dport,
                        PacketSize = evt.Bytes,
                        PID = pid
                    };
                }

                AttributionTrace.Record(message, "network-producer-prepared");
                EventChannel.Send(message);
                AttributionTrace.Record(message, "network-producer-send-returned");
                return 0;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} event handler error: {ex.Message}", LogLevel.Error);
                return -1;
            }
        }

        private string ConvertIpToString(uint ipNetworkOrder)
        {
            if (ipNetworkOrder == 0)
                return "0.0.0.0";

            // eBPF sends the IPv4 address as the raw 4 bytes used by the
            // kernel/network stack. Marshal reads those bytes into a native
            // endian uint, so converting back to bytes preserves the address
            // order for IPAddress.
            return new IPAddress(BitConverter.GetBytes(ipNetworkOrder)).ToString();
        }

        protected override void OnStopping()
        {
            try
            {
                _diagReporterCancel?.Cancel();
                _diagReporterThread?.Join(TimeSpan.FromSeconds(2));
            }
            catch { }

            foreach (var link in _additionalLinks)
            {
                if (link != IntPtr.Zero)
                    LibBpf.bpf_link__destroy(link);
            }
            _additionalLinks.Clear();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct NetworkEvent
    {
        public uint Pid;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Comm;

        public ulong TimestampNs;
        
        public uint Saddr;
        public uint Daddr;
        public ushort Sport;
        public ushort Dport;
        public byte Protocol;
        public byte OpType;
        
        public uint Bytes;
        
        public byte IsIpv6;
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] SaddrV6;
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] DaddrV6;

        public string GetComm() => StructHelper.GetString(Comm);
    }
}
