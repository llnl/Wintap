using gov.llnl.wintap.core.collect;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Base class for eBPF-based sensors
    /// Handles common eBPF loading, polling, and cleanup
    /// </summary>
    internal abstract class BaseEbpfSensor : BaseSensor
    {
        // eBPF resources
        protected IntPtr BpfObject = IntPtr.Zero;
        protected IntPtr BpfLink = IntPtr.Zero;
        protected IntPtr RingBuffer = IntPtr.Zero;
        
        // Keep strong reference to callback to prevent GC
        protected LibBpf.RingBufferCallback? RingBufferCallback;
        
        // Threading
        protected Thread? PollingThread;
        protected volatile bool IsRunning = false;
        // Diagnostics thread that polls BPF maps (e.g., diag_counters)
        protected Thread? DiagThread;
        protected CancellationTokenSource? DiagCancel;

        // Abstract properties - subclasses define these
        protected abstract string BpfObjectFileName { get; }
        protected abstract string BpfProgramName { get; }
        protected virtual string[] FallbackBpfObjectFileNames => Array.Empty<string>();

        /// <summary>
        /// Start the sensor - loads eBPF program and starts polling
        /// </summary>
        public override bool Start()
        {
            try
            {
                WintapLogger.Log.Append($"Starting {SensorName} sensor...", LogLevel.Info);

                // Check root privileges (required for eBPF)
                if (getuid() != 0)
                {
                    WintapLogger.Log.Append($"{SensorName} requires root privileges", LogLevel.Error);
                    return false;
                }

                LogEbpfEnvironment();

                string[] candidates = GetBpfObjectCandidates();
                if (!TryLoadBpfProgram(candidates, out string loadedPath))
                {
                    return false;
                }

                WintapLogger.Log.Append($"{SensorName} loaded eBPF object: {loadedPath}", LogLevel.Info);

                // Allow subclass to do additional initialization
                if (!OnStarting())
                {
                    Stop();
                    return false;
                }

                // Start polling thread
                IsRunning = true;
                PollingThread = new Thread(PollRingBuffer)
                {
                    IsBackground = true,
                    Name = $"{SensorName}-Poller"
                };
                PollingThread.Start();

                WintapLogger.Log.Append($"{SensorName} sensor started", LogLevel.Info);
                return true;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Failed to start {SensorName}: {ex.Message}", LogLevel.Error);
                WintapLogger.Log.Append($"{SensorName} stack trace: {ex.StackTrace}", LogLevel.Debug);
                Stop();
                return false;
            }
        }

        /// <summary>
        /// Load and attach eBPF program to kernel
        /// </summary>
        private bool TryLoadBpfProgram(string[] candidates, out string loadedPath)
        {
            loadedPath = string.Empty;

            foreach (string candidate in candidates)
            {
                string bpfPath = FindBpfObject(candidate);
                WintapLogger.Log.Append($"{SensorName} searching for eBPF object: {candidate}", LogLevel.Debug);
                WintapLogger.Log.Append($"{SensorName} candidate path: {bpfPath}", LogLevel.Debug);

                if (!File.Exists(bpfPath))
                {
                    WintapLogger.Log.Append($"{SensorName} BPF object not found: {bpfPath}", LogLevel.Warn);
                    continue;
                }

                if (LoadBpfProgram(bpfPath))
                {
                    loadedPath = bpfPath;
                    return true;
                }

                WintapLogger.Log.Append($"{SensorName} failed to load candidate eBPF object: {bpfPath}", LogLevel.Warn);
                CleanupBpfResources();
            }

            WintapLogger.Log.Append($"{SensorName} could not load any eBPF object candidate", LogLevel.Error);
            return false;
        }

        private bool LoadBpfProgram(string bpfPath)
        {
            // Open BPF object
            BpfObject = LibBpf.bpf_object__open(bpfPath);
            if (BpfObject == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} failed to open BPF object", LogLevel.Error);
                return false;
            }

            // Load into kernel
            int ret = LibBpf.bpf_object__load(BpfObject);
            if (ret != 0)
            {
                WintapLogger.Log.Append($"{SensorName} failed to load BPF: {ret}", LogLevel.Error);
                return false;
            }

            // Find program by name
            IntPtr prog = LibBpf.bpf_object__find_program_by_name(BpfObject, BpfProgramName);
            if (prog == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} program '{BpfProgramName}' not found", LogLevel.Error);
                return false;
            }

            // Attach to tracepoint
            BpfLink = LibBpf.bpf_program__attach(prog);
            if (BpfLink == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} failed to attach program", LogLevel.Error);
                return false;
            }

            // Setup ring buffer
            IntPtr eventsMap = LibBpf.bpf_object__find_map_by_name(BpfObject, "events");
            if (eventsMap == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} events map not found", LogLevel.Error);
                return false;
            }

            int mapFd = LibBpf.bpf_map__fd(eventsMap);
            
            // CRITICAL: Store callback in instance field to prevent GC
            RingBufferCallback = GetRingBufferCallback();
            
            RingBuffer = LibBpf.ring_buffer__new(mapFd, RingBufferCallback, IntPtr.Zero, IntPtr.Zero);
            if (RingBuffer == IntPtr.Zero)
            {
                WintapLogger.Log.Append($"{SensorName} failed to create ring buffer", LogLevel.Error);
                return false;
            }

            if (ConfigManager.GetValue<bool>("EnableBpfDiagMonitor"))
            {
                // Start diagnostics monitor in background. It will look for a map named
                // "diag_counters" and periodically log STORE/HIT/MISS counts. This uses
                // bpftool and creates subprocess noise, so it is opt-in only.
                StartDiagMonitor();
            }

            return true;
        }

        private string[] GetBpfObjectCandidates()
        {
            string[] fallbacks = FallbackBpfObjectFileNames ?? Array.Empty<string>();
            string[] candidates = new string[1 + fallbacks.Length];
            candidates[0] = BpfObjectFileName;
            for (int i = 0; i < fallbacks.Length; i++)
            {
                candidates[i + 1] = fallbacks[i];
            }
            return candidates;
        }

        private void LogEbpfEnvironment()
        {
            try
            {
                string arch = RuntimeInformation.ProcessArchitecture.ToString();
                bool btfPresent = File.Exists("/sys/kernel/btf/vmlinux");
                WintapLogger.Log.Append($"{SensorName} eBPF environment: arch={arch}, kernel_btf_present={btfPresent}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"{SensorName} could not inspect eBPF environment: {ex.Message}", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Ring buffer polling thread
        /// </summary>
        private void PollRingBuffer()
        {
            while (IsRunning)
            {
                try
                {
                    int pollRet = LibBpf.ring_buffer__poll(RingBuffer, 100);

                    if (pollRet < 0 && pollRet != -4) // -4 is EINTR
                    {
                        WintapLogger.Log.Append($"{SensorName} poll error: {pollRet}", LogLevel.Warn);
                    }
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append($"{SensorName} poll exception: {ex.Message}", LogLevel.Error);
                    Thread.Sleep(100);
                }
            }
        }

        /// <summary>
        /// Stop the sensor - cleanup eBPF resources
        /// </summary>
        public override void Stop()
        {
            WintapLogger.Log.Append($"Stopping {SensorName} sensor...", LogLevel.Info);

            IsRunning = false;

            // Stop diagnostic monitor if running
            try
            {
                DiagCancel?.Cancel();
                DiagThread?.Join(TimeSpan.FromSeconds(2));
            }
            catch { }

            // Native ring-buffer memory must not be freed while poll is still
            // executing a callback. A timed join can expire under a burst and
            // turn the cleanup below into a use-after-free/segfault.
            WaitForThreadExit(PollingThread);

            // Allow subclass cleanup
            OnStopping();

            CleanupBpfResources();

            WintapLogger.Log.Append($"{SensorName} sensor stopped", LogLevel.Info);
        }

        internal static void WaitForThreadExit(Thread thread)
        {
            thread?.Join();
        }

        private void CleanupBpfResources()
        {
            if (RingBuffer != IntPtr.Zero)
            {
                LibBpf.ring_buffer__free(RingBuffer);
                RingBuffer = IntPtr.Zero;
            }

            if (BpfLink != IntPtr.Zero)
            {
                LibBpf.bpf_link__destroy(BpfLink);
                BpfLink = IntPtr.Zero;
            }

            if (BpfObject != IntPtr.Zero)
            {
                LibBpf.bpf_object__close(BpfObject);
                BpfObject = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Find eBPF object file in various locations
        /// </summary>
        protected virtual string FindBpfObject(string fileName)
        {
            var locations = new[]
            {
                fileName,
                $"./sensor/ebpf/tracers/{fileName}",
                $"./platform/linux/sensor/ebpf/tracers/{fileName}",  // Build output path
                $"./tracers/{fileName}",
                $"/opt/wintap/tracers/{fileName}",
                Path.Combine(AppContext.BaseDirectory, fileName),
                Path.Combine(AppContext.BaseDirectory, "platform", "linux", "sensor", "ebpf", "tracers", fileName),
                Path.Combine(AppContext.BaseDirectory, "tracers", fileName)
            };

            foreach (var location in locations)
            {
                if (File.Exists(location))
                    return location;
            }

            return fileName;
        }

        /// <summary>
        /// Get ring buffer callback - subclass implements this
        /// </summary>
        protected abstract LibBpf.RingBufferCallback GetRingBufferCallback();

        /// <summary>
        /// Hook for subclass initialization (optional)
        /// </summary>
        protected virtual bool OnStarting() => true;

        /// <summary>
        /// Hook for subclass cleanup (optional)
        /// </summary>
        protected virtual void OnStopping() { }

        private void StartDiagMonitor()
        {
            try
            {
                DiagCancel = new CancellationTokenSource();
                var ct = DiagCancel.Token;
                DiagThread = new Thread(() =>
                {
                    while (!ct.IsCancellationRequested)
                    {
                        try
                        {
                            // Find diag_counters map via bpftool
                            var psi = new System.Diagnostics.ProcessStartInfo("bpftool", "map list -j")
                            {
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            using var p = System.Diagnostics.Process.Start(psi);
                            if (p == null)
                                throw new Exception("bpftool start failed");
                            string outJson = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(2000);

                            int mapId = -1;
                            if (!string.IsNullOrWhiteSpace(outJson))
                            {
                                try
                                {
                                    using var doc = System.Text.Json.JsonDocument.Parse(outJson);
                                    foreach (var el in doc.RootElement.EnumerateArray())
                                    {
                                        if (el.TryGetProperty("name", out var nameEl) && nameEl.GetString() == "diag_counters")
                                        {
                                            if (el.TryGetProperty("id", out var idEl))
                                                mapId = idEl.GetInt32();
                                            break;
                                        }
                                    }
                                }
                                catch { /* ignore JSON parse errors */ }
                            }

                            if (mapId != -1)
                            {
                                // Dump map entries human-readable and parse keys/values
                                var psi2 = new System.Diagnostics.ProcessStartInfo("bpftool", $"map dump id {mapId} -p")
                                {
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                using var p2 = System.Diagnostics.Process.Start(psi2);
                                if (p2 != null)
                                {
                                    string dump = p2.StandardOutput.ReadToEnd();
                                    p2.WaitForExit(2000);
                                    long store = 0, hit = 0, miss = 0;
                                    foreach (var line in dump.Split('\n'))
                                    {
                                        var s = line.Trim();
                                        if (s.Length == 0) continue;

                                        // Lines may be one of:
                                        //   key: 0 value: 123
                                        // or for per-cpu arrays:
                                        //   key: 0 value: 12, 0, 7
                                        try
                                        {
                                            int key = -1;
                                            int idx = s.IndexOf("key:", StringComparison.Ordinal);
                                            if (idx >= 0)
                                            {
                                                var after = s.Substring(idx + 4).Trim();
                                                var parts = after.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                                if (parts.Length > 0)
                                                {
                                                    int.TryParse(parts[0].TrimEnd(':'), out key);
                                                }
                                            }

                                            long valueSum = 0;
                                            idx = s.IndexOf("value:", StringComparison.Ordinal);
                                            if (idx >= 0)
                                            {
                                                var valPart = s.Substring(idx + 6).Trim();
                                                // Remove any trailing characters
                                                valPart = valPart.Trim();
                                                // If per-cpu, values are comma-separated
                                                var tokens = valPart.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                                foreach (var t in tokens)
                                                {
                                                    if (long.TryParse(t.Trim(), out var parsed))
                                                        valueSum += parsed;
                                                }
                                            }

                                            if (key == 0) store = valueSum;
                                            else if (key == 1) hit = valueSum;
                                            else if (key == 2) miss = valueSum;
                                        }
                                        catch { }
                                    }

                                    WintapLogger.Log.Append($"BPF diag counters (STORE/HIT/MISS) = {store}/{hit}/{miss}", LogLevel.Info);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            WintapLogger.Log.Append($"DiagMonitor error: {ex.Message}", LogLevel.Debug);
                        }

                        try {
                            int waitMs = 5000;
                            for (int i = 0; i < waitMs / 200; i++)
                            {
                                if (ct.IsCancellationRequested) break;
                                Thread.Sleep(200);
                            }
                        } catch { }
                    }
                }) { IsBackground = true };

                DiagThread.Start();
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Failed to start diag monitor: {ex.Message}", LogLevel.Debug);
            }
        }

        [DllImport("libc")]
        private static extern uint getuid();
    }
}
