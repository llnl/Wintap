using gov.llnl.wintap;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using System;
using System.Collections.Generic;
using System.Text;
using System.Globalization;
using System.Threading;
using System.Timers;

namespace gov.llnl.wintap.core.infrastructure.health
{
    internal sealed class SensorHealthMonitor
    {
        private const int UnknownStreamOffset = 1;
        private const int LivenessTickSeconds = 5;
        private const int LivenessGraceSeconds = 60;
        // MemoryMap bypasses EventChannel.Send today; its signal becomes meaningful after shc-02 wires its direct egress site.
        private static readonly WintapMessage.MessageTypeEnum[] WatchedStreams = { WintapMessage.MessageTypeEnum.File, WintapMessage.MessageTypeEnum.Registry, WintapMessage.MessageTypeEnum.MemoryMap, WintapMessage.MessageTypeEnum.ImageLoad, WintapMessage.MessageTypeEnum.TcpConnection, WintapMessage.MessageTypeEnum.UdpPacket };
        private static readonly Lazy<SensorHealthMonitor> defaultMonitor = new Lazy<SensorHealthMonitor>(CreateDefault);

        private readonly IReadOnlyList<IWintapHealthCheck> checks;
        private readonly int typeCount;
        private readonly long[] checkedCounts;
        private readonly long[] previousFlushCounts;
        private readonly long[] failureCounts;
        private readonly string[][] samples;
        private readonly int[] sampleClaims;
        private readonly long[] lastTickCounts;
        private readonly bool[] stalled;
        private readonly DateTime[] stalledSinceUtc;
        private readonly int sampleCap;
        private readonly Action<string, LogLevel> logSink;
        private readonly System.Timers.Timer flushTimer;
        private readonly System.Timers.Timer livenessTimer;
        private DateTime windowStartUtc;
        private DateTime startTimeUtc;
        private int enabled;
        private int started;
        private int disableLogged;
        private int flushOwned;
        private readonly int attributionCheckIndex;
        private readonly long[] passedCounts, unresolvedCounts, previousPassed, previousUnresolved;
        private readonly DateTime monitorCreatedUtc;

        internal SensorHealthMonitor(IReadOnlyList<IWintapHealthCheck> checks, bool enabled, int sampleCap, int flushIntervalSeconds, Action<string, LogLevel> logSink = null)
        {
            this.checks = checks ?? Array.Empty<IWintapHealthCheck>();
            typeCount = HighestMessageTypeValue() + 1;
            checkedCounts = new long[typeCount + UnknownStreamOffset];
            previousFlushCounts = new long[typeCount + UnknownStreamOffset];
            failureCounts = new long[(typeCount + UnknownStreamOffset) * this.checks.Count];
            samples = new string[(typeCount + UnknownStreamOffset) * this.checks.Count][];
            sampleClaims = new int[(typeCount + UnknownStreamOffset) * this.checks.Count];
            lastTickCounts = new long[typeCount + UnknownStreamOffset];
            stalled = new bool[typeCount + UnknownStreamOffset];
            stalledSinceUtc = new DateTime[typeCount + UnknownStreamOffset];
            this.sampleCap = Math.Max(0, Math.Min(20, sampleCap));
            FlushIntervalSeconds = Math.Max(5, flushIntervalSeconds);
            this.enabled = enabled ? 1 : 0;
            this.logSink = logSink ?? ((line, level) => WintapLogger.Log.Append(line, level));
            windowStartUtc = monitorCreatedUtc = DateTime.UtcNow;
            attributionCheckIndex = FindAttributionCheck(this.checks);
            passedCounts = new long[checkedCounts.Length];
            unresolvedCounts = new long[checkedCounts.Length];
            previousPassed = new long[checkedCounts.Length];
            previousUnresolved = new long[checkedCounts.Length];

            flushTimer = new System.Timers.Timer(FlushIntervalSeconds * 1000) { AutoReset = true };
            flushTimer.Elapsed += FlushTimerElapsed;
            livenessTimer = new System.Timers.Timer(LivenessTickSeconds * 1000) { AutoReset = true };
            livenessTimer.Elapsed += LivenessTimerElapsed;
        }

        internal static SensorHealthMonitor Default => defaultMonitor.Value;
        internal bool IsEnabled => Volatile.Read(ref enabled) != 0;
        internal int FlushIntervalSeconds { get; }

        internal static SensorHealthMonitor CreateDefault()
        {
            try
            {
                string enabledValue = ConfigManager.GetValue<string>("WINTAP_HEALTH_ENABLED");
                bool enabled = ParseEnabled(enabledValue, OperatingSystem.IsWindows());
                int flushSeconds = ParseInt(ConfigManager.GetValue<string>("WINTAP_HEALTH_FLUSH_SECONDS"), 60, 5, int.MaxValue);
                int cap = ParseInt(ConfigManager.GetValue<string>("WINTAP_HEALTH_SAMPLE_CAP"), 3, 0, 20);
                return new SensorHealthMonitor(DefaultHealthChecks.CreateAll(), enabled, cap, flushSeconds);
            }
            catch
            {
                return new SensorHealthMonitor(DefaultHealthChecks.CreateAll(), OperatingSystem.IsWindows(), 3, 60);
            }
        }

        internal void Inspect(WintapMessage msg)
        {
            if (!IsEnabled || msg == null) return;
            try
            {
                int streamIndex = GetStreamIndex(msg.MessageType);
                Interlocked.Increment(ref checkedCounts[streamIndex]);
                for (int checkIndex = 0; checkIndex < checks.Count; checkIndex++)
                {
                    IWintapHealthCheck check = checks[checkIndex];
                    bool passes = check.Passes(msg);
                    if (checkIndex == attributionCheckIndex)
                    {
                        if (passes) Interlocked.Increment(ref passedCounts[streamIndex]);
                        else Interlocked.Increment(ref unresolvedCounts[streamIndex]);
                    }
                    if (!passes)
                    {
                        int failureIndex = streamIndex * checks.Count + checkIndex;
                        Interlocked.Increment(ref failureCounts[failureIndex]);
                        CaptureSample(failureIndex, check, msg);
                    }
                }
            }
            catch (Exception ex)
            {
                Interlocked.Exchange(ref enabled, 0);
                if (Interlocked.Exchange(ref disableLogged, 1) == 0) SafeLog("SensorHealth disabled after internal error: " + ex.Message, LogLevel.Warn);
            }
        }

        internal void Start()
        {
            if (!IsEnabled || Interlocked.Exchange(ref started, 1) != 0) return;
            startTimeUtc = DateTime.UtcNow;
            for (int i = 0; i < checkedCounts.Length; i++)
            {
                lastTickCounts[i] = Interlocked.Read(ref checkedCounts[i]);
                stalled[i] = false;
                stalledSinceUtc[i] = default;
            }
            flushTimer.Start();
            livenessTimer.Start();
        }

        internal void Stop()
        {
            if (Interlocked.Exchange(ref started, 0) == 0) return;
            flushTimer.Stop();
            livenessTimer.Stop();
            for (int i = 0; i < stalled.Length; i++)
            {
                stalled[i] = false;
                stalledSinceUtc[i] = default;
                lastTickCounts[i] = Interlocked.Read(ref checkedCounts[i]);
            }
            try { FlushNow(); } catch { }
        }

        /// <summary>Timer, Stop, and explicit callers share nonblocking flush ownership.</summary>
        internal void FlushNow()
        {
            if (Interlocked.CompareExchange(ref flushOwned, 1, 0) != 0) return;
            try { FlushOwned(); }
            finally { Volatile.Write(ref flushOwned, 0); }
        }

        private void FlushOwned()
        {
            if (!IsEnabled) return;
            DateTime beginUtc = windowStartUtc;
            DateTime endUtc = DateTime.UtcNow;
            bool hasActivity = false;
            StringBuilder summary = new StringBuilder("SensorHealth: window=");
            summary.Append(FormatUtc(windowStartUtc)).Append("..").Append(FormatUtc(endUtc)).Append(" checked");
            for (int stream = 0; stream < checkedCounts.Length; stream++)
            {
                long total = Interlocked.Read(ref checkedCounts[stream]);
                long delta = total - previousFlushCounts[stream];
                previousFlushCounts[stream] = total;
                if (delta > 0)
                {
                    hasActivity = true;
                    summary.Append(' ').Append(StreamName(stream)).Append('=').Append(delta);
                }
            }
            windowStartUtc = endUtc;
            FlushAttribution(beginUtc, endUtc);
            if (!hasActivity) return;
            SafeLog(summary.ToString(), LogLevel.Info);

            for (int stream = 0; stream < checkedCounts.Length; stream++)
            {
                for (int checkIndex = 0; checkIndex < checks.Count; checkIndex++)
                {
                    int failureIndex = stream * checks.Count + checkIndex;
                    long failures = Interlocked.Exchange(ref failureCounts[failureIndex], 0);
                    string[] captured = Interlocked.Exchange(ref samples[failureIndex], null);
                    Interlocked.Exchange(ref sampleClaims[failureIndex], 0);
                    if (failures == 0) continue;
                    StringBuilder line = new StringBuilder("SensorHealth FAIL: stream=");
                    line.Append(StreamName(stream)).Append(" check=").Append(checks[checkIndex].Name).Append(" count=").Append(failures);
                    if (captured != null)
                    {
                        bool wroteSample = false;
                        for (int i = 0; i < captured.Length; i++)
                        {
                            if (captured[i] == null) continue;
                            line.Append(wroteSample ? " | " : " samples: ").Append(captured[i]);
                            wroteSample = true;
                        }
                    }
                    SafeLog(line.ToString(), LogLevel.Warn);
                }
            }
        }

        private static int FindAttributionCheck(IReadOnlyList<IWintapHealthCheck> candidates)
        {
            try
            {
                int found = -1;
                for (int i = 0; i < candidates.Count; i++)
                {
                    if (!string.Equals(candidates[i].Name, "process_unresolved", StringComparison.Ordinal)) continue;
                    if (found >= 0) return -1;
                    found = i;
                }
                return found;
            }
            catch { return -1; }
        }

        private void FlushAttribution(DateTime beginUtc, DateTime endUtc)
        {
            if (attributionCheckIndex < 0) return;
            long intervalEvaluated = 0, intervalFailed = 0, totalEvaluated = 0, totalFailed = 0;
            for (int stream = 0; stream < checkedCounts.Length; stream++)
            {
                long passed = Interlocked.Read(ref passedCounts[stream]);
                long failed = Interlocked.Read(ref unresolvedCounts[stream]);
                long deltaFailed = failed - previousUnresolved[stream];
                long deltaEvaluated = passed - previousPassed[stream] + deltaFailed;
                previousPassed[stream] = passed;
                previousUnresolved[stream] = failed;
                long evaluated = passed + failed;
                intervalEvaluated += deltaEvaluated;
                intervalFailed += deltaFailed;
                totalEvaluated += evaluated;
                totalFailed += failed;
                if (evaluated != 0)
                    LogAttribution(beginUtc, endUtc, StreamName(stream), deltaEvaluated, deltaFailed, evaluated, failed);
            }
            if (totalEvaluated != 0)
                LogAttribution(beginUtc, endUtc, "_overall", intervalEvaluated, intervalFailed, totalEvaluated, totalFailed);
        }

        private void LogAttribution(DateTime beginUtc, DateTime endUtc, string stream,
            long intervalEvaluated, long intervalFailed, long totalEvaluated, long totalFailed)
        {
            string intervalPct = intervalEvaluated == 0 ? "n/a" :
                (100.0 * intervalFailed / intervalEvaluated).ToString("F6", CultureInfo.InvariantCulture);
            SafeLog(string.Format(CultureInfo.InvariantCulture,
                "SensorHealth ATTRIBUTION: window={0}..{1} since={2} stream={3} intervalEvaluated={4} intervalUnresolved={5} intervalUnresolvedPct={6} totalEvaluated={7} totalUnresolved={8} totalUnresolvedPct={9}",
                FormatUtc(beginUtc), FormatUtc(endUtc), FormatUtc(monitorCreatedUtc), stream,
                intervalEvaluated, intervalFailed, intervalPct, totalEvaluated, totalFailed,
                (100.0 * totalFailed / totalEvaluated).ToString("F6", CultureInfo.InvariantCulture)), LogLevel.Info);
        }
        internal void EvaluateLivenessTick(DateTime utcNow)
        {
            if (!IsEnabled || Volatile.Read(ref started) == 0) return;
            bool grace = utcNow < startTimeUtc.AddSeconds(LivenessGraceSeconds);
            for (int i = 0; i < WatchedStreams.Length; i++)
            {
                int stream = GetStreamIndex(WatchedStreams[i]);
                long total = Interlocked.Read(ref checkedCounts[stream]);
                long delta = total - lastTickCounts[stream];
                lastTickCounts[stream] = total;
                if (grace)
                {
                    stalled[stream] = false;
                    continue;
                }
                if (delta == 0 && !stalled[stream])
                {
                    stalled[stream] = true;
                    stalledSinceUtc[stream] = utcNow;
                    SafeLog("SensorHealth STALL: stream=" + StreamName(stream) + " no events in 5s interval", LogLevel.Error);
                }
                else if (delta > 0 && stalled[stream])
                {
                    long seconds = Math.Max(0, (long)(utcNow - stalledSinceUtc[stream]).TotalSeconds);
                    stalled[stream] = false;
                    SafeLog("SensorHealth RECOVERED: stream=" + StreamName(stream) + " stalledSeconds=" + seconds, LogLevel.Info);
                }
            }
        }

        private void CaptureSample(int failureIndex, IWintapHealthCheck check, WintapMessage msg)
        {
            if (sampleCap == 0) return;
            int claim = Interlocked.Increment(ref sampleClaims[failureIndex]) - 1;
            if (claim >= sampleCap) return;
            string[] slot = Volatile.Read(ref samples[failureIndex]);
            if (slot == null)
            {
                string[] created = new string[sampleCap];
                slot = Interlocked.CompareExchange(ref samples[failureIndex], created, null) ?? created;
            }
            slot[claim] = check.Describe(msg);
        }

        private void FlushTimerElapsed(object sender, ElapsedEventArgs e)
        {
            try { FlushNow(); } catch (Exception ex) { SafeLog("SensorHealth flush error: " + ex.Message, LogLevel.Warn); }
        }

        private void LivenessTimerElapsed(object sender, ElapsedEventArgs e)
        {
            try { EvaluateLivenessTick(DateTime.UtcNow); } catch (Exception ex) { SafeLog("SensorHealth liveness error: " + ex.Message, LogLevel.Warn); }
        }

        private void SafeLog(string line, LogLevel level)
        {
            try { logSink(line, level); } catch { }
        }

        private int GetStreamIndex(WintapMessage.MessageTypeEnum type)
        {
            int index = (int)type;
            return index >= 0 && index < typeCount ? index : typeCount;
        }

        private string StreamName(int index) => index == typeCount ? "_unknown" : ((WintapMessage.MessageTypeEnum)index).ToString();
        private static string FormatUtc(DateTime value) => value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        private static int HighestMessageTypeValue() { int highest = 0; foreach (WintapMessage.MessageTypeEnum value in Enum.GetValues(typeof(WintapMessage.MessageTypeEnum))) highest = Math.Max(highest, (int)value); return highest; }
        private static bool ParseEnabled(string value, bool fallback) => string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1" ? true : string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) || value == "0" ? false : fallback;
        private static int ParseInt(string value, int fallback, int minimum, int maximum) => int.TryParse(value, out int parsed) ? Math.Max(minimum, Math.Min(maximum, parsed)) : fallback;
    }
}
