using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace gov.llnl.wintap.core.infrastructure
{
    // Startup evidence, not a claim of continuous health or loss-free capture.
    public sealed class RuntimeCapabilityReceipt
    {
        public int SchemaVersion { get; set; } = 1;
        public string CaptureRunId { get; set; } = Guid.NewGuid().ToString("D");
        public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime? CompletedAtUtc { get; set; }
        public string Phase { get; set; } = "starting";
        public string Platform { get; set; }
        public string Architecture { get; set; }
        public string KernelRelease { get; set; }
        public string OsRelease { get; set; }
        public bool? KernelBtfReadable { get; set; }
        public string ApplicationVersion { get; set; }
        public string Instrumentation { get; set; }
        public SortedDictionary<string, RuntimeSetting> Settings { get; set; } = new();
        public SortedDictionary<string, RuntimeSensorCapability> Sensors { get; set; } = new();
    }

    public sealed class RuntimeSetting
    {
        public object EffectiveValue { get; set; }
        public string Source { get; set; }
    }

    public sealed class RuntimeSensorCapability
    {
        public bool Enabled { get; set; }
        public string ConfigurationSource { get; set; }
        public string Status { get; set; } = "starting";
        public string FailureReason { get; set; }
        public string LoadedObject { get; set; }
        public string ObjectSha256 { get; set; }
        public string Tier { get; set; }
        public List<RuntimeObjectAttempt> ObjectAttempts { get; set; } = new();
        public SortedDictionary<string, RuntimeHookOutcome> Hooks { get; set; } = new();
        public SortedDictionary<string, object> Features { get; set; } = new();
    }

    public sealed class RuntimeObjectAttempt
    {
        public string Object { get; set; }
        public string Outcome { get; set; }
        public long? ErrorCode { get; set; }
    }

    public sealed class RuntimeHookOutcome
    {
        public string Role { get; set; }
        public string Outcome { get; set; }
        public long? ErrorCode { get; set; }
    }

    public static class RuntimeCapabilities
    {
        private static readonly object Gate = new();
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        private static RuntimeCapabilityReceipt receipt;
        private static string completedJson;
        public static bool IsComplete { get { lock (Gate) return completedJson != null; } }
        public static void EnsureInitialized() { lock (Gate) Ensure(); }

        public static void Begin()
        {
            bool linux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
            lock (Gate)
            {
                completedJson = null;
                receipt = new RuntimeCapabilityReceipt
                {
                    Platform = linux ? "linux" : RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" : "macos",
                    Architecture = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
                    KernelRelease = linux ? ReadText("/proc/sys/kernel/osrelease") : null,
                    OsRelease = linux ? ReadText("/etc/os-release") : null,
                    KernelBtfReadable = linux ? CanRead("/sys/kernel/btf/vmlinux") : null,
                    ApplicationVersion = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(),
                    Instrumentation = linux ? "linux-startup-v1" : "sensor-outcomes-not-instrumented"
                };
            }
        }

        public static void Setting(string key, object value, string source)
        {
            lock (Gate) { Ensure(); receipt.Settings[key] = new RuntimeSetting { EffectiveValue = value, Source = source }; }
        }

        public static void Sensor(string key, bool enabled, string source)
        {
            lock (Gate)
            {
                Ensure();
                receipt.Sensors[key] = new RuntimeSensorCapability
                {
                    Enabled = enabled, ConfigurationSource = source, Status = enabled ? "starting" : "disabled"
                };
            }
        }

        public static void Attempt(string key, string path, string outcome, long? error = null)
        {
            lock (Gate)
            {
                var sensor = GetSensor(key);
                sensor.ObjectAttempts.Add(new RuntimeObjectAttempt { Object = Path.GetFileName(path), Outcome = outcome, ErrorCode = error });
            }
        }

        public static void Loaded(string key, string path, string tier)
        {
            lock (Gate)
            {
                var sensor = GetSensor(key);
                sensor.LoadedObject = Path.GetFileName(path);
                sensor.ObjectSha256 = HashFile(path);
                sensor.Tier = tier;
            }
        }

        public static void Hook(string key, string program, string role, string outcome, long? error = null)
        {
            lock (Gate) GetSensor(key).Hooks[program] = new RuntimeHookOutcome { Role = role, Outcome = outcome, ErrorCode = error };
        }

        public static void Feature(string key, string name, object value)
        {
            lock (Gate) GetSensor(key).Features[name] = value;
        }

        public static void Finished(string key, bool started, string failure = null)
        {
            lock (Gate)
            {
                var sensor = GetSensor(key);
                sensor.FailureReason = started ? null : failure ?? sensor.FailureReason ?? "start-returned-false";
                sensor.Status = !started ? "failed" : sensor.Hooks.Values.Any(h => h.Outcome != "attached" && h.Outcome != "not-applicable") ? "partial" : "running";
            }
        }

        public static string Complete()
        {
            lock (Gate)
            {
                Ensure();
                if (completedJson == null)
                {
                    foreach (var sensor in receipt.Sensors.Values.Where(s => s.Status == "starting"))
                    {
                        sensor.Status = "failed";
                        sensor.FailureReason = "startup-incomplete";
                    }
                    receipt.Phase = "startup-complete";
                    receipt.CompletedAtUtc = DateTime.UtcNow;
                    completedJson = JsonSerializer.Serialize(receipt, JsonOptions);
                }
                return completedJson;
            }
        }

        public static string GetJson()
        {
            lock (Gate) return completedJson ?? (receipt == null ? null : JsonSerializer.Serialize(receipt, JsonOptions));
        }

        public static string GetSensorJson(string key)
        {
            lock (Gate) return JsonSerializer.Serialize(new { schemaVersion = 1, captureRunId = receipt?.CaptureRunId,
                sensor = key, capability = GetSensor(key) }, JsonOptions);
        }

        private static void Ensure() { if (receipt == null) Begin(); }
        private static RuntimeSensorCapability GetSensor(string key)
        {
            Ensure();
            if (!receipt.Sensors.ContainsKey(key)) Sensor(key, true, "direct-start");
            return receipt.Sensors[key];
        }
        private static string ReadText(string path) { try { return File.ReadAllText(path).Trim(); } catch { return null; } }
        private static bool CanRead(string path) { try { using var stream = File.OpenRead(path); return stream.ReadByte() >= 0; } catch { return false; } }
        private static string HashFile(string path)
        {
            try { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
            catch { return null; }
        }
    }
}
