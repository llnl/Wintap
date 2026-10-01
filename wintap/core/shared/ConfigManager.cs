using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Reflection;
using System.Linq;
using System.Globalization;

namespace gov.llnl.wintap.core.shared
{
    public static class ConfigManager
    {
        private static ConfigRoot _config;
        private const string DefaultConfigPath = "wintap/wintap/core/etl/ETLConfig.json";

        static ConfigManager()
        {
            LoadConfig();
        }

        private static void LoadConfig()
        {
            string configPath = Environment.GetEnvironmentVariable("WINTAP_CONFIG_PATH");
            if (string.IsNullOrEmpty(configPath))
            {
                // Try several sensible default locations relative to the running assembly and repository layout.
                var appBase = AppDomain.CurrentDomain.BaseDirectory;
                var candidates = new[]
                {
                    Path.Combine(appBase, DefaultConfigPath),                // default: appBase/wintap/wintap/core/etl/ETLConfig.json
                    Path.Combine(appBase, "ETLConfig.json"),               // appBase/ETLConfig.json
                    Path.GetFullPath(Path.Combine(appBase, "..", "..", "..", "..", "wintap", "core", "etl", "ETLConfig.json")),
                    Path.GetFullPath(Path.Combine(appBase, "..", "..", "wintap", "core", "etl", "ETLConfig.json")),
                    Path.GetFullPath(Path.Combine(appBase, "..", "..", "..", "wintap", "core", "etl", "ETLConfig.json"))
                };

                configPath = candidates.FirstOrDefault(p => File.Exists(p));
            }

            if (!string.IsNullOrEmpty(configPath) && File.Exists(configPath))
            {
                try
                {
                    string json = File.ReadAllText(configPath);
                    _config = JsonSerializer.Deserialize<ConfigRoot>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
                catch
                {
                    // Fallback to default if file is corrupted
                    _config = new ConfigRoot();
                }
            }
            else
            {
                _config = new ConfigRoot();
            }
        }

        // Attempts to resolve a configuration value by the provided key. The key may be either the
        // canonical config property name (e.g. "DataRoot") or an environment-style name
        // (e.g. "WINTAP_DATA_ROOT").
        public static T GetValue<T>(string key)
        {
            try
            {
                // Environment overrides (only for WINTAP_* keys, or keys that map to ConfigRoot properties).
                // This is required for packaged/systemd deployments where /etc/lintap/lintap.env sets
                // WINTAP_DATA_ROOT and runtime isolation flags.
                if (!string.IsNullOrEmpty(key))
                {
                    if (key.StartsWith("WINTAP_", StringComparison.OrdinalIgnoreCase))
                    {
                        var envVal = Environment.GetEnvironmentVariable(key);
                        if (!string.IsNullOrEmpty(envVal) && TryConvertFromString(envVal, out T envTyped))
                        {
                            return envTyped;
                        }
                    }
                }

                // Try direct property lookup (case-insensitive)
                var prop = typeof(ConfigRoot).GetProperty(key, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                if (prop == null)
                {
                    // Try mapping env-style name to PascalCase (strip optional WINTAP_ prefix)
                    string mapped = MapEnvNameToProperty(key);
                    prop = typeof(ConfigRoot).GetProperty(mapped, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                }

                if (prop != null)
                {
                    // Allow env override for known ConfigRoot properties (e.g. DataRoot -> WINTAP_DATA_ROOT)
                    string envName = ToWintapEnvName(prop.Name);
                    var envVal = Environment.GetEnvironmentVariable(envName);
                    if (!string.IsNullOrEmpty(envVal) && TryConvertFromString(envVal, out T envTyped))
                    {
                        return envTyped;
                    }

                    var value = prop.GetValue(_config);
                    if (value == null) return default;
                    return (T)Convert.ChangeType(value, typeof(T));
                }

                // If no property matched and key wasn't WINTAP_* above, return default (do not read arbitrary env vars).
                return default;
            }
            catch
            {
                return default;
            }
        }

        private static bool TryConvertFromString<T>(string value, out T typed)
        {
            typed = default;
            try
            {
                var targetType = typeof(T);
                if (targetType == typeof(string))
                {
                    typed = (T)(object)value;
                    return true;
                }

                if (targetType == typeof(bool) || targetType == typeof(bool?))
                {
                    var v = value.Trim();
                    if (string.Equals(v, "1", StringComparison.OrdinalIgnoreCase))
                    {
                        typed = (T)(object)true;
                        return true;
                    }
                    if (string.Equals(v, "0", StringComparison.OrdinalIgnoreCase))
                    {
                        typed = (T)(object)false;
                        return true;
                    }
                    if (bool.TryParse(v, out var b))
                    {
                        typed = (T)(object)b;
                        return true;
                    }
                    return false;
                }

                // Numeric types
                if (targetType == typeof(int) || targetType == typeof(int?))
                {
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i))
                    {
                        typed = (T)(object)i;
                        return true;
                    }
                    return false;
                }

                if (targetType == typeof(long) || targetType == typeof(long?))
                {
                    if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l))
                    {
                        typed = (T)(object)l;
                        return true;
                    }
                    return false;
                }

                if (targetType == typeof(double) || targetType == typeof(double?))
                {
                    if (double.TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var d))
                    {
                        typed = (T)(object)d;
                        return true;
                    }
                    return false;
                }

                typed = (T)Convert.ChangeType(value, targetType, CultureInfo.InvariantCulture);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string ToWintapEnvName(string propertyName)
        {
            // DataRoot -> WINTAP_DATA_ROOT
            if (string.IsNullOrEmpty(propertyName)) return "WINTAP_";
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < propertyName.Length; i++)
            {
                char c = propertyName[i];
                if (char.IsUpper(c) && i > 0)
                {
                    sb.Append('_');
                }
                sb.Append(char.ToUpperInvariant(c));
            }
            return "WINTAP_" + sb.ToString();
        }

        private static string MapEnvNameToProperty(string key)
        {
            if (string.IsNullOrEmpty(key)) return key;
            string work = key;
            if (work.StartsWith("WINTAP_", StringComparison.OrdinalIgnoreCase))
            {
                work = work.Substring("WINTAP_".Length);
            }

            // Convert snake_case / UPPER_UNDERSCORE to PascalCase
            var parts = work.Split(new[] { '_', '-' }, StringSplitOptions.RemoveEmptyEntries);
            var pascal = string.Join(string.Empty, parts.Select(p => char.ToUpperInvariant(p[0]) + p.Substring(1).ToLowerInvariant()));
            return pascal;
        }
    }

    public class ConfigRoot
    {
        public string DataRoot { get; set; }
        public bool DisableMCP { get; set; } = true;
        public bool DisableDuckDBUI { get; set; } = true;
        public bool DisableETL { get; set; } = false;
        public bool DisableSensors { get; set; } = false;
        public bool EarlyConsole { get; set; } = true;
        public bool DisableSettings { get; set; } = true;
        public bool EnableDirectParquet { get; set; } = false;
        public int DirectParquetFlushSeconds { get; set; } = 15;
        public bool Execve { get; set; } = true;
        public bool Clone { get; set; } = true;
        public bool Exit { get; set; } = true;
        public bool Network { get; set; } = true;
        public bool FileOps { get; set; } = true;
        public bool SELinux { get; set; } = true;
        public string FileOpsDenyComms { get; set; } = "";
        public bool ProcessRundown { get; set; } = true;
        public bool EnableBpfDiagMonitor { get; set; } = false;
        public bool SkipProcessResolve { get; set; } = false;
        public bool SkipParentProcessResolve { get; set; } = false;
        public bool SkipProcessRegister { get; set; } = false;
        public bool SkipEsperSend { get; set; } = false;
        public int ETLMaxQueueEvents { get; set; } = 10000;
        public int ETLMaxQueueEventsSerializer { get; set; } = 10000;
        public string ETLQueueDropPolicy { get; set; } = "newest";
        public int ParquetMaxBatchBacklog { get; set; } = 1000;
        public string ParquetBacklogDropPolicy { get; set; } = "newest";
        public int DirectParquetMaxQueueEvents { get; set; } = 5000;
        public string DirectParquetQueueDropPolicy { get; set; } = "newest";
        public int SerializationIntervalSec { get; set; } = 60;
        public int UploadIntervalSec { get; set; } = 300;
        public bool WriteToParquet { get; set; } = true;
        public string LogLevel { get; set; } = "Normal";
        public string SensorProfile { get; set; } = "Quality";
    }
}
