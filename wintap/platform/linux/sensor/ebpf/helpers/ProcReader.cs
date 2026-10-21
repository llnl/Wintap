using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// Utility for reading process information from /proc filesystem
    /// </summary>
    public static class ProcReader
    {
        private const int _SC_CLK_TCK = 2;
        private static readonly object passwdLock = new object();
        private static Dictionary<uint, string> passwdUserLookup;
        private static DateTime? cachedBootTimeUtc;
        private static long? cachedClockTicksPerSecond;

        /// <summary>
        /// Read comprehensive process information from /proc
        /// </summary>
        public static ProcessInfo ReadProcessInfo(uint pid)
        {
            var info = new ProcessInfo
            {
                Pid = pid
            };

            try
            {
                var procDir = $"/proc/{pid}";
                if (!Directory.Exists(procDir))
                {
                    return info;
                }

                info.Exists = true;

                // Read /proc/<pid>/status
                ReadStatus(procDir, ref info);

                // Read /proc/<pid>/stat for kernel start time
                ReadStat(procDir, ref info);

                // Read /proc/<pid>/cmdline
                ReadCmdline(procDir, ref info);

                // Read /proc/<pid>/environ
                ReadEnviron(procDir, ref info);

                // Read /proc/<pid>/cwd
                ReadCwd(procDir, ref info);

                // /proc/<pid>/exe for executable path
                ReadExe(procDir, ref info);

                if (string.IsNullOrWhiteSpace(info.Username) && info.Uid > 0)
                {
                    info.Username = LookupUsername(info.Uid);
                }
            }
            catch
            {
                // Process may have exited
            }

            return info;
        }

        /// <summary>
        /// Converts a kernel monotonic/boot timestamp captured by an eBPF
        /// lifecycle tracepoint to UTC. This is the fallback identity time when
        /// the child has already exited and /proc is no longer available.
        /// </summary>
        internal static DateTime? TryConvertBootNsToUtc(ulong bootNs)
        {
            if (bootNs == 0) return null;
            try
            {
                // /proc/<pid>/stat stores a start time in clock ticks, not
                // nanoseconds. Quantize the eBPF timestamp to that same basis
                // before hashing so Clone, Execve, and ProcessRundown describe
                // one process identity rather than adjacent identities for a
                // single PID.
                long ticksPerSecond = GetClockTicksPerSecond();
                ulong startTicks = checked((bootNs * (ulong)ticksPerSecond) / 1_000_000_000UL);
                DateTime startUtc = GetBootTimeUtc().AddTicks(
                    checked((long)(startTicks * (ulong)TimeSpan.TicksPerSecond / (ulong)ticksPerSecond)));
                return NormalizeStartTimeUtc(startUtc);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Canonicalize Linux process start times to the nearest /proc clock
        /// tick. Lifecycle sources can otherwise differ by one DateTime tick
        /// (100 ns) at a clock-tick boundary and generate different PID hashes
        /// for Clone, Execve, and rundown records describing one execution.
        /// </summary>
        internal static DateTime NormalizeStartTimeUtc(DateTime startTimeUtc)
        {
            return NormalizeStartTimeUtc(startTimeUtc, GetBootTimeUtc(), GetClockTicksPerSecond());
        }

        internal static DateTime NormalizeStartTimeUtc(
            DateTime startTimeUtc,
            DateTime bootTimeUtc,
            long clockTicksPerSecond)
        {
            DateTime utc = startTimeUtc.ToUniversalTime();
            DateTime bootUtc = bootTimeUtc.ToUniversalTime();
            if (clockTicksPerSecond <= 0 || utc < bootUtc)
            {
                return utc;
            }

            try
            {
                ulong elapsedDateTimeTicks = checked((ulong)(utc - bootUtc).Ticks);
                ulong clockTicks = checked(
                    (elapsedDateTimeTicks * (ulong)clockTicksPerSecond +
                     (ulong)TimeSpan.TicksPerSecond / 2UL) /
                    (ulong)TimeSpan.TicksPerSecond);
                long canonicalDateTimeTicks = checked((long)(
                    clockTicks * (ulong)TimeSpan.TicksPerSecond /
                    (ulong)clockTicksPerSecond));
                return bootUtc.AddTicks(canonicalDateTimeTicks);
            }
            catch
            {
                return utc;
            }
        }

        /// <summary>
        /// Enumerate live processes from /proc. Processes can exit while being read;
        /// those entries are skipped if their /proc directory disappears before basic
        /// metadata can be collected.
        /// </summary>
        public static IEnumerable<ProcessInfo> EnumerateProcesses()
        {
            foreach (string procDir in Directory.EnumerateDirectories("/proc"))
            {
                string name = Path.GetFileName(procDir);
                if (!uint.TryParse(name, out uint pid))
                {
                    continue;
                }

                ProcessInfo info = ReadProcessInfo(pid);
                if (info.Exists)
                {
                    yield return info;
                }
            }
        }

        /// <summary>
        /// Read file event context from /proc
        /// Used by OpenatSensor
        /// </summary>
        public static FileEventContext ReadFileEventContext(uint pid)
        {
            var context = new FileEventContext();

            try
            {
                var procDir = $"/proc/{pid}";

                // Read minimal info for file events
                var statusPath = $"{procDir}/status";
                if (File.Exists(statusPath))
                {
                    foreach (var line in File.ReadLines(statusPath))
                    {
                        if (line.StartsWith("PPid:"))
                        {
                            var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2 && int.TryParse(parts[1], out int ppid))
                                context.PPid = ppid;
                        }
                        else if (line.StartsWith("Uid:"))
                        {
                            var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2 && uint.TryParse(parts[1], out uint uid))
                                context.Uid = uid;
                        }
                        else if (line.StartsWith("Gid:"))
                        {
                            var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2 && uint.TryParse(parts[1], out uint gid))
                                context.Gid = gid;
                        }
                    }
                }

                // Read cmdline
                ReadCmdline(procDir, ref context);

                // Read username from environ
                var environPath = $"{procDir}/environ";
                if (File.Exists(environPath))
                {
                    var environBytes = File.ReadAllBytes(environPath);
                    ParseEnvironBytes(environBytes, ref context);
                }
            }
            catch
            {
                // Process may have exited
            }

            return context;
        }

        private static void ReadStatus(string procDir, ref ProcessInfo info)
        {
            var statusPath = $"{procDir}/status";
            if (!File.Exists(statusPath))
                return;

            foreach (var line in File.ReadLines(statusPath))
            {
                if (line.StartsWith("Name:"))
                {
                    var parts = line.Split(new[] { ':', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                        info.Name = parts[1].Trim();
                }
                else if (line.StartsWith("PPid:"))
                {
                    var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int ppid))
                        info.PPid = ppid;
                }
                else if (line.StartsWith("Uid:"))
                {
                    var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && uint.TryParse(parts[1], out uint uid))
                        info.Uid = uid;
                }
                else if (line.StartsWith("Gid:"))
                {
                    var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && uint.TryParse(parts[1], out uint gid))
                        info.Gid = gid;
                }
                else if (line.StartsWith("NSpid:"))
                {
                    var parts = line.Split(new[] { ':', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int sid))
                        info.SessionId = sid;
                }
            }
        }

        private static void ReadStat(string procDir, ref ProcessInfo info)
        {
            var statPath = $"{procDir}/stat";
            if (!File.Exists(statPath))
                return;

            string stat = File.ReadAllText(statPath);
            int closeParen = stat.LastIndexOf(')');
            if (closeParen < 0 || closeParen + 2 >= stat.Length)
                return;

            string[] fieldsAfterComm = stat.Substring(closeParen + 2).Split(' ', StringSplitOptions.RemoveEmptyEntries);

            // /proc/<pid>/stat field 22 is starttime. fieldsAfterComm[0] is field 3 (state),
            // so starttime is index 19.
            if (fieldsAfterComm.Length > 19 && ulong.TryParse(fieldsAfterComm[19], out ulong startTicks))
            {
                DateTime bootTimeUtc = GetBootTimeUtc();
                long ticksPerSecond = GetClockTicksPerSecond();
                info.StartTimeUtc = NormalizeStartTimeUtc(
                    bootTimeUtc.AddTicks(
                        checked((long)(startTicks * (ulong)TimeSpan.TicksPerSecond / (ulong)ticksPerSecond))),
                    bootTimeUtc,
                    ticksPerSecond);
            }
        }

        private static void ReadCmdline(string procDir, ref ProcessInfo info)
        {
            var cmdlinePath = $"{procDir}/cmdline";
            if (!File.Exists(cmdlinePath))
                return;

            var cmdlineBytes = File.ReadAllBytes(cmdlinePath);
            var args = new List<string>();
            int start = 0;

            for (int i = 0; i < cmdlineBytes.Length; i++)
            {
                if (cmdlineBytes[i] == 0)
                {
                    if (i > start)
                    {
                        args.Add(Encoding.UTF8.GetString(cmdlineBytes, start, i - start));
                    }
                    start = i + 1;
                }
            }

            info.CommandLine = string.Join(" ", args);
        }

        private static void ReadCmdline(string procDir, ref FileEventContext context)
        {
            var cmdlinePath = $"{procDir}/cmdline";
            if (!File.Exists(cmdlinePath))
                return;

            var cmdlineBytes = File.ReadAllBytes(cmdlinePath);
            var args = new List<string>();
            int start = 0;

            for (int i = 0; i < cmdlineBytes.Length; i++)
            {
                if (cmdlineBytes[i] == 0)
                {
                    if (i > start)
                    {
                        args.Add(Encoding.UTF8.GetString(cmdlineBytes, start, i - start));
                    }
                    start = i + 1;
                }
            }

            context.CommandLine = string.Join(" ", args);
        }

        private static void ReadEnviron(string procDir, ref ProcessInfo info)
        {
            var environPath = $"{procDir}/environ";
            if (!File.Exists(environPath))
                return;

            var environBytes = File.ReadAllBytes(environPath);
            ParseEnvironBytes(environBytes, ref info);
        }

        private static void ParseEnvironBytes(byte[] environBytes, ref ProcessInfo info)
        {
            int start = 0;
            for (int i = 0; i < environBytes.Length; i++)
            {
                if (environBytes[i] == 0)
                {
                    if (i > start)
                    {
                        var envVar = Encoding.UTF8.GetString(environBytes, start, i - start);
                        if (envVar.StartsWith("USER="))
                            info.Username = envVar.Substring(5);
                        else if (envVar.StartsWith("HOME="))
                            info.Home = envVar.Substring(5);
                        else if (envVar.StartsWith("SHELL="))
                            info.Shell = envVar.Substring(6);
                    }
                    start = i + 1;
                }
            }
        }

        private static void ParseEnvironBytes(byte[] environBytes, ref FileEventContext context)
        {
            int start = 0;
            for (int i = 0; i < environBytes.Length; i++)
            {
                if (environBytes[i] == 0)
                {
                    if (i > start)
                    {
                        var envVar = Encoding.UTF8.GetString(environBytes, start, i - start);
                        if (envVar.StartsWith("USER="))
                            context.Username = envVar.Substring(5);
                    }
                    start = i + 1;
                }
            }
        }

        private static void ReadCwd(string procDir, ref ProcessInfo info)
        {
            var cwdPath = $"{procDir}/cwd";
            try
            {
                var fileInfo = new FileInfo(cwdPath);
                if (fileInfo.Exists)
                {
                    info.Cwd = fileInfo.LinkTarget ?? fileInfo.FullName;
                }
            }
            catch
            {
                // Permission denied or not a symlink
            }
        }

        private static void ReadExe(string procDir, ref ProcessInfo info)
        {
            var exePath = $"{procDir}/exe";
            try
            {
                var fileInfo = new FileInfo(exePath);
                if (fileInfo.Exists)
                {
                    info.ExecutablePath = fileInfo.LinkTarget ?? fileInfo.FullName;
                }
            }
            catch
            {
                // Permission denied or not a symlink
                info.ExecutablePath = null;
            }
        }

        private static DateTime GetBootTimeUtc()
        {
            if (cachedBootTimeUtc.HasValue)
            {
                return cachedBootTimeUtc.Value;
            }

            foreach (string line in File.ReadLines("/proc/stat"))
            {
                if (line.StartsWith("btime "))
                {
                    string value = line.Substring("btime ".Length).Trim();
                    if (long.TryParse(value, out long bootUnixSeconds))
                    {
                        cachedBootTimeUtc = DateTimeOffset.FromUnixTimeSeconds(bootUnixSeconds).UtcDateTime;
                        return cachedBootTimeUtc.Value;
                    }
                }
            }

            cachedBootTimeUtc = DateTime.UtcNow;
            return cachedBootTimeUtc.Value;
        }

        private static long GetClockTicksPerSecond()
        {
            if (cachedClockTicksPerSecond.HasValue)
            {
                return cachedClockTicksPerSecond.Value;
            }

            long ticks = sysconf(_SC_CLK_TCK);
            cachedClockTicksPerSecond = ticks > 0 ? ticks : 100;
            return cachedClockTicksPerSecond.Value;
        }

        private static string LookupUsername(uint uid)
        {
            lock (passwdLock)
            {
                if (passwdUserLookup == null)
                {
                    passwdUserLookup = new Dictionary<uint, string>();
                    if (File.Exists("/etc/passwd"))
                    {
                        foreach (string line in File.ReadLines("/etc/passwd"))
                        {
                            string[] parts = line.Split(':');
                            if (parts.Length > 2 && uint.TryParse(parts[2], out uint passwdUid))
                            {
                                passwdUserLookup[passwdUid] = parts[0];
                            }
                        }
                    }
                }

                return passwdUserLookup.TryGetValue(uid, out string userName) ? userName : uid.ToString();
            }
        }

        [DllImport("libc")]
        private static extern long sysconf(int name);

        public struct ProcessInfo
        {
            public bool Exists;
            public uint Pid;
            public int PPid;
            public int SessionId;
            public uint Uid;
            public uint Gid;
            public string Name;
            public DateTime StartTimeUtc;
            public string CommandLine;
            public string Username;
            public string Home;
            public string Shell;
            public string Cwd;
            public string ExecutablePath;
        }

        public struct FileEventContext
        {
            public int PPid;
            public uint Uid;
            public uint Gid;
            public string CommandLine;
            public string Username;
        }
    }
}
