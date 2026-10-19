using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace gov.llnl.wintap.platform.windows.infrastructure
{
    // Immutable after construction; conflicting alias observations are deliberately omitted.
    internal sealed class WindowsFileVolumeMap
    {
        internal sealed record Entry(string Alias, string Device, string[] Mounts);
        private readonly Entry[] entries;
        internal static readonly WindowsFileVolumeMap Empty = new WindowsFileVolumeMap(Array.Empty<Entry>());
        internal int Count => entries.Length;
        internal int UnresolvedEntries { get; }
        internal WindowsFileVolumeMap(IEnumerable<Entry> observations, int unresolvedEntries = 0)
        {
            UnresolvedEntries = unresolvedEntries;
            Entry[] supplied = observations.ToArray();
            var ambiguousMounts = new HashSet<string>(supplied.SelectMany(e => e.Mounts.Select(m => (Mount: m.TrimEnd('\\'), e.Device)))
                .GroupBy(x => x.Mount, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Select(x => x.Device).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
                .Select(g => g.Key), StringComparer.OrdinalIgnoreCase);
            entries = supplied.GroupBy(e => e.Alias, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Select(e => e.Device).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1)
                .Select(g => new Entry(g.Key, g.First().Device,
                    g.SelectMany(e => e.Mounts).Where(m => WindowsFilePathNormalizer.IsDrivePath(m) && !ambiguousMounts.Contains(m.TrimEnd('\\')))
                     .Distinct(StringComparer.OrdinalIgnoreCase).ToArray())).ToArray();
        }
        internal string Render(string path)
        {
            var match = entries.SelectMany(e => new[] { (Root: e.Alias, Entry: e), (Root: e.Device, Entry: e) })
                .Where(x => WindowsFilePathNormalizer.HasRoot(path, x.Root))
                .OrderByDescending(x => x.Root.Length).FirstOrDefault();
            if (match.Entry == null) return path;
            string suffix = path.Substring(match.Root.TrimEnd('\\').Length);
            string native = Join(match.Entry.Device, suffix);
            return entries.Where(e => string.Equals(e.Device, match.Entry.Device, StringComparison.OrdinalIgnoreCase))
                .SelectMany(e => e.Mounts).Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(m => WindowsFilePathNormalizer.SafeOrdinary(Join(m, suffix)))
                .OrderBy(m => m.Length == 3 ? 0 : 1).ThenBy(m => m.Length)
                .ThenBy(m => m, StringComparer.OrdinalIgnoreCase)
                .Select(m => Join(m, suffix)).FirstOrDefault() ?? native;
        }
        internal static string Join(string root, string suffix) => root.TrimEnd('\\') + (suffix.Length == 0 ? (WindowsFilePathNormalizer.IsDrivePath(root) && root.Length == 3 ? "\\" : "") : (suffix[0] == '\\' ? suffix : "\\" + suffix));

        // Buffer-level seams exercise the same MULTI_SZ parsing and resizing as native discovery.
        internal interface INative
        {
            IntPtr First(char[] buffer, out int error);
            bool Next(IntPtr handle, char[] buffer, out int error);
            void Close(IntPtr handle);
            int Query(string alias, char[] buffer, out int error);
            bool Mounts(string volume, char[] buffer, out int required, out int error);
        }
        internal static string[] MultiString(char[] buffer, int length) => new string(buffer, 0, length).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        private const int Ceiling = 65536;
        internal static WindowsFileVolumeMap Discover(INative api = null)
        {
            api ??= new Native();
            var result = new List<Entry>();
            int unresolved = 0;
            IntPtr handle = new IntPtr(-1);
            try
            {
                char[] buffer = new char[Ceiling];
                handle = api.First(buffer, out int error);
                if (handle == new IntPtr(-1)) return Empty;
                do
                {
                    string volume = new string(buffer).Split('\0')[0];
                    try
                    {
                        if (volume.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) && volume.EndsWith(@"\"))
                        {
                            string device = QueryCurrent(api, volume.Substring(4).TrimEnd('\\'));
                            if (IsNativeDevice(device))
                            {
                                string[] mounts = ReadMounts(api, volume);
                                if (mounts.Length == 0) unresolved++;
                                result.Add(new Entry(volume.TrimEnd('\\'), device, mounts));
                                result.Add(new Entry(@"\??\" + volume.Substring(4).TrimEnd('\\'), device, mounts));
                            }
                        }
                    }
                    catch { unresolved++; /* Preserve other established entries. */ }
                    Array.Clear(buffer, 0, buffer.Length);
                    if (api.Next(handle, buffer, out error)) continue;
                    if (error != 18) return Empty; // ERROR_NO_MORE_FILES is the only successful termination.
                    break;
                } while (true);
                for (char drive = 'A'; drive <= 'Z'; drive++)
                {
                    try
                    {
                        string device = QueryCurrent(api, drive + ":");
                        if (IsNativeDevice(device) && !device.StartsWith(@"\Device\Mup", StringComparison.OrdinalIgnoreCase)
                            && !device.StartsWith(@"\Device\LanmanRedirector", StringComparison.OrdinalIgnoreCase)
                            && !device.StartsWith(@"\Device\Rdbss", StringComparison.OrdinalIgnoreCase))
                            result.Add(new Entry(drive + ":", device, new[] { drive + @":\" }));
                    }
                    catch { unresolved++; }
                }
                return new WindowsFileVolumeMap(result, unresolved);
            }
            catch { return Empty; }
            finally { if (handle != new IntPtr(-1)) api.Close(handle); }
        }
        private static bool IsNativeDevice(string value) => value != null && value.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase);
        private static string QueryCurrent(INative api, string alias)
        {
            for (int size = 256; size <= Ceiling; size *= 2)
            {
                var buffer = new char[size];
                int count = api.Query(alias, buffer, out int error);
                if (count > 0 && count <= size && buffer[count - 1] == '\0') return MultiString(buffer, count).FirstOrDefault();
                if (error != 122) break;
            }
            return null;
        }
        private static string[] ReadMounts(INative api, string volume)
        {
            int size = 256;
            while (size <= Ceiling)
            {
                var buffer = new char[size];
                if (api.Mounts(volume, buffer, out int required, out int error))
                    return required > 0 && required <= size && buffer[required - 1] == '\0' ? MultiString(buffer, required) : Array.Empty<string>();
                if (error != 234 && error != 122) break;
                size = Math.Max(size * 2, required);
            }
            return Array.Empty<string>();
        }
        private sealed class Native : INative
        {
            public IntPtr First(char[] b, out int e) { var h = FindFirstVolumeW(b, (uint)b.Length); e = Marshal.GetLastWin32Error(); return h; }
            public bool Next(IntPtr h, char[] b, out int e) { bool ok = FindNextVolumeW(h, b, (uint)b.Length); e = Marshal.GetLastWin32Error(); return ok; }
            public void Close(IntPtr h) { FindVolumeClose(h); }
            public int Query(string a, char[] b, out int e) { int n = (int)QueryDosDeviceW(a, b, (uint)b.Length); e = Marshal.GetLastWin32Error(); return n; }
            public bool Mounts(string v, char[] b, out int n, out int e) { bool ok = GetVolumePathNamesForVolumeNameW(v, b, (uint)b.Length, out uint needed); n = (int)needed; e = Marshal.GetLastWin32Error(); return ok; }
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr FindFirstVolumeW([Out] char[] b, uint n);
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool FindNextVolumeW(IntPtr h, [Out] char[] b, uint n);
            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FindVolumeClose(IntPtr h);
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint QueryDosDeviceW(string a, [Out] char[] b, uint n);
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool GetVolumePathNamesForVolumeNameW(string v, [Out] char[] b, uint n, out uint needed);
        }
    }
}
