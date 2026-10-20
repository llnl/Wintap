using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace gov.llnl.wintap.platform.windows.infrastructure
{
    internal sealed class WindowsFilePathNormalizer
    {
        private sealed record Lease(WindowsFileVolumeMap Map, double Started);
        private Lease lease;
        private readonly Func<WindowsFileVolumeMap> discover;
        private readonly Func<double> clock;
        private readonly Action<Action> schedule;
        private readonly Action<string> summary;
        private int inFlight;
        private double lastAttempt = double.NegativeInfinity;
        internal WindowsFilePathNormalizer(Func<WindowsFileVolumeMap> discover, Func<double> clock = null,
            Action<Action> schedule = null, Action<string> summary = null)
        {
            this.discover = discover;
            this.clock = clock ?? (() => (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency);
            this.schedule = schedule ?? (work => ThreadPool.QueueUserWorkItem(_ => work()));
            this.summary = summary ?? (_ => { });
        }
        internal void Initialize() { if (Admit(out double started)) Refresh(started); }
        private bool Admit(out double started)
        {
            started = clock();
            if (Interlocked.CompareExchange(ref inFlight, 1, 0) != 0) return false;
            if (started - Volatile.Read(ref lastAttempt) < 60) { Volatile.Write(ref inFlight, 0); return false; }
            Volatile.Write(ref lastAttempt, started);
            return true;
        }
        private void Refresh(double started)
        {
            string failure = "";
            var map = WindowsFileVolumeMap.Empty;
            try { map = discover() ?? WindowsFileVolumeMap.Empty; if (map.Count == 0) failure = "empty/unavailable"; }
            catch (Exception ex) { failure = ex.GetType().Name; }
            try
            {
                // The lease starts before discovery, so slow work cannot revive an old map.
                if (clock() - started < 60) Volatile.Write(ref lease, new Lease(map, started));
                try { summary($"FILE volume discovery: {map.Count} mappings; {map.UnresolvedEntries} unresolved mount entries; {failure}"); } catch { }
            }
            finally { Volatile.Write(ref inFlight, 0); }
        }
        internal string Normalize(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            Lease current = Volatile.Read(ref lease);
            bool fresh = current != null && clock() - current.Started < 60;
            if (!fresh && Admit(out double started))
            {
                try { schedule(() => Refresh(started)); }
                catch { Volatile.Write(ref inFlight, 0); }
            }
            return Normalize(path, fresh ? current.Map : WindowsFileVolumeMap.Empty);
        }
        internal static bool IsDrivePath(string p) => p != null && p.Length >= 3 &&
            ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && p[2] == '\\';
        internal static bool HasRoot(string p, string root)
        {
            root = root.TrimEnd('\\');
            return p.StartsWith(root, StringComparison.OrdinalIgnoreCase) && (p.Length == root.Length || p[root.Length] == '\\');
        }
        private static bool PlainUnc(string p)
        {
            if (!p.StartsWith(@"\\")) return false;
            string[] parts = p.Substring(2).Split('\\');
            return parts.Length >= 2 && parts[0].Length > 0 && parts[1].Length > 0 &&
                !parts[0].Contains(';') && !parts[1].Contains(';');
        }
        internal static bool SafeOrdinary(string path)
        {
            string rest = IsDrivePath(path) ? path.Substring(3) : path.StartsWith(@"\\") ? path.Substring(2) : path;
            foreach (string component in rest.Split('\\'))
            {
                if (component.Length == 0) continue;
                string name = component.Split(':')[0];
                if (component.EndsWith(" ") || component.EndsWith(".") || component.Contains('/') || name == "." || name == ".." || name.EndsWith(" ") || name.EndsWith(".")) return false;
                string stem = name.Split('.')[0].ToUpperInvariant();
                if (new[] { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" }.Contains(stem)) return false;
                if (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && "123456789\u00b9\u00b2\u00b3".Contains(stem[3])) return false;
            }
            return true;
        }
        internal static string Normalize(string path, WindowsFileVolumeMap map)
        {
            if (string.IsNullOrEmpty(path)) return path;
            string chosen = path;
            if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            {
                string tail = path.Substring(4);
                if (tail.StartsWith(@"GLOBALROOT\Device\", StringComparison.OrdinalIgnoreCase)) chosen = map.Render(@"\" + tail.Substring(11));
                else if (IsDrivePath(tail) && SafeOrdinary(tail)) chosen = tail;
                else if (tail.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    string unc = @"\\" + tail.Substring(4);
                    if (PlainUnc(unc) && SafeOrdinary(unc)) chosen = unc;
                }
                else if (tail.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase)) chosen = map.Render(path);
            }
            else if (path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                chosen = map.Render(path);
                foreach (string prefix in new[] { @"\Device\Mup\", @"\Device\LanmanRedirector\" })
                    if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        string unc = @"\\" + path.Substring(prefix.Length);
                        if (PlainUnc(unc) && SafeOrdinary(unc)) chosen = unc;
                    }
            }
            return chosen.ToLowerInvariant();
        }
    }
}
