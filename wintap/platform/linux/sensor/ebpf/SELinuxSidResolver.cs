using System;
using System.Collections.Concurrent;
using System.IO;

namespace gov.llnl.wintap.platform.linux.collect
{
    internal sealed class SELinuxSidResolver
    {
        private readonly ConcurrentDictionary<uint, string> _sidToContext = new ConcurrentDictionary<uint, string>();

        public int LearnedCount => _sidToContext.Count;

        public void Learn(uint sid, string context)
        {
            if (sid == 0 || string.IsNullOrWhiteSpace(context))
            {
                return;
            }

            _sidToContext[sid] = CleanContext(context);
        }

        public string ResolveSource(uint sid, int pid, out bool hit)
        {
            if (sid != 0 && _sidToContext.TryGetValue(sid, out string cached))
            {
                hit = true;
                return cached;
            }

            string procContext = ReadProcContext(pid);
            if (!string.IsNullOrWhiteSpace(procContext))
            {
                Learn(sid, procContext);
                hit = true;
                return procContext;
            }

            hit = false;
            return string.Empty;
        }

        public string ResolveKnown(uint sid, out bool hit)
        {
            if (sid != 0 && _sidToContext.TryGetValue(sid, out string cached))
            {
                hit = true;
                return cached;
            }

            hit = false;
            return string.Empty;
        }

        public void Clear()
        {
            _sidToContext.Clear();
        }

        private static string ReadProcContext(int pid)
        {
            if (pid <= 0)
            {
                return string.Empty;
            }

            try
            {
                return CleanContext(File.ReadAllText($"/proc/{pid}/attr/current"));
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string CleanContext(string context)
        {
            return string.IsNullOrEmpty(context)
                ? string.Empty
                : context.TrimEnd('\0', '\r', '\n', ' ', '\t');
        }
    }
}
