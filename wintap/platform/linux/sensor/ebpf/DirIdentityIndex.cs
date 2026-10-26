using System;
using System.Collections.Generic;
using System.Threading;

namespace gov.llnl.wintap.platform.linux.collect
{
    /// <summary>
    /// fop-13c/fop-13d: the global directory-identity index behind
    /// race-free relative-open resolution.
    ///
    /// Keyed by (mnt_ns, s_dev, i_ino) — namespace-qualified so bind-mount /
    /// container path aliases in another mount namespace can never satisfy a
    /// lookup from this one (fop-13c; mnt_ns 0 groups records from senders
    /// that cannot read it, e.g. the fallback tracer tier).
    ///
    /// Eviction is touch-on-hit LRU (fop-13d): filesystem walks that flood
    /// the index with one-shot directory identities age out ahead of the
    /// hot, long-lived base directories that steady-state relative opens
    /// keep touching. (The original FIFO shortcut evicted hot entries during
    /// scans, observed in the field as dir_index_miss ≈ total miss with
    /// 133k+ evictions/interval at a pinned cap.)
    ///
    /// Thread model: all mutations happen on the sensor's poller thread;
    /// Count is read from logging paths on other threads. A single lock
    /// keeps it safe either way — contention is negligible at directory-open
    /// rates.
    /// </summary>
    internal sealed class DirIdentityIndex
    {
        private readonly Dictionary<(uint Ns, uint Dev, ulong Ino), LinkedListNode<(uint Ns, uint Dev, ulong Ino, string Path)>> _map;
        private readonly LinkedList<(uint Ns, uint Dev, ulong Ino, string Path)> _lru;
        private readonly object _gate = new object();
        private readonly int _maxEntries;
        private long _evictions;

        public DirIdentityIndex(int maxEntries)
        {
            _maxEntries = maxEntries > 0 ? maxEntries : 65536;
            _map = new Dictionary<(uint, uint, ulong), LinkedListNode<(uint, uint, ulong, string)>>();
            _lru = new LinkedList<(uint, uint, ulong, string)>();
        }

        public int Count
        {
            get
            {
                lock (_gate)
                {
                    return _map.Count;
                }
            }
        }

        public long TakeEvictions() => Interlocked.Exchange(ref _evictions, 0);

        /// <summary>
        /// Join unlink intent to its captured base, including after producer exit
        /// or dirfd reuse. A missing/evicted base (including the fallback tracer's
        /// zero identity) stays relative. Never consult a later process cwd/fd.
        /// Learned directory aliases/renames remain an index limitation.
        /// </summary>
        public string ResolveUnlinkPath(uint ns, uint dev, ulong ino, string rawPath)
        {
            if (string.IsNullOrEmpty(rawPath) || rawPath[0] == '/') return rawPath;
            if (ns == 0 || ino == 0 || Array.IndexOf(rawPath.Split('/'), "..") >= 0)
                return rawPath; // Lexical parent reduction would misresolve symlinks.
            if (!TryGet(ns, dev, ino, out string directory) ||
                string.IsNullOrEmpty(directory) || directory[0] != '/') return rawPath;
            return directory.TrimEnd('/') + "/" + rawPath;
        }

        /// <summary>Lookup; a hit refreshes the entry's LRU position.</summary>
        public bool TryGet(uint ns, uint dev, ulong ino, out string path)
        {
            lock (_gate)
            {
                if (_map.TryGetValue((ns, dev, ino), out var node))
                {
                    _lru.Remove(node);
                    _lru.AddFirst(node);
                    path = node.Value.Path;
                    return true;
                }
            }

            path = null;
            return false;
        }

        /// <summary>Insert or update; either refreshes the LRU position.</summary>
        public void Put(uint ns, uint dev, ulong ino, string absolutePath)
        {
            lock (_gate)
            {
                var key = (ns, dev, ino);
                if (_map.TryGetValue(key, out var node))
                {
                    _lru.Remove(node);
                    node.Value = (ns, dev, ino, absolutePath);
                    _lru.AddFirst(node);
                    return;
                }

                var added = new LinkedListNode<(uint, uint, ulong, string)>((ns, dev, ino, absolutePath));
                _lru.AddFirst(added);
                _map[key] = added;

                while (_map.Count > _maxEntries)
                {
                    var oldest = _lru.Last;
                    if (oldest == null)
                    {
                        break;
                    }

                    _lru.RemoveLast();
                    _map.Remove((oldest.Value.Ns, oldest.Value.Dev, oldest.Value.Ino));
                    Interlocked.Increment(ref _evictions);
                }
            }
        }
    }
}
