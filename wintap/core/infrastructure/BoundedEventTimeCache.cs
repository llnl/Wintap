using System;
using System.Collections.Generic;

namespace gov.llnl.wintap.core.infrastructure
{
    internal sealed class BoundedEventTimeCache<T>
    {
        private sealed class Entry
        {
            internal int Key;
            internal string Identity = string.Empty;
            internal DateTime ValidFromUtc;
            internal DateTime ValidThroughUtc;
            internal T Value = default!;
        }

        private readonly int capacity;
        private readonly object gate = new object();
        private readonly Dictionary<int, List<LinkedListNode<Entry>>> entriesByKey = new Dictionary<int, List<LinkedListNode<Entry>>>();
        private readonly LinkedList<Entry> lru = new LinkedList<Entry>();
        private long hits;
        private long misses;
        private long evictions;

        internal BoundedEventTimeCache(int capacity)
        {
            this.capacity = Math.Max(0, capacity);
        }

        internal bool TryGet(int key, DateTime eventTime, out T value)
        {
            return TryGet(key, eventTime, true, out value);
        }

        internal bool TryGetWithoutCounting(int key, DateTime eventTime, out T value)
        {
            return TryGet(key, eventTime, false, out value);
        }

        private bool TryGet(int key, DateTime eventTime, bool countAttempt, out T value)
        {
            value = default!;
            if (capacity == 0)
            {
                if (countAttempt)
                {
                    lock (gate)
                    {
                        misses++;
                    }
                }
                return false;
            }

            DateTime eventTimeUtc = AsUtc(eventTime);
            lock (gate)
            {
                if (entriesByKey.TryGetValue(key, out var candidates))
                {
                    LinkedListNode<Entry>? newestMatch = null;
                    for (int i = 0; i < candidates.Count; i++)
                    {
                        LinkedListNode<Entry> node = candidates[i];
                        Entry entry = node.Value;
                        if (entry.ValidFromUtc <= eventTimeUtc &&
                            entry.ValidThroughUtc >= eventTimeUtc &&
                            (newestMatch == null || entry.ValidFromUtc > newestMatch.Value.ValidFromUtc))
                        {
                            newestMatch = node;
                        }
                    }

                    if (newestMatch != null)
                    {
                        lru.Remove(newestMatch);
                        lru.AddLast(newestMatch);
                        if (countAttempt)
                        {
                            hits++;
                        }
                        value = newestMatch.Value.Value;
                        return true;
                    }
                }

                if (countAttempt)
                {
                    misses++;
                }
                return false;
            }
        }

        internal void Set(int key, string identity, DateTime validFrom, DateTime validThrough, T value)
        {
            if (capacity == 0 || string.IsNullOrWhiteSpace(identity))
            {
                return;
            }

            DateTime validFromUtc = AsUtc(validFrom);
            DateTime validThroughUtc = AsUtc(validThrough);
            if (validThroughUtc < validFromUtc)
            {
                return;
            }

            lock (gate)
            {
                if (entriesByKey.TryGetValue(key, out var candidates))
                {
                    for (int i = 0; i < candidates.Count; i++)
                    {
                        LinkedListNode<Entry> existing = candidates[i];
                        if (string.Equals(existing.Value.Identity, identity, StringComparison.Ordinal))
                        {
                            existing.Value.ValidFromUtc = validFromUtc;
                            existing.Value.ValidThroughUtc = validThroughUtc;
                            existing.Value.Value = value;
                            lru.Remove(existing);
                            lru.AddLast(existing);
                            return;
                        }
                    }
                }

                while (lru.Count >= capacity)
                {
                    EvictOldest();
                }

                // Eviction may have removed this PID's last entry and its index key.
                if (!entriesByKey.TryGetValue(key, out candidates))
                {
                    candidates = new List<LinkedListNode<Entry>>();
                    entriesByKey[key] = candidates;
                }

                var entry = new Entry
                {
                    Key = key,
                    Identity = identity,
                    ValidFromUtc = validFromUtc,
                    ValidThroughUtc = validThroughUtc,
                    Value = value
                };
                LinkedListNode<Entry> node = lru.AddLast(entry);
                candidates.Add(node);
            }
        }

        internal void TakeCounters(out long hitCount, out long missCount, out long evictionCount, out int entryCount)
        {
            lock (gate)
            {
                hitCount = hits;
                missCount = misses;
                evictionCount = evictions;
                entryCount = lru.Count;
                hits = 0;
                misses = 0;
                evictions = 0;
            }
        }

        internal void Clear()
        {
            lock (gate)
            {
                entriesByKey.Clear();
                lru.Clear();
                hits = 0;
                misses = 0;
                evictions = 0;
            }
        }

        internal void Remove(int key, string identity)
        {
            lock (gate)
            {
                if (!entriesByKey.TryGetValue(key, out var candidates)) return;
                for (int i = candidates.Count - 1; i >= 0; i--)
                {
                    var node = candidates[i];
                    if (!string.Equals(node.Value.Identity, identity, StringComparison.Ordinal)) continue;
                    lru.Remove(node);
                    candidates.RemoveAt(i);
                }
                if (candidates.Count == 0) entriesByKey.Remove(key);
            }
        }

        private void EvictOldest()
        {
            LinkedListNode<Entry>? oldest = lru.First;
            if (oldest == null)
            {
                return;
            }

            lru.RemoveFirst();
            if (entriesByKey.TryGetValue(oldest.Value.Key, out var candidates))
            {
                candidates.Remove(oldest);
                if (candidates.Count == 0)
                {
                    entriesByKey.Remove(oldest.Value.Key);
                }
            }
            evictions++;
        }

        private static DateTime AsUtc(DateTime value)
        {
            return value.Kind == DateTimeKind.Local
                ? value.ToUniversalTime()
                : DateTime.SpecifyKind(value, DateTimeKind.Utc);
        }
    }
}
