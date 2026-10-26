/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.collect.models;
using System;
using System.Collections.Generic;

namespace gov.llnl.wintap.core.infrastructure
{
    /// <summary>
    /// Internal interface for platform-specific process resolution and PID hash management.
    /// Not exposed to plugins - internal Wintap infrastructure only.
    /// </summary>
    public interface IProcessResolver
    {
        /// <summary>
        /// Resolve process information at a specific point in time (handles PID reuse)
        /// </summary>
        ProcessRecord ResolveProcessAtTime(int pid, DateTime eventTime);

        /// <summary>
        /// Resolve only process identity, using bounded event-time-valid history
        /// for exited process instances before consulting durable storage.
        /// </summary>
        ProcessRecord ResolveProcessIdentityAtTime(int pid, DateTime eventTime);

        /// <summary>
        /// Resolve the currently active process for a PID from the in-memory cache.
        /// Returns false when the PID is not active or the event predates the cached process start.
        /// </summary>
        bool TryResolveCurrentProcessAtTime(int pid, DateTime eventTime, out ProcessRecord process);

        // Optional experimental Linux recovery. Other resolvers remain unsupported.
        bool RetainExitIdentityEvidence(WintapMessage stop, DateTime kernelStartUtc) => false;
        bool TryResolveExitIdentityEvidence(int pid, DateTime eventTime, out ProcessRecord evidence)
        {
            evidence = null;
            return false;
        }

        // Narrow fallback for Windows BAM writes emitted immediately after ProcessStop.
        ProcessRecord ResolveRegistryTeardownProcess(int pid, DateTime eventTime);

        void TakeHistoricalIdentityCacheCounters(out long hits, out long misses, out long evictions, out int entries);

        void RegisterProcess(WintapMessage processEvent);

        /// <summary>
        /// Check if a process exists for the given PID at the specified time
        /// </summary>
        bool ProcessExistsForPid(int pid, long eventTime);

        bool IsProcessRowOpen(string pidHash);

        void UpdateCollectionHeartbeat();

        bool TryReadCollectionHeartbeat(out DateTime lastWriteUtc, out string sessionId);

        int ReconcileStartupOpenRows(IReadOnlyCollection<string> livePidHashes, DateTime gapEndUtc);

        bool TryRepairParentLinkage(string pidHash, int parentPid, string parentPidHash);

        void WriteCollectionGap(DateTime gapStartUtc, DateTime gapEndUtc, string priorSessionId, string reason);

        /// <summary>
        /// Generate a PID hash for the given process ID and creation time
        /// </summary>
        string GetPidHash(int pid, DateTime createTime);

        List<ProcessRecord> GetAllProcesses();

        void ClearDB();
    }
}
