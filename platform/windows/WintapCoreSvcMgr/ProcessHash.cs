/*
 * Copyright (c) 2023, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using System;
using System.Collections.Generic;
using System.Linq;

namespace gov.llnl.wintap.platform.windows.collect.etw.helpers
{
    internal class ProcessHash
    {
        internal string GenPidHash(int pid, long processStartFileTimeUtc)
        {
            return ProcessIdentity.Compute(Environment.MachineName, pid, processStartFileTimeUtc);
        }

        /// <summary>
        /// Caching class for MD5/Sha2 to prevent IO thrashing on hash retrieval
        ///   adjust maxHashAgeMinutes to balance performance with accuracy.
        /// </summary>
        internal class Hasher
        {
            private int maxHashAgeMinutes = 5;
            private System.Timers.Timer hashExpiry;
            // path-to-hash
            private Dictionary<string, string> md5Lookup = new Dictionary<string, string>();
            private Dictionary<string, string> sha2Lookup = new Dictionary<string, string>();
            // ageOfHash-to-path
            private Dictionary<DateTime, string> hashAge = new Dictionary<DateTime, string>();
            private int MAX_DICT_SIZE = 1000;

            public Hasher()
            {
                hashExpiry = new System.Timers.Timer();
                hashExpiry.Interval = 1000;
                hashExpiry.Elapsed += HashExpiry_Elapsed;
                hashExpiry.AutoReset = true;
                hashExpiry.Start();
            }

            private void HashExpiry_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
            {
                foreach (var keypair in hashAge.Where(a => a.Key < DateTime.Now.Subtract(new TimeSpan(0, maxHashAgeMinutes, 0))))
                {
                    md5Lookup.Remove(keypair.Value);
                }
                List<DateTime> keysToRemove = new List<DateTime>();

                foreach (var key in hashAge.Keys)
                {
                    if (key < DateTime.Now.Subtract(new TimeSpan(0, 5, 0)))
                    {
                        keysToRemove.Add(key);
                    }
                }

                foreach (DateTime key in keysToRemove)
                {
                    hashAge.Remove(key);
                }
                if (md5Lookup.Count >= MAX_DICT_SIZE)
                {
                    WintapLogger.Log.Append($"WARN Process Hasher: Max size reached on md5Lookup dictionary.  Current size: {md5Lookup.Count}, max size: {MAX_DICT_SIZE}.  clearing dictionary...", LogLevel.Always);
                    md5Lookup = new Dictionary<string, string>();
                    WintapLogger.Log.Append($"Process Hasher: md5Lookup dictionary.  Current size: {md5Lookup.Count}, max size: {MAX_DICT_SIZE}.", LogLevel.Always);
                }
                if (hashAge.Count >= MAX_DICT_SIZE)
                {
                    WintapLogger.Log.Append($"WARN Process Hasher: Max size reached on hashAge dictionary.  Current size: {hashAge.Count}, max size: {MAX_DICT_SIZE}.  clearing dictionary...", LogLevel.Always);
                    hashAge = new Dictionary<DateTime, string>();
                    WintapLogger.Log.Append($"Process Hasher: md5Lookup dictionary.  Current size: {hashAge.Count}, max size: {MAX_DICT_SIZE}.", LogLevel.Always);
                }
            }
        }
    }
}
