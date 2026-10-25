/*
 * Copyright (c) 2026, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace gov.llnl.wintap.core.shared
{
    // The ONLY process-identity formula. Also source-linked into WintapCoreSvcMgr.
    internal static class ProcessIdentity
    {
        internal const string Version = "pid-v2";
        internal const string MainStoreFileName = "main.pid-v2.duckdb";
        internal const string RecoveryStoreFileName = "recovery.pid-v2.duckdb";

        internal static string NormalizeHostname(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname))
                throw new ArgumentException("Process identity requires a hostname.", nameof(hostname));
            return hostname.Trim().ToUpperInvariant();
        }

        internal static string Compute(string hostname, int pid, long processStartFileTimeUtc)
        {
            // Fixed namespace/type markers are not instance inputs. Keep the existing
            // two-stage MD5 representation, but remove agent UUID and normalize once.
            string attributes = "Process_ID`llnl`" +
                processStartFileTimeUtc.ToString(CultureInfo.InvariantCulture) + "`" +
                NormalizeHostname(hostname) + "`" + pid.ToString(CultureInfo.InvariantCulture) + "`";
            string attributeHash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(attributes)));
            return Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes("N`Process`" + attributeHash + "`")));
        }
    }
}
