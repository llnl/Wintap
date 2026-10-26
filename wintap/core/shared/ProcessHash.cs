/*
 * Copyright (c) 2023, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using System.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.shared.helpers
{
    internal class ProcessHash
    {
        private static readonly string context = "llnl";
        private static readonly string msgType = "Process";

        internal string GenPidHash(int _pid, long _eventTime)
        {
            return GenKeyForProcess(context, Environment.MachineName, StateManager.AgentId, _pid, _eventTime, msgType);
        }

        internal string GenKeyForProcess(string inContext, string inHostName, Guid agentId, int inPid, long inFirstEventTime, string msgType)
        {
            // Get the attribute key hash
            String attrKey = GenAttrKeyForProcess_ID(inContext, inHostName, agentId.ToString(), inPid, inFirstEventTime);

            // Add the entity name
            StringBuilder preImage = new StringBuilder();
            preImage.Append("N`");
            preImage.Append("Process");
            preImage.Append("`");
            preImage.Append(attrKey);
            preImage.Append("`");

            // Return as a hash
            return GetHash(preImage.ToString());
        }

        private string GenAttrKeyForProcess_ID(string inContext
         , string inHostName
         , string inAgentId
         , int inPid
         , long inFirstEventTime
         )
        {
            StringBuilder preImage = new StringBuilder(9999);
            preImage.Append("Process_ID`");
            preImage.Append(inContext);
            preImage.Append("`");
            preImage.Append(inFirstEventTime);
            preImage.Append("`");
            preImage.Append(inHostName);
            preImage.Append("`");
            preImage.Append(inAgentId);
            preImage.Append("`");
            preImage.Append(inPid);
            preImage.Append("`");
            return GetHash(preImage.ToString());
        }

        private string GetHash(string preImage)
        {
            byte[] result = MD5.HashData(Encoding.UTF8.GetBytes(preImage));
            StringBuilder hashStr = new StringBuilder(9999);
            for (int i = 0; i < result.Length; i++)
            {
                hashStr.Append(result[i].ToString("X2"));
            }
            return hashStr.ToString();
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

            internal string GetMD5(string path)
            {
                string hash = "NA";
                try
                {
                    if (md5Lookup.ContainsKey(path))
                    {
                        hash = md5Lookup[path];
                    }
                    else
                    {
                        hash = gov.llnl.wintap.core.shared.Utilities.getMD5(path);
                        md5Lookup.Add(path, hash);
                        hashAge.Add(DateTime.Now, path);
                    }
                }
                catch (Exception ex)
                {

                }

                return hash;
            }

            internal string GetSHA2(string path)
            {
                string hash = "NA";
                try
                {
                    if (sha2Lookup.ContainsKey(path))
                    {
                        hash = sha2Lookup[path];
                    }
                    else
                    {
                        hash = gov.llnl.wintap.core.shared.Utilities.getSHA2(path);
                        sha2Lookup.Add(path, hash);
                        hashAge.Add(DateTime.Now, path);
                    }
                }
                catch (Exception e)
                {

                }

                if (sha2Lookup.Count >= MAX_DICT_SIZE)
                {
                    WintapLogger.Log.Append($"WARN Process Hasher: Max size reached on sha2Lookup dictionary.  Current size: {sha2Lookup.Count}, max size: {MAX_DICT_SIZE}.  clearing dictionary...", LogLevel.Always);
                    sha2Lookup = new Dictionary<string, string>();
                    WintapLogger.Log.Append($"Process Hasher: sha2Lookup dictionary.  Current size: {sha2Lookup.Count}, max size: {MAX_DICT_SIZE}.", LogLevel.Always);
                }
                if (hashAge.Count >= MAX_DICT_SIZE)
                {
                    WintapLogger.Log.Append($"WARN Process Hasher: Max size reached on hashAge dictionary.  Current size: {hashAge.Count}, max size: {MAX_DICT_SIZE}.  clearing dictionary...", LogLevel.Always);
                    hashAge = new Dictionary<DateTime, string>();
                    WintapLogger.Log.Append($"Process Hasher: md5Lookup dictionary.  Current size: {hashAge.Count}, max size: {MAX_DICT_SIZE}.", LogLevel.Always);
                }

                return hash;
            }
        }
    }
}
