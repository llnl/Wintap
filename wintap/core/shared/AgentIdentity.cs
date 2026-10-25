/*
 * Copyright (c) 2026, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Microsoft.Win32;

namespace gov.llnl.wintap.core.shared
{
    // Separate from process identity: collector UUIDs are persisted and host-bound.
    internal static class AgentIdentity
    {
        internal sealed record Result(Guid AgentId, string Reason, bool Changed);

        private sealed class SavedState
        {
            public string AgentId { get; set; }
            public string HostBinding { get; set; }
            public int StateVersion { get; set; }
            [JsonExtensionData]
            public Dictionary<string, JsonElement> OtherFields { get; set; }
        }

        internal static string ReadMachineId()
        {
            if (OperatingSystem.IsLinux())
                return File.Exists("/etc/machine-id") ? File.ReadAllText("/etc/machine-id").Trim() : "";
            if (OperatingSystem.IsWindows())
            {
                using var registry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = registry.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                return key?.GetValue("MachineGuid")?.ToString()?.Trim() ?? "";
            }
            // Hostname-only binding on platforms without an implemented machine-ID provider.
            return "";
        }

        internal static string CreateHostBinding(string hostname, string machineId)
        {
            string host = ProcessIdentity.NormalizeHostname(hostname);
            string machine = (machineId ?? "").Trim().ToUpperInvariant();
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                "WintapAgentHost:v1:" + host.Length + ":" + host + ":" + machine)));
        }

        internal static Result LoadOrCreate(string statePath, string hostname, string machineId, string legacyPath = null)
        {
            string binding = CreateHostBinding(hostname, machineId);
            statePath = Path.GetFullPath(statePath);
            Directory.CreateDirectory(Path.GetDirectoryName(statePath));
            using var stateLock = AcquireLock(statePath + ".lock");
            bool exists = File.Exists(statePath);
            string input = exists ? statePath : legacyPath;
            SavedState saved = input != null && File.Exists(input)
                ? JsonSerializer.Deserialize<SavedState>(File.ReadAllText(input))
                    ?? throw new InvalidDataException("Agent state must be a JSON object.")
                : new SavedState();
            if (saved.StateVersion > 1)
                throw new InvalidDataException("Agent state version is newer than this collector supports.");

            bool valid = Guid.TryParse(saved.AgentId, out Guid id) && id != Guid.Empty;
            bool bound = saved.StateVersion == 1 && saved.HostBinding == binding;
            if (valid && bound && exists)
                return new Result(id, "existing-host-bound-state", false);

            // Unbound legacy UUIDs cannot safely be claimed by a host: they may
            // already have been distributed to multiple machines. Reissue once.
            string reason = !valid ? "new-agent" : !bound
                ? string.IsNullOrEmpty(saved.HostBinding) ? "legacy-unbound-state" : "copied-or-changed-host-state"
                : "moved-host-bound-state";
            if (!valid || !bound)
                id = Guid.NewGuid();
            saved.AgentId = id.ToString();
            saved.HostBinding = binding;
            saved.StateVersion = 1;

            string pending = statePath + "." + Guid.NewGuid().ToString("N") + ".pending";
            try
            {
                using (var stream = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, saved);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(pending, statePath, overwrite: true);
            }
            finally
            {
                if (File.Exists(pending)) File.Delete(pending);
            }
            // Never return an ID that was not successfully persisted.
            return new Result(id, reason, true);
        }

        private static FileStream AcquireLock(string path)
        {
            var elapsed = Stopwatch.StartNew();
            while (true)
            {
                try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException) when (elapsed.Elapsed < TimeSpan.FromSeconds(5)) { Thread.Sleep(25); }
            }
        }
    }
}
