/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using System;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.platform.windows.collect.etw.helpers;
using gov.llnl.wintap.platform.windows.collect.shared;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace gov.llnl.wintap.platform.windows.collect.etw
{
    /// <summary>
    /// Registry events from the manifest Microsoft-Windows-Kernel-Registry provider.
    /// </summary>
    internal class RegistrySensor : EtwProviderCollector
    {
        private const string ManifestRegistryProviderId = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
        private static readonly Guid ManifestRegistryProviderGuid = new Guid(ManifestRegistryProviderId);

        private readonly Action<WintapMessage> emit;
        private readonly Func<bool> collectRegistryRead;
        private readonly ulong keywordMask;
        private RegistryCaptureEnabler captureEnabler;
        private RegistryCaptureCanary captureCanary;
        private long canarySequence;

        internal static readonly TimeSpan ReassertInterval = TimeSpan.FromMinutes(5);

        public RegistrySensor() : this(null, null)
        {
        }

        /// <summary>
        /// Test seams for emission and the CollectRegistryRead setting.
        /// </summary>
        internal RegistrySensor(Action<WintapMessage> emit, Func<bool> collectRegistryRead)
        {
            SensorName = "Registry";
            EtwProviderId = ManifestRegistryProviderId;
            this.emit = emit ?? EventChannel.Send;
            this.collectRegistryRead = collectRegistryRead
                ?? (() => Properties.Settings.Default.CollectRegistryRead);
            keywordMask = SelectKeywordMask(this.collectRegistryRead());
            TraceEventFlags = keywordMask;
            EventLevel = TraceEventLevel.Verbose;
        }

        public override void Process_Event(TraceEvent obj)
        {
            base.Process_Event(obj);
            if (obj == null || obj.ProviderGuid != ManifestRegistryProviderGuid)
            {
                return;
            }

            Counter++;
            try
            {
                switch (RegistryPayloadDecoder.KindFromEventId((int)obj.ID))
                {
                    case RegistryEventKind.CreateKey:
                        HandleCreateKey(
                            obj.TimeStamp,
                            obj.ProcessID,
                            PayloadString(obj, "BaseName"),
                            PayloadString(obj, "RelativeName"));
                        break;
                    case RegistryEventKind.DeleteKey:
                        HandleDeleteKey(obj.TimeStamp, obj.ProcessID, PayloadString(obj, "KeyName"));
                        break;
                    case RegistryEventKind.SetValueKey:
                        HandleSetValue(
                            obj.TimeStamp,
                            obj.ProcessID,
                            PayloadString(obj, "KeyName"),
                            PayloadString(obj, "ValueName"),
                            PayloadInt32(obj, "Type"),
                            PayloadBytes(obj, "CapturedData"),
                            PayloadInt32(obj, "PreviousDataType"),
                            PayloadBytes(obj, "PreviousData"));
                        break;
                    case RegistryEventKind.DeleteValueKey:
                        HandleDeleteValue(
                            obj.TimeStamp,
                            obj.ProcessID,
                            PayloadString(obj, "KeyName"),
                            PayloadString(obj, "ValueName"));
                        break;
                    case RegistryEventKind.QueryValueKey:
                        if (collectRegistryRead())
                        {
                            HandleQueryValue(
                                obj.TimeStamp,
                                obj.ProcessID,
                                PayloadString(obj, "KeyName"),
                                PayloadString(obj, "ValueName"));
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error parsing user mode event: " + ex.Message, LogLevel.Debug);
            }
        }

        protected override void OnEtwSessionStarted(TraceEventSession session)
        {
            captureEnabler = new RegistryCaptureEnabler(
                session,
                ManifestRegistryProviderGuid,
                keywordMask);
            captureEnabler.EnableCapture();
            captureEnabler.StartReassertTimer(ReassertInterval);

            captureCanary = new RegistryCaptureCanary(
                WriteCaptureCanary,
                StateManager.WintapPID,
                captureEnabler.NotifyCaptureLossSuspected);
            captureCanary.Start();
        }

        public override void Stop()
        {
            captureCanary?.Stop();
            captureCanary?.Dispose();
            captureCanary = null;
            captureEnabler?.StopReassertTimer();
            captureEnabler?.Dispose();
            captureEnabler = null;
            base.Stop();
        }

        internal void HandleCreateKey(DateTime timestamp, int pid, string baseName, string relativeName)
        {
            EmitNoData(timestamp, pid, WintapMessage.ActivityTypeEnum.CreateKey,
                AssembleCreateKeyPath(baseName, relativeName), string.Empty);
        }

        internal void HandleDeleteKey(DateTime timestamp, int pid, string keyName)
        {
            EmitNoData(timestamp, pid, WintapMessage.ActivityTypeEnum.DeleteKey,
                NormalizeKeyPath(keyName), string.Empty);
        }

        internal void HandleDeleteValue(
            DateTime timestamp,
            int pid,
            string keyName,
            string valueName)
        {
            EmitNoData(timestamp, pid, WintapMessage.ActivityTypeEnum.DeleteValue,
                NormalizeKeyPath(keyName), valueName ?? string.Empty);
        }

        internal void HandleSetValue(
            DateTime timestamp,
            int pid,
            string keyName,
            string valueName,
            int type,
            byte[] capturedData,
            int previousDataType,
            byte[] previousData)
        {
            if (captureCanary?.Observe(pid, valueName, keyName) == true)
            {
                return;
            }

            string path = NormalizeKeyPath(keyName);
            if (!IsQualifiedRegistry(path))
            {
                return;
            }

            var message = CreateMessage(
                timestamp,
                pid,
                WintapMessage.ActivityTypeEnum.Write,
                path,
                valueName ?? string.Empty);
            message.Registry.Data = RegistryPayloadDecoder.DecodeRegValue(type, capturedData ?? Array.Empty<byte>());
            message.Registry.DataType = MapDataType(type);
            message.Registry.PreviousData = RegistryPayloadDecoder.DecodeRegValue(
                previousDataType,
                previousData ?? Array.Empty<byte>());
            message.Registry.PreviousDataType = MapDataType(previousDataType);
            emit(message);
        }

        internal void HandleQueryValue(DateTime timestamp, int pid, string keyName, string valueName)
        {
            EmitNoData(timestamp, pid, WintapMessage.ActivityTypeEnum.Read,
                NormalizeKeyPath(keyName), valueName ?? string.Empty);
        }

        internal bool ShouldCollectRegistryRead()
        {
            return collectRegistryRead();
        }

        // FINAL (Architect 2026-08-25; probe8 PASS â€” see the ADR addendum).
        internal static ulong SelectKeywordMask(bool collectRegistryRead)
        {
            return collectRegistryRead
                ? RegistryCaptureEnabler.ReadKeywordMask
                : RegistryCaptureEnabler.DefaultKeywordMask;
        }

        internal static string NormalizeKeyPath(string kernelPath)
        {
            if (string.IsNullOrWhiteSpace(kernelPath))
            {
                return string.Empty;
            }

            return kernelPath.TrimStart('\\').ToLowerInvariant();
        }

        internal static string AssembleCreateKeyPath(string baseName, string relativeName)
        {
            string candidate;
            if (!string.IsNullOrEmpty(relativeName) && relativeName.StartsWith("\\", StringComparison.Ordinal))
            {
                candidate = relativeName;
            }
            else if (!string.IsNullOrEmpty(baseName))
            {
                string normalizedBase = baseName.TrimEnd('\\');
                string normalizedRelative = (relativeName ?? string.Empty).TrimStart('\\');
                candidate = normalizedRelative.Length == 0
                    ? normalizedBase
                    : normalizedBase + "\\" + normalizedRelative;
            }
            else
            {
                return string.Empty;
            }

            return NormalizeKeyPath(candidate);
        }

        internal static WintapMessage.DataTypeEnum MapDataType(int nativeType)
        {
            switch (nativeType)
            {
                case 1:
                    return WintapMessage.DataTypeEnum.STRING;
                case 2:
                    return WintapMessage.DataTypeEnum.EXPAND_SZ;
                case 3:
                    return WintapMessage.DataTypeEnum.BINARY;
                case 4:
                    return WintapMessage.DataTypeEnum.DWORD;
                case 7:
                    return WintapMessage.DataTypeEnum.MULTI_SZ;
                case 11:
                    return WintapMessage.DataTypeEnum.QWORD;
                default:
                    return WintapMessage.DataTypeEnum.NONE;
            }
        }

        private void EmitNoData(
            DateTime timestamp,
            int pid,
            WintapMessage.ActivityTypeEnum activityType,
            string path,
            string valueName)
        {
            if (!IsQualifiedRegistry(path))
            {
                return;
            }

            WintapMessage message = CreateMessage(timestamp, pid, activityType, path, valueName);
            message.Registry.Data = string.Empty;
            message.Registry.DataType = WintapMessage.DataTypeEnum.NONE;
            message.Registry.PreviousData = string.Empty;
            message.Registry.PreviousDataType = WintapMessage.DataTypeEnum.NONE;
            emit(message);
        }

        private static WintapMessage CreateMessage(
            DateTime timestamp,
            int pid,
            WintapMessage.ActivityTypeEnum activityType,
            string path,
            string valueName)
        {
            return new WintapMessage(timestamp, pid, WintapMessage.MessageTypeEnum.Registry)
            {
                ActivityType = activityType,
                Registry = new WintapMessage.RegActivityObject
                {
                    Path = path,
                    ValueName = valueName,
                    Data = string.Empty,
                    DataType = WintapMessage.DataTypeEnum.NONE,
                    PreviousData = string.Empty,
                    PreviousDataType = WintapMessage.DataTypeEnum.NONE
                }
            };
        }

        private static bool IsQualifiedRegistry(string path)
        {
            return path == "registry"
                || (path != null && path.StartsWith("registry\\", StringComparison.Ordinal));
        }

        private static string PayloadString(TraceEvent obj, string name)
        {
            try
            {
                return obj.PayloadByName(name) as string ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static byte[] PayloadBytes(TraceEvent obj, string name)
        {
            try
            {
                return obj.PayloadByName(name) as byte[] ?? Array.Empty<byte>();
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        private static int PayloadInt32(TraceEvent obj, string name)
        {
            try
            {
                object value = obj.PayloadByName(name);
                return value == null ? 0 : Convert.ToInt32(value);
            }
            catch
            {
                return 0;
            }
        }

        private void WriteCaptureCanary()
        {
            long sequence = System.Threading.Interlocked.Increment(ref canarySequence);
            string keyPath = @"HKEY_LOCAL_MACHINE\" + Env.RegistryCollectorPath + "\\" + SensorName;
            string payload = sequence + "|" + DateTime.UtcNow.Ticks;
            Microsoft.Win32.Registry.SetValue(
                keyPath,
                RegistryCaptureCanary.CanaryValueName,
                payload,
                Microsoft.Win32.RegistryValueKind.String);
        }
    }
}
