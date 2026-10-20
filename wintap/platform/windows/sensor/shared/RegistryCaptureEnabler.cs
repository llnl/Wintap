/*
 * Copyright (c) 2026, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.infrastructure;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Timers;

namespace gov.llnl.wintap.platform.windows.collect.shared
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_FILTER_DESCRIPTOR
    {
        public IntPtr Ptr;
        public int Size;
        public int Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENABLE_TRACE_PARAMETERS
    {
        public uint Version;
        public uint EnableProperty;
        public uint ControlFlags;
        public Guid SourceId;
        public IntPtr EnableFilterDesc;
        public int FilterDescCount;
    }

    /// <summary>
    /// Enables the undocumented capture mode of a manifest ETW provider
    /// (Microsoft-Windows-Kernel-Registry) on a live TraceEventSession:
    /// disable-then-enable with a 4-byte 0xFFFFFFFF EVENT_FILTER_DESCRIPTOR
    /// via EnableTraceEx2 at startup/recovery, plus periodic enable-only refresh.
    /// Routine refresh must not disable a healthy provider and lose intervening writes.
    /// Mechanism record:
    /// ../Wintap-Analytics/wiki/decision/registry-provider-strategy.md
    /// </summary>
    internal sealed class RegistryCaptureEnabler : IDisposable
    {
        private const uint EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0;
        private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
        private const byte TRACE_LEVEL_VERBOSE = 5;
        private const int EnableTimeoutMs = 10000;

        // Architect-chosen masks (2026-08-25) from the provider's keyword table
        // (logman query providers Microsoft-Windows-Kernel-Registry):
        //   SetValueKey 0x100 | DeleteValueKey 0x200 | CreateKey 0x1000 | DeleteKey 0x4000
        internal const ulong DefaultKeywordMask = 0x5300;
        //   + QueryValueKey 0x400, only when CollectRegistryRead is enabled
        internal const ulong ReadKeywordMask = 0x5700;
        // CONFIRMED FINAL by probe8 (2026-08-25): narrowed MatchAnyKeyword
        // composes cleanly with the capture filter (probe8.log; ADR addendum).

        internal delegate int NativeEnableTraceEx2(
            ulong traceHandle, in Guid providerId, uint controlCode, byte level,
            ulong matchAnyKeyword, ulong matchAllKeyword, int timeout,
            in ENABLE_TRACE_PARAMETERS parameters);

        private readonly TraceEventSession session;
        private readonly Guid providerId;
        private readonly ulong matchAnyKeyword;
        private readonly NativeEnableTraceEx2 nativeEnableTraceEx2;
        private readonly Action<string, LogLevel> log;
        private readonly object enableLock = new object();
        private readonly object timerLock = new object();
        private System.Timers.Timer reassertTimer;
        private ulong traceHandle;
        private bool hasTraceHandle;
        private long reassertCount;

        internal RegistryCaptureEnabler(
            TraceEventSession session,
            Guid providerId,
            ulong matchAnyKeyword,
            NativeEnableTraceEx2 nativeOverride = null)
        {
            this.session = session;
            this.providerId = providerId;
            this.matchAnyKeyword = matchAnyKeyword;
            nativeEnableTraceEx2 = nativeOverride ?? EnableTraceEx2;
            log = (message, level) => WintapLogger.Log.Append(message, level);
        }

        // Test-only construction seam: avoids creating an elevated ETW session.
        internal RegistryCaptureEnabler(
            ulong traceHandle,
            Guid providerId,
            ulong matchAnyKeyword,
            NativeEnableTraceEx2 nativeOverride,
            Action<string, LogLevel> logOverride = null)
            : this(null, providerId, matchAnyKeyword, nativeOverride)
        {
            this.traceHandle = traceHandle;
            hasTraceHandle = true;
            log = logOverride ?? log;
        }

        internal long ReassertCount => Interlocked.Read(ref reassertCount);

        /// <summary>
        /// Acquires TraceEvent's internal session handle with explicit guards for
        /// private API changes in the pinned dependency.
        /// </summary>
        internal static ulong GetSessionHandle(TraceEventSession session)
        {
            FieldInfo sessionHandleField = typeof(TraceEventSession).GetField(
                "m_SessionHandle",
                BindingFlags.Instance | BindingFlags.NonPublic);

            if (sessionHandleField == null)
            {
                throw new InvalidOperationException(
                    "TraceEventSession.m_SessionHandle field not found via reflection — " +
                    "TraceEvent version changed? Wintap pins TraceEvent 3.1.23 " +
                    "(wintap/Wintap.csproj); registry capture mode cannot start.");
            }

            return AcquireHandleFromFieldValue(sessionHandleField.GetValue(session));
        }

        /// <summary>
        /// Guarded, duck-typed access to TraceEvent's internal SafeTraceHandle.
        /// </summary>
        internal static ulong AcquireHandleFromFieldValue(object sessionHandleFieldValue)
        {
            if (sessionHandleFieldValue == null)
            {
                throw new InvalidOperationException(
                    "TraceEvent m_SessionHandle is null — session not started. Wintap pins " +
                    "TraceEvent 3.1.23 (wintap/Wintap.csproj); registry capture mode cannot start.");
            }

            MethodInfo dangerousGetHandle = sessionHandleFieldValue.GetType().GetMethod(
                "DangerousGetHandle",
                BindingFlags.Instance | BindingFlags.Public,
                null,
                Type.EmptyTypes,
                null);

            if (dangerousGetHandle == null)
            {
                throw new InvalidOperationException(
                    "DangerousGetHandle() not found on TraceEvent's internal SafeTraceHandle — " +
                    "TraceEvent version changed? Wintap pins TraceEvent 3.1.23 " +
                    "(wintap/Wintap.csproj); registry capture mode cannot start.");
            }

            object handleValue = dangerousGetHandle.Invoke(sessionHandleFieldValue, null);
            if (handleValue is IntPtr pointer)
            {
                return unchecked((ulong)pointer.ToInt64());
            }

            return Convert.ToUInt64(handleValue);
        }

        /// <summary>
        /// Disables, then enables, the provider with the capture filter attached.
        /// </summary>
        internal void EnableCapture()
        {
            AssertCaptureFilter(resetProvider: true);
            log(
                $"Registry provider {providerId} mask 0x{matchAnyKeyword:X}: capture filter asserted",
                LogLevel.Info);
        }

        /// <summary>Refreshes capture without a disable gap unless recovery requires a reset.</summary>
        internal void ReassertCapture(bool resetProvider = false)
        {
            AssertCaptureFilter(resetProvider);
            Interlocked.Increment(ref reassertCount);
            log(
                $"Registry provider {providerId} mask 0x{matchAnyKeyword:X}: capture filter re-asserted (provider_reset={resetProvider})",
                LogLevel.Info);
        }

        /// <summary>Immediately re-asserts capture after a caller detects suspected loss.</summary>
        internal void NotifyCaptureLossSuspected()
        {
            log(
                $"Registry provider {providerId}: capture loss suspected; re-asserting capture filter",
                LogLevel.Info);
            ReassertCapture(resetProvider: true);
        }

        internal void StartReassertTimer(TimeSpan interval)
        {
            lock (timerLock)
            {
                StopReassertTimerCore();
                reassertTimer = new System.Timers.Timer(interval.TotalMilliseconds)
                {
                    AutoReset = true
                };
                reassertTimer.Elapsed += ReassertTimerElapsed;
                reassertTimer.Start();
            }
        }

        internal void StopReassertTimer()
        {
            lock (timerLock)
            {
                StopReassertTimerCore();
            }
        }

        /// <summary>Runs one resilient periodic re-assert attempt.</summary>
        internal void OnReassertTick()
        {
            try
            {
                ReassertCapture();
            }
            catch (Exception ex)
            {
                log(
                    $"Registry provider {providerId}: capture filter re-assert failed: {ex.Message}",
                    LogLevel.Info);
            }
        }

        public void Dispose()
        {
            StopReassertTimer();
        }

        private void AssertCaptureFilter(bool resetProvider)
        {
            lock (enableLock)
            {
                ulong currentTraceHandle = GetOrAcquireTraceHandle();
                if (resetProvider)
                {
                    var disableParameters = new ENABLE_TRACE_PARAMETERS
                    {
                        Version = 2
                    };

                    int disableResult = nativeEnableTraceEx2(
                        currentTraceHandle,
                        in providerId,
                        EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                        0,
                        0,
                        0,
                        EnableTimeoutMs,
                        in disableParameters);

                    if (disableResult != 0)
                    {
                        log(
                            $"Registry provider {providerId}: disable before capture assertion returned win32 error {disableResult}; continuing",
                            LogLevel.Info);
                    }
                }

                byte[] captureFlags = BitConverter.GetBytes(0xFFFFFFFFu);
                var filter = new EVENT_FILTER_DESCRIPTOR
                {
                    Size = 4,
                    Type = 0x1
                };

                GCHandle payloadHandle = default;
                GCHandle filterHandle = default;
                try
                {
                    payloadHandle = GCHandle.Alloc(captureFlags, GCHandleType.Pinned);
                    filter.Ptr = payloadHandle.AddrOfPinnedObject();
                    filterHandle = GCHandle.Alloc(filter, GCHandleType.Pinned);

                    var enableParameters = new ENABLE_TRACE_PARAMETERS
                    {
                        Version = 2,
                        EnableFilterDesc = filterHandle.AddrOfPinnedObject(),
                        FilterDescCount = 1
                    };

                    int enableResult = nativeEnableTraceEx2(
                        currentTraceHandle,
                        in providerId,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE,
                        matchAnyKeyword,
                        0,
                        EnableTimeoutMs,
                        in enableParameters);

                    if (enableResult != 0)
                    {
                        throw new InvalidOperationException(
                            $"EnableTraceEx2 failed to assert registry capture filter with win32 error {enableResult}.");
                    }
                }
                finally
                {
                    if (filterHandle.IsAllocated)
                    {
                        filterHandle.Free();
                    }

                    if (payloadHandle.IsAllocated)
                    {
                        payloadHandle.Free();
                    }
                }
            }
        }

        private ulong GetOrAcquireTraceHandle()
        {
            if (!hasTraceHandle)
            {
                traceHandle = GetSessionHandle(session);
                hasTraceHandle = true;
            }

            return traceHandle;
        }

        private void ReassertTimerElapsed(object sender, ElapsedEventArgs e)
        {
            OnReassertTick();
        }

        private void StopReassertTimerCore()
        {
            if (reassertTimer == null)
            {
                return;
            }

            reassertTimer.Stop();
            reassertTimer.Elapsed -= ReassertTimerElapsed;
            reassertTimer.Dispose();
            reassertTimer = null;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int EnableTraceEx2(
            ulong traceHandle,
            in Guid providerId,
            uint controlCode,
            byte level,
            ulong matchAnyKeyword,
            ulong matchAllKeyword,
            int timeout,
            in ENABLE_TRACE_PARAMETERS enableParameters);
    }
}
