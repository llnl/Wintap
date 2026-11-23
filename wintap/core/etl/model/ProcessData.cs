/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */
using System;

namespace gov.llnl.wintap.core.etl.models
{
    [Serializable]

    public class ProcessTerminateData : SensorData
    {
        private readonly string _parentPidHash;

        public ProcessTerminateData(string parentPidHash)
        {
            this._parentPidHash = parentPidHash;
        }

        public string PidHash { get; set; }
        public string ParentPidHash
        {
            get
            {
                return _parentPidHash;
            }
        }
        public string ProcessName { get; set; }
        public long CPUCycleCount { get; set; }
        public int CPUUtilization { get; set; }
        public long CommitCharge { get; set; }
        public long CommitPeak { get; set; }
        public long ReadOperationCount { get; set; }
        public long WriteOperationCount { get; set; }
        public long ReadTransferKiloBytes { get; set; }
        public long WriteTransferKiloBytes { get; set; }
        public int HardFaultCount { get; set; }
        public int TokenElevationType { get; set; }
        public long ExitCode { get; set; }
        public string ExitCodeCaptureStatus { get; set; }
        public long? ObservationTimeFileTimeUtc { get; set; }
        public long? ObservationTimeMonotonicNanoseconds { get; set; }
        public string ObservationClockDomain { get; set; }
        public string ObservationRunId { get; set; }
        public string AgentId { get; internal set; }
    }
}
