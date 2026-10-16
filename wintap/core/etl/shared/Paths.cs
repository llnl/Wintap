/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.etl.shared
{
    internal class Paths
    {
        internal static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        internal static readonly string DataRoot = Env.FileDataRoot;
        internal static readonly string RuntimeRoot = Env.FileRuntimeRoot;
        internal static readonly string ParquetDataPath = DataRoot;
        internal static readonly string EsperStagingPath = Path.Combine(RuntimeRoot, "esper_staging");
        internal static readonly string LogDataPath = Path.Combine(RuntimeRoot, "Logs");
        internal static readonly string EventStorePath = Path.Combine(RuntimeRoot, "event_store");
        internal static readonly string CsvDataPath = Path.Combine(RuntimeRoot, "csv");
        internal static readonly string RecordingDataPath = Path.Combine(RuntimeRoot, "recordings");
        internal static readonly string DiagDataPath = Path.Combine(RuntimeRoot, "diag");
        internal static readonly string AiDataPath = Path.Combine(RuntimeRoot, "ai");
        internal static readonly string WorkbenchStatePath = Path.Combine(RuntimeRoot, "workbench-state.json");
    }
}
