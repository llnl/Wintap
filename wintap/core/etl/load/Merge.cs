using System.Diagnostics;
using System.IO;
using System.Linq;
using System;
using Antlr4.Runtime.Misc;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.shared;
using DuckDB.NET.Data;
using System.Collections.Generic;

namespace gov.llnl.wintap.core.etl.load
{
    public class Merge
    {
        private static string parquetSearchRoot;
        private static string wintapDataRoot;
        private static string sensorName;
        private static DateTime mergeTime;

        internal void Start(string[] args)
        {
            // CHECK AND PROCESS INPUTS
            try
            {
                processInputs(args);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Could not start merge: " + ex.Message, LogLevel.Info);
                return;
            }

            // MERGE PARQUET
            try
            {
                if (parquetSearchRoot.EndsWith("defaultserializer") || parquetSearchRoot.EndsWith("selinuxserializer"))
                {
                    List<string> defaultTypes = new List<string>();
                    // run merge on each contained type handled by multi-type serializers
                    DirectoryInfo defaultRoot = new DirectoryInfo(parquetSearchRoot);
                    if (defaultRoot.Exists)
                    {
                        foreach(FileInfo file in defaultRoot.GetFiles())
                        {
                            string defaultType = file.Name.ToLower().Split('-')[0];
                            if(!defaultTypes.Contains(defaultType))
                            {
                                defaultTypes.Add(defaultType);
                            }
                        }
                        foreach (string defaultMergeType in defaultTypes)
                        {
                            WintapLogger.Log.Append($"Attempting parquet merge on serializer type: {defaultMergeType}", LogLevel.Info);
                            try
                            {
                                sensorName = defaultMergeType;
                                string mergeFileName = Environment.MachineName.ToLower() + "+raw_" + sensorName.Replace("serializer", "") + "+" + mergeTime.ToFileTimeUtc().ToString() + ".parquet";
                                string sourceParquetGlob = parquetSearchRoot.Replace("\\", "/") + "/" + defaultMergeType + "*.parquet";
                                RawSensorWriter.MaterializeFromParquetGlob(sourceParquetGlob, mergeFileName);
                            }
                            catch(Exception ex)
                            {
                                WintapLogger.Log.Append($"Could not merge for serializer type {defaultMergeType}: {ex.Message}", LogLevel.Error);
                            }
                            
                        }
                    }
                    // split filenames by '-' to get distinct set of message types
                }
                else
                {
                    WintapLogger.Log.Append("Attempting to query parquets at root: " + parquetSearchRoot, LogLevel.Info);
                    sensorName = renameSensor(sensorName);  // e.g. tcp/udp
                    string mergeFileName = Environment.MachineName.ToLower() + "+raw_" + sensorName.Replace("serializer", "") + "+" + mergeTime.ToFileTimeUtc().ToString() + ".parquet";
                    string sourceParquetGlob = parquetSearchRoot.Replace("\\", "/") + "/*.parquet";
                    RawSensorWriter.MaterializeFromParquetGlob(sourceParquetGlob, mergeFileName);
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Error in duckdb merge for: " + sensorName + " msg: " + ex.Message, LogLevel.Info);
            }



            foreach(FileInfo mergedParquet in new DirectoryInfo(parquetSearchRoot).GetFiles("*.parquet"))
            {
                mergedParquet.Delete();
            }

            WintapLogger.Log.Append("Merge and cleanup complete!", LogLevel.Info);
        }

        private static string renameSensor(string _sensorName)
        {
            if (_sensorName.ToLower().StartsWith("tcpconnection"))
            {
                _sensorName = "tcp_process_conn_incr";
            }
            if (_sensorName.ToLower().StartsWith("udppacket"))
            {
                _sensorName = "udp_process_conn_incr";
            }
            return _sensorName;
        }

        //private static void runCmdLine(string path, long eventTime)
        //{
        //    WintapLogger.Log.Append("Shelling out for parquet merge for sensor: " + path, LogLevel.Info);
        //    ProcessStartInfo psi = new ProcessStartInfo();
        //    psi.FileName = System.Reflection.Assembly.GetExecutingAssembly().Location.Replace(".dll", ".exe");
        //    psi.Arguments = path + " " + eventTime;
        //    Process helperExe = new Process();
        //    helperExe.StartInfo = psi;
        //    WintapLogger.Log.Append("Attempting to rerun parquet merger: " + psi.FileName + " " + psi.Arguments, LogLevel.Info);
        //    helperExe.Start();
        //    helperExe.WaitForExit();
        //    WintapLogger.Log.Append("MergeHelper complete on : " + path, LogLevel.Info);
        //}

        private static void processInputs(string[] args)
        {
            if (args.Count() != 2)
            {
                throw new Exception("Wrong number of command line parameters. Expected 2, got " + args.Count());
            }
            if (!new DirectoryInfo(args[0]).Exists)
            {
                throw new Exception("Argument 1 not a valid file system path. parameter value: " + args[0]);
            }
            parquetSearchRoot = args[0];
            DirectoryInfo parquetSearchInfo = new DirectoryInfo(parquetSearchRoot);
            wintapDataRoot = parquetSearchInfo.Parent.FullName;
            sensorName = parquetSearchInfo.Name;
            WintapLogger.Log.Append("Search root: " + parquetSearchRoot, LogLevel.Info);
            if (parquetSearchInfo.GetFiles("*.parquet").Count() == 0)
            {
                throw new Exception("No parquet files found at path: " + parquetSearchInfo.FullName);
            }
            if (parquetSearchRoot.ToLower().Contains("merged"))
            {
                throw new Exception("invalid action: cannot merge the merge folder");
            }
            WintapLogger.Log.Append("Parsing Merge time from command line args (all merged parquets in an upload batch share this value)", LogLevel.Info);
            try
            {
                mergeTime = DateTime.FromFileTimeUtc(Convert.ToInt64(args[1])).ToUniversalTime();
                if (!(DateTime.UtcNow.Subtract(mergeTime) > new TimeSpan(0, 0, 0) && DateTime.UtcNow.Subtract(mergeTime) < new TimeSpan(0, 1, 0, 0)))
                {
                    throw new Exception("Invalid merge time.  Received: " + mergeTime + ".   Value must be within 1 hour of now");
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            WintapLogger.Log.Append("Merge time: " + mergeTime, LogLevel.Info);
        }
    }
}
