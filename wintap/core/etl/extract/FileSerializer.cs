
/*
 * Copyright (c) 2022, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */


using com.espertech.esper.client;
using com.espertech.esper.common.client;
using gov.llnl.wintap.collect.models;
using gov.llnl.wintap.core.etl.models;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.transform;
using System;
using System.Dynamic;

namespace gov.llnl.wintap.core.etl.extract
{
    internal class FileSerializer : Serializer
    {

        // Producer owns platform normalization. Linux/macOS paths can differ
        // only by case; do not collapse them during projection or file-keying.
        internal static string SelectPath(string path, bool windows) => path;

        internal FileSerializer(string query) : base(query)
        {

        }

        internal void EsperMon_Overrun(object sender, EventArgs e)
        {

        }

        protected override void HandleSensorEvent(EventBean sensorEvent)
        {
            try
            {
                IdGenerator idGen = new IdGenerator();
                // GrantJ - force non-null
                string pidHash = sensorEvent["PidHash"]?.ToString() ??  "fixmepid";
                // string pidHash = sensorEvent["PidHash"].ToString();
                DateTime eventTime = DateTime.FromFileTimeUtc((long)sensorEvent["firstSeen"]);
                // dynamic flatMsg = (ExpandoObject)new WintapMessage.FileActivityObject().ToDynamic();
                dynamic flatMsg = new ExpandoObject();  // since we are overriding WintapMessage property name definitions, i.e. File_Path
                flatMsg.ActivityType = sensorEvent["activityType"].ToString();
                flatMsg.ProcessName = sensorEvent["ProcessName"].ToString();
                flatMsg.AgentId = sensorEvent["AgentId"].ToString();
                flatMsg.BytesRequested = Int32.Parse(sensorEvent["bytesRequested"].ToString());
                flatMsg.EventCount = Int32.Parse(sensorEvent["eventCount"].ToString());
                flatMsg.FirstSeen = (long)sensorEvent["firstSeen"];
                flatMsg.LastSeen = (long)sensorEvent["lastSeen"];
                flatMsg.PidHash = pidHash;
                flatMsg.PID = Int32.Parse(sensorEvent["PID"].ToString());
                // Keep file rows in the same hostname namespace as process and
                // network serializers.  Lower-casing only this event family
                // makes host-scoped downstream joins silently diverge on Linux.
                flatMsg.Hostname = HostSerializer.Instance.HostId.Hostname;
                flatMsg.File_Path = SelectPath(sensorEvent["path"].ToString(), System.OperatingSystem.IsWindows());
                flatMsg.File_Hash = idGen.GenKeyForFile(transform.Transformer.context, HostSerializer.Instance.HostId.Hostname, flatMsg.AgentId, flatMsg.File_Path);
                flatMsg.MessageType = "PROCESS_FILE";
                flatMsg.EventTime = GetUnixNowTime();
                this.Save(flatMsg);
                sensorEvent = null;
                flatMsg = null;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("FILE Error creating WintapData object, exception: " + ex.Message, LogLevel.Info);
            }

        }
    }
}
