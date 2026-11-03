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
using System;
using System.Dynamic;
using static gov.llnl.wintap.collect.models.WintapMessage;

namespace gov.llnl.wintap.core.etl.extract
{
    /// <summary>
    /// generic wintap data processor for all event types that don't require aggregation or other special handling.
    /// </summary>
    internal class DefaultSerializer : Serializer
    {
        internal DefaultSerializer(string query) : base(query)
        {
        }

        protected override void HandleSensorEvent(EventBean sensorEvent)
        {
            try
            {
                base.HandleSensorEvent(sensorEvent);
                WintapMessage wintapMessage = (WintapMessage)sensorEvent.Underlying;
                dynamic flatMsg = BuildFlatMessage(wintapMessage);
                this.Save(flatMsg);
                sensorEvent = null;
                flatMsg = null;
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("WARN creating default sensor data object for pid: " + sensorEvent["PID"] + " message type: " + sensorEvent["MessageType"] + ", exception: " + ex.Message, LogLevel.Debug);
            }
        }
        internal static ExpandoObject BuildFlatMessage(WintapMessage wintapMessage)
        {
            // The payload property name must match MessageType for default ETL.
            var property = wintapMessage.GetType().GetProperty(wintapMessage.MessageType.ToString());
            if (property?.GetValue(wintapMessage) is not WintapBase payload)
                throw new InvalidOperationException("Missing payload for " + wintapMessage.MessageType);

            dynamic flatMsg = payload.ToDynamic();
            flatMsg.PidHash = wintapMessage.PidHash.ToString();
            flatMsg.ProcessName = wintapMessage.ProcessName.ToString();
            flatMsg.PID = wintapMessage.PID;
            // Parquet stores enum names, not .NET enum instances.
            flatMsg.MessageType = wintapMessage.MessageType.ToString();
            flatMsg.ActivityType = wintapMessage.ActivityType.ToString();
            flatMsg.EventTime = wintapMessage.EventTime;
            flatMsg.ComputerName = Environment.MachineName;
            flatMsg.AgentId = wintapMessage.AgentId;
            flatMsg.ActivityId = wintapMessage.ActivityId;
            flatMsg.CorrelationId = wintapMessage.CorrelationId;
            return (ExpandoObject)flatMsg;
        }
    }
}
