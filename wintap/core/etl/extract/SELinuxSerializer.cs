/*
 * Copyright (c) 2026, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using com.espertech.esper.common.client;
using gov.llnl.wintap.core.infrastructure;
using System;
using System.Dynamic;

namespace gov.llnl.wintap.core.etl.extract
{
    internal class SELinuxSerializer : Serializer
    {
        internal SELinuxSerializer(string query) : base(query)
        {
        }

        protected override void HandleSensorEvent(EventBean sensorEvent)
        {
            try
            {
                dynamic flatMsg = new ExpandoObject();
                flatMsg.MessageType = GetString(sensorEvent, "MessageType");
                flatMsg.PID = GetInt(sensorEvent, "PID");
                flatMsg.PidHash = GetString(sensorEvent, "PidHash");
                flatMsg.ProcessName = GetString(sensorEvent, "ProcessName");
                flatMsg.AgentId = GetString(sensorEvent, "AgentId");
                flatMsg.Hostname = Environment.MachineName.ToLower();
                flatMsg.FirstSeen = GetLong(sensorEvent, "FirstSeen");
                flatMsg.LastSeen = GetLong(sensorEvent, "LastSeen");
                flatMsg.EventTime = GetUnixEventTime(flatMsg.FirstSeen);
                flatMsg.EventCount = GetInt(sensorEvent, "EventCount");
                flatMsg.PolicyEpoch = GetInt(sensorEvent, "PolicyEpoch");

                string messageType = flatMsg.MessageType;
                if (messageType == "SELinuxAvc")
                {
                    flatMsg.SContext = GetString(sensorEvent, "SContext");
                    flatMsg.TContext = GetString(sensorEvent, "TContext");
                    flatMsg.TClass = GetString(sensorEvent, "TClass");
                    flatMsg.RequestedMask = GetLong(sensorEvent, "RequestedMask");
                    flatMsg.DeniedMask = GetLong(sensorEvent, "DeniedMask");
                    flatMsg.AuditedMask = GetLong(sensorEvent, "AuditedMask");
                    flatMsg.RequestedPerms = GetString(sensorEvent, "RequestedPerms");
                    flatMsg.DeniedPerms = GetString(sensorEvent, "DeniedPerms");
                    flatMsg.Result = GetInt(sensorEvent, "Result");
                    flatMsg.Enforcing = GetBool(sensorEvent, "Enforcing");
                }
                else if (messageType == "SELinuxTransition")
                {
                    flatMsg.OldSid = GetLong(sensorEvent, "OldSid");
                    flatMsg.NewSid = GetLong(sensorEvent, "NewSid");
                    flatMsg.OldContext = GetString(sensorEvent, "OldContext");
                    flatMsg.NewContext = GetString(sensorEvent, "NewContext");
                    flatMsg.ExeFile = GetString(sensorEvent, "ExeFile");
                }
                else if (messageType == "SELinuxInteraction")
                {
                    flatMsg.SSid = GetLong(sensorEvent, "SSid");
                    flatMsg.TSid = GetLong(sensorEvent, "TSid");
                    flatMsg.SContext = GetString(sensorEvent, "SContext");
                    flatMsg.TContext = GetString(sensorEvent, "TContext");
                    flatMsg.TClass = GetString(sensorEvent, "TClass");
                    flatMsg.Permission = GetString(sensorEvent, "Permission");
                    flatMsg.RequestedMask = GetLong(sensorEvent, "RequestedMask");
                    flatMsg.Novel = GetBool(sensorEvent, "Novel");
                }
                else
                {
                    return;
                }

                Save(flatMsg);
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("SELinux Error creating WintapData object, exception: " + ex.Message, LogLevel.Info);
            }
        }

        private static object Get(EventBean sensorEvent, string name)
        {
            try
            {
                return sensorEvent[name];
            }
            catch
            {
                string lower = char.ToLowerInvariant(name[0]) + name.Substring(1);
                return sensorEvent[lower];
            }
        }

        private static string GetString(EventBean sensorEvent, string name)
        {
            return Get(sensorEvent, name)?.ToString() ?? "";
        }

        private static int GetInt(EventBean sensorEvent, string name)
        {
            return Convert.ToInt32(Get(sensorEvent, name));
        }

        private static long GetLong(EventBean sensorEvent, string name)
        {
            return Convert.ToInt64(Get(sensorEvent, name));
        }

        private static bool GetBool(EventBean sensorEvent, string name)
        {
            return Convert.ToBoolean(Get(sensorEvent, name));
        }
    }
}
