/*
 * Copyright (c) 2021, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.etl.shared;
using System;
using System.IO;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.api
{

    // meta data controller for the esper engine
    public class EsperServiceController : ControllerBase
    {

        public EsperServiceController()
        {

        }

        /// <summary>
        /// Gets events per second metric since the last ask and resets the counter
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("api/EsperService")]
        public IActionResult Get(string id)
        {
            StateManager.LastWorkbenchActivity = DateTime.Now;
            return Ok(new
            {
                eventsPerSecond = EventChannel.EventsPerSecond,
                maxEventsPerSecond = EventChannel.MaxEventsPerSecond,
                maxEventTime = EventChannel.MaxEventTime,
                totalEvents = EventChannel.TotalEvents,
                runtime = EventChannel.Runtime,
                wintapOK = parseWintapLog(),
                collectorOK = parseCollectorLog()
            });
            ;
        }


        private bool parseWintapLog()
        {
            bool wintapLogOK = false;
            try
            {
                wintapLogOK = ReadTail(Path.Combine(Paths.LogDataPath, "Wintap.log"));
            }
            catch (Exception ex)
            {

            }

            return wintapLogOK;
        }

        private bool parseCollectorLog()
        {

            bool collectorOK = false;
            try
            {
                collectorOK = ReadTail(Path.Combine(Paths.LogDataPath, "WintapETL.log"));
            }
            catch (Exception ex)
            {

            }
            return collectorOK;
        }

        internal bool ReadTail(string filename)
        {
            bool logOK = false;
            try
            {
                using (FileStream fs = System.IO.File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] bytes = new byte[fs.Length];
                    fs.Read(bytes, 0, (int)fs.Length);
                    string s = Encoding.Default.GetString(bytes);
                    logOK = processLogChunk(s, filename);
                }
            }
            catch (Exception Ex)
            {

            }
            return logOK;
        }

        /// <summary>
        /// returns True if log chunk contains no error
        /// </summary>
        /// <param name="s"></param>
        /// <param name="logName"></param>
        /// <returns></returns>
        internal bool processLogChunk(string s, string logName)
        {
            bool logChunkOK = true;
            EventArgs e = new EventArgs();
            string[] logLines = s.Split(new char[] { '\r' });
            foreach (string line in logLines)
            {
                if (logName.ToUpper().Contains("WINTAPETL"))
                {
                    if (line.ToLower().Contains("error creating registry data object"))
                    {
                        continue;  // registry collection is noisy, ignore...
                    }
                    else if (line.ToLower().Contains("error"))
                    {
                        logChunkOK = false;
                    }
                }
                else if (line.ToLower().Contains("error"))
                {
                    logChunkOK = false;
                }
            }
            return logChunkOK;
        }
    }

    public class EsperResult
    {
        public string Result { get; set; }
    }
}
