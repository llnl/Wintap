using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.etl.model
{
    public class ETLConfig
    {
        public ETLConfig() { }
        public string LogLevel { get; set; }
        public string SensorProfile { get; set; }
        public int SerializationIntervalSec { get; set; }
        public int? FileSerializationIntervalSec { get; set; }
        public int? FileSerializationHighWaterEvents { get; set; }
        public int? RegistrySerializationIntervalSec { get; set; }
        public int? RegistrySerializationHighWaterEvents { get; set; }
        public int? RegistrySerializationMaxQueueEvents { get; set; }
        // Keys are serializer class names, e.g. "tcpconnectionserializer".
        public Dictionary<string, SerializerOptions> Serializers { get; set; } = new();
        public class SerializerOptions
        {
            public bool? UseDedicatedWorker { get; set; }
            public int? IntervalSec { get; set; }
            public int? HighWaterEvents { get; set; }
            public int? MaxQueueEvents { get; set; }
        }
        public int UploadIntervalSec { get; set; }
        public long RawSensorMaxCacheSizeBytes { get; set; }
        public bool WriteToParquet { get; set; }
        public bool WriteToCsv { get; set; }
        public string DataRootPath { get; set; }
        public List<Adapter> Adapters = new List<Adapter>();
        public class Adapter
        {
            public Adapter()
            {
                Properties = new Dictionary<string, string>();
            }
            public string Name { get; set; }
            public bool Enabled { get; set; }
            public Dictionary<string, string> Properties;
        }
    }
}
