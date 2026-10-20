using System;
using gov.llnl.wintap.core.etl.model;

namespace gov.llnl.wintap.core.etl.extract
{
    internal static class SerializerSchedule
    {
        internal static ETLConfig.SerializerOptions ResolveOptions(ETLConfig config, string name, int inheritedCapacity, int? capacityOverride = null)
        {
            ETLConfig.SerializerOptions custom = null;
            if (config.Serializers != null)
                foreach (var entry in config.Serializers)
                    if (string.Equals(entry.Key, name, StringComparison.OrdinalIgnoreCase)) custom = entry.Value;
            bool registry = name == "registryserializer", file = name == "fileserializer";
            int capacity = ResolveQueueCapacity(custom?.MaxQueueEvents,
                registry ? ResolveQueueCapacity(config.RegistrySerializationMaxQueueEvents, inheritedCapacity) : inheritedCapacity);
            capacity = ResolveQueueCapacity(capacityOverride, capacity);
            int interval = ResolveIntervalSeconds(name, config.SerializationIntervalSec,
                config.FileSerializationIntervalSec ?? 5, config.RegistrySerializationIntervalSec ?? 5);
            if (custom?.IntervalSec != null)
                interval = custom.IntervalSec > 0 ? custom.IntervalSec.Value : (config.SerializationIntervalSec > 0 ? config.SerializationIntervalSec : 60);
            int highWater = custom?.HighWaterEvents ?? (registry ? config.RegistrySerializationHighWaterEvents ?? 5000
                : file ? config.FileSerializationHighWaterEvents ?? 5000 : 0);
            return new ETLConfig.SerializerOptions
            {
                UseDedicatedWorker = custom?.UseDedicatedWorker ?? registry,
                IntervalSec = interval,
                MaxQueueEvents = capacity,
                HighWaterEvents = ResolveHighWaterEvents(highWater, capacity)
            };
        }

        internal static int ResolveIntervalSeconds(string serializerName, int defaultIntervalSeconds, int fileIntervalSeconds, int registryIntervalSeconds = 5)
        {
            int fallback = defaultIntervalSeconds > 0 ? defaultIntervalSeconds : 60;
            if (serializerName == "registryserializer" && registryIntervalSeconds > 0)
            {
                return registryIntervalSeconds;
            }
            if (serializerName == "fileserializer" && fileIntervalSeconds > 0)
            {
                return fileIntervalSeconds;
            }

            return fallback;
        }

        internal static bool ShouldRequestHighWaterFlush(string serializerName, long queueDepth, int highWaterEvents, bool configured = false)
        {
            return (configured || serializerName == "fileserializer" || serializerName == "registryserializer") && highWaterEvents > 0 && queueDepth >= highWaterEvents;
        }

        internal static int ResolveHighWaterEvents(int configured, int queueCapacity)
        {
            // Preserve an explicit disable, otherwise reserve half the bounded queue
            // for arrivals while the drain worker is being scheduled.
            if (configured <= 0) return 0;
            return queueCapacity > 0 ? System.Math.Min(configured, System.Math.Max(1, queueCapacity / 2)) : configured;
        }

        internal static int ResolveQueueCapacity(int? configured, int inherited)
        {
            return configured.GetValueOrDefault() > 0 ? configured.Value : inherited;
        }
    }
}
