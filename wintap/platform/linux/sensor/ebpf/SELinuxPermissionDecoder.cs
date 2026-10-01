using gov.llnl.wintap.core.infrastructure;
using System;
using System.Collections.Generic;
using System.IO;

namespace gov.llnl.wintap.platform.linux.collect
{
    internal sealed class SELinuxPermissionDecoder
    {
        private readonly Dictionary<uint, string> _classNames = new Dictionary<uint, string>();
        private readonly Dictionary<string, uint> _classIndexes = new Dictionary<string, uint>(StringComparer.Ordinal);
        private readonly Dictionary<uint, Dictionary<uint, string>> _permissionsByClass = new Dictionary<uint, Dictionary<uint, string>>();

        public int ClassCount => _classNames.Count;

        public int PermissionCount
        {
            get
            {
                int count = 0;
                foreach (Dictionary<uint, string> permissions in _permissionsByClass.Values)
                {
                    count += permissions.Count;
                }
                return count;
            }
        }

        public static SELinuxPermissionDecoder LoadFromSelinuxFs(string root = "/sys/fs/selinux/class")
        {
            var decoder = new SELinuxPermissionDecoder();
            try
            {
                if (!Directory.Exists(root))
                {
                    WintapLogger.Log.Append($"SELinux permission decoder disabled: {root} not found", LogLevel.Warn);
                    return decoder;
                }

                foreach (string classDir in Directory.EnumerateDirectories(root))
                {
                    string className = Path.GetFileName(classDir);
                    string indexPath = Path.Combine(classDir, "index");
                    if (!TryReadUInt(indexPath, out uint classIndex) || classIndex == 0)
                    {
                        continue;
                    }

                    decoder._classNames[classIndex] = className;
                    decoder._classIndexes[className] = classIndex;
                    string permsDir = Path.Combine(classDir, "perms");
                    if (!Directory.Exists(permsDir))
                    {
                        continue;
                    }

                    var permissions = new Dictionary<uint, string>();
                    foreach (string permFile in Directory.EnumerateFiles(permsDir))
                    {
                        if (TryReadUInt(permFile, out uint bitIndex) && bitIndex > 0 && bitIndex <= 32)
                        {
                            permissions[bitIndex - 1] = Path.GetFileName(permFile);
                        }
                    }

                    if (permissions.Count > 0)
                    {
                        decoder._permissionsByClass[classIndex] = permissions;
                    }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"SELinux permission decoder load error: {ex.Message}", LogLevel.Warn);
            }

            return decoder;
        }

        public string GetClassName(uint classIndex)
        {
            return _classNames.TryGetValue(classIndex, out string name) ? name : classIndex.ToString();
        }

        public bool TryGetClassIndex(string className, out uint classIndex)
        {
            classIndex = 0;
            return !string.IsNullOrWhiteSpace(className) && _classIndexes.TryGetValue(className, out classIndex);
        }

        public string DecodePermissions(uint classIndex, uint mask, out uint unknownBits)
        {
            unknownBits = 0;
            if (mask == 0)
            {
                return string.Empty;
            }

            var names = new List<string>();
            _permissionsByClass.TryGetValue(classIndex, out Dictionary<uint, string> permissions);
            for (uint bit = 0; bit < 32; bit++)
            {
                uint bitMask = 1u << (int)bit;
                if ((mask & bitMask) == 0)
                {
                    continue;
                }

                if (permissions != null && permissions.TryGetValue(bit, out string permName))
                {
                    names.Add(permName);
                }
                else
                {
                    unknownBits |= bitMask;
                    names.Add($"0x{bitMask:x}");
                }
            }

            return string.Join(",", names);
        }

        private static bool TryReadUInt(string path, out uint value)
        {
            value = 0;
            try
            {
                string text = File.ReadAllText(path).Trim();
                return uint.TryParse(text, out value);
            }
            catch
            {
                return false;
            }
        }
    }
}
