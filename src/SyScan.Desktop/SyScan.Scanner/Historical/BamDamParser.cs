using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace SyScan.Scanner.Historical;

public sealed class BamDamEntry
{
    public string ExecutablePath { get; set; } = string.Empty;
    public string NormalizedPath { get; set; } = string.Empty;
    public string UserSid { get; set; } = string.Empty;
    public DateTime? LastExecutionUtc { get; set; }
    public string SourceService { get; set; } = "BAM"; // BAM or DAM
    public bool IsSuspicious { get; set; }
}

public static class BamDamParser
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    private static readonly Dictionary<string, string> DeviceToDriveMap = BuildDeviceMap();

    private static Dictionary<string, string> BuildDeviceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                string driveLetter = drive.Name.TrimEnd('\\');
                var sb = new StringBuilder(512);
                if (QueryDosDevice(driveLetter, sb, sb.Capacity) > 0)
                {
                    string target = sb.ToString();
                    if (!string.IsNullOrWhiteSpace(target) && !map.ContainsKey(target))
                    {
                        map[target] = driveLetter;
                    }
                }
            }
        }
        catch
        {
            // Fallback default mapping
            map[@"\Device\HarddiskVolume3"] = "C:";
        }
        return map;
    }

    public static string NormalizeDevicePath(string devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath))
            return string.Empty;

        foreach (var kvp in DeviceToDriveMap)
        {
            if (devicePath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                return kvp.Value + devicePath.Substring(kvp.Key.Length);
            }
        }

        return devicePath;
    }

    public static BamDamEntry? ParseValue(string valueName, byte[] valueData, string sid, string service = "BAM")
    {
        if (string.IsNullOrWhiteSpace(valueName) || valueData == null || valueData.Length < 8)
            return null;

        // Skip non-path values (e.g. "SequenceNumber" or "Version")
        if (valueName.Equals("SequenceNumber", StringComparison.OrdinalIgnoreCase) ||
            valueName.Equals("Version", StringComparison.OrdinalIgnoreCase))
            return null;

        long fileTime = BitConverter.ToInt64(valueData, 0);
        DateTime? execTime = null;
        if (fileTime > 0)
        {
            try { execTime = DateTime.FromFileTimeUtc(fileTime); } catch { }
        }

        string normalized = NormalizeDevicePath(valueName);
        string lower = normalized.ToLowerInvariant();
        bool susp = lower.Contains(@"\temp\") ||
                    lower.Contains(@"\downloads\") ||
                    lower.Contains("vape") ||
                    lower.Contains("cheat") ||
                    lower.Contains("inject") ||
                    lower.Contains("drip") ||
                    lower.Contains("clicker");

        return new BamDamEntry
        {
            ExecutablePath = valueName,
            NormalizedPath = normalized,
            UserSid = sid,
            LastExecutionUtc = execTime,
            SourceService = service,
            IsSuspicious = susp
        };
    }

    public static List<BamDamEntry> ReadFromLiveRegistry()
    {
        var entries = new List<BamDamEntry>();
        string[] services = new[] { "bam", "dam" };

        foreach (var svc in services)
        {
            string rootPath = $@"SYSTEM\CurrentControlSet\Services\{svc}\State\UserSettings";
            try
            {
                using var userSettingsKey = Registry.LocalMachine.OpenSubKey(rootPath);
                if (userSettingsKey == null) continue;

                foreach (string sid in userSettingsKey.GetSubKeyNames())
                {
                    using var sidKey = userSettingsKey.OpenSubKey(sid);
                    if (sidKey == null) continue;

                    foreach (string valName in sidKey.GetValueNames())
                    {
                        var data = sidKey.GetValue(valName) as byte[];
                        if (data != null && data.Length >= 8)
                        {
                            var entry = ParseValue(valName, data, sid, svc.ToUpperInvariant());
                            if (entry != null)
                            {
                                entries.Add(entry);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Key inaccessible
            }
        }

        return entries;
    }
}

