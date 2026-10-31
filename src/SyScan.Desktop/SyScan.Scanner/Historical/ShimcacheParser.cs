using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace SyScan.Scanner.Historical;

public sealed class ShimcacheEntry
{
    public string Path { get; set; } = string.Empty;
    public DateTime? LastModifiedUtc { get; set; }
    public uint DataSize { get; set; }
    public bool Executed { get; set; }
    public string RawSignature { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}

public static class ShimcacheParser
{
    // Common magic bytes for Win10/11 entries: "10ts"
    private static readonly byte[] Signature10ts = new byte[] { (byte)'1', (byte)'0', (byte)'t', (byte)'s' };

    public static List<ShimcacheEntry> Parse(byte[] data)
    {
        var entries = new List<ShimcacheEntry>();
        if (data == null || data.Length < 16)
            return entries;

        int index = 0;
        while (index <= data.Length - 16)
        {
            // Look for "10ts" signature
            if (data[index] == Signature10ts[0] &&
                data[index + 1] == Signature10ts[1] &&
                data[index + 2] == Signature10ts[2] &&
                data[index + 3] == Signature10ts[3])
            {
                try
                {
                    int recordStart = index;
                    // Standard Win10/11 entry:
                    // 0x00: "10ts" (4 bytes)
                    // 0x04: Unknown (4 bytes)
                    // 0x08: Entry size / Data size (4 bytes)
                    // 0x0C: Path length in bytes (2 bytes)
                    // 0x0E: Path string (UTF-16LE, Path length bytes)
                    // After path: Last modified FILETIME (8 bytes)
                    // Flags / Executed (4 bytes)

                    if (recordStart + 14 > data.Length)
                        break;

                    uint dataSize = BitConverter.ToUInt32(data, recordStart + 8);
                    ushort pathLength = BitConverter.ToUInt16(data, recordStart + 12);

                    int pathOffset = recordStart + 14;
                    if (pathLength > 0 && pathLength < 2048 && pathOffset + pathLength <= data.Length)
                    {
                        string path = Encoding.Unicode.GetString(data, pathOffset, pathLength).TrimEnd('\0');

                        DateTime? lastMod = null;
                        int timeOffset = pathOffset + pathLength;
                        if (timeOffset + 8 <= data.Length)
                        {
                            long ft = BitConverter.ToInt64(data, timeOffset);
                            if (ft > 0)
                            {
                                try { lastMod = DateTime.FromFileTimeUtc(ft); } catch { }
                            }
                        }

                        bool executed = false;
                        if (timeOffset + 12 <= data.Length)
                        {
                            uint flags = BitConverter.ToUInt32(data, timeOffset + 8);
                            executed = (flags & 0x02) != 0 || flags != 0;
                        }

                        if (!string.IsNullOrWhiteSpace(path) && (path.Contains('\\') || path.Contains('/')))
                        {
                            string lower = path.ToLowerInvariant();
                            bool susp = lower.Contains(@"\temp\") ||
                                        lower.Contains(@"\downloads\") ||
                                        lower.Contains("vape") ||
                                        lower.Contains("cheat") ||
                                        lower.Contains("inject") ||
                                        lower.Contains("drip");

                            entries.Add(new ShimcacheEntry
                            {
                                Path = path,
                                LastModifiedUtc = lastMod,
                                DataSize = dataSize,
                                Executed = executed,
                                RawSignature = "10ts",
                                IsSuspicious = susp
                            });
                        }

                        // Advance index past this record
                        int advance = 14 + pathLength + 12;
                        if (advance < 16) advance = 16;
                        index += advance;
                        continue;
                    }
                }
                catch
                {
                    // Continue search
                }
            }

            index++;
        }

        return entries;
    }

    public static List<ShimcacheEntry> ReadFromLiveRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
            if (key != null)
            {
                var value = key.GetValue("AppCompatCache") as byte[];
                if (value != null && value.Length > 0)
                {
                    return Parse(value);
                }
            }
        }
        catch
        {
            // Requires admin or key missing
        }

        return new List<ShimcacheEntry>();
    }
}

