using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SyScan.Scanner.Historical;

public sealed class JumpListEntry
{
    public string SourceFile { get; set; } = string.Empty;
    public string TargetPath { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
    public string WorkingDirectory { get; set; } = string.Empty;
    public DateTime? TargetCreatedUtc { get; set; }
    public DateTime? TargetModifiedUtc { get; set; }
    public DateTime? TargetAccessedUtc { get; set; }
    public long FileSizeBytes { get; set; }
    public bool IsSuspicious { get; set; }
    public bool IsInformational { get; set; } = true;
}

public static class JumpListParser
{
    // LNK Header CLSID: {00021401-0000-0000-C000-000000000046}
    private static readonly byte[] LnkGuid = new byte[] {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".asi"
    };

    private static readonly string[] SuspiciousCheatKeywords = new[]
    {
        "vape", "drip", "cheat", "injector", "aimbot", "redengine", "eulen",
        "hammafia", "kiddions", "spoofer", "bypass"
    };

    public static List<JumpListEntry> ParseStreamOrFile(byte[] data, string sourcePath = "")
    {
        var results = new List<JumpListEntry>();
        if (data == null || data.Length < 76)
            return results;

        int offset = 0;
        while (offset <= data.Length - 76)
        {
            if (BitConverter.ToUInt32(data, offset) == 0x4C)
            {
                bool guidMatch = true;
                for (int g = 0; g < 16; g++)
                {
                    if (data[offset + 4 + g] != LnkGuid[g])
                    {
                        guidMatch = false;
                        break;
                    }
                }

                if (guidMatch)
                {
                    try
                    {
                        var entry = ParseLnkHeader(data, offset, sourcePath);
                        if (entry != null && !string.IsNullOrWhiteSpace(entry.TargetPath))
                        {
                            results.Add(entry);
                        }
                    }
                    catch { }
                }
            }

            offset++;
        }

        return results;
    }

    private static JumpListEntry? ParseLnkHeader(byte[] data, int start, string sourcePath)
    {
        if (start + 76 > data.Length)
            return null;

        uint flags = BitConverter.ToUInt32(data, start + 0x14);
        long createdFt = BitConverter.ToInt64(data, start + 0x1C);
        long accessedFt = BitConverter.ToInt64(data, start + 0x24);
        long modifiedFt = BitConverter.ToInt64(data, start + 0x2C);
        uint fileSize = BitConverter.ToUInt32(data, start + 0x34);

        DateTime? cTime = createdFt > 0 ? SafeFileTime(createdFt) : null;
        DateTime? aTime = accessedFt > 0 ? SafeFileTime(accessedFt) : null;
        DateTime? mTime = modifiedFt > 0 ? SafeFileTime(modifiedFt) : null;

        var entry = new JumpListEntry
        {
            SourceFile = sourcePath,
            TargetCreatedUtc = cTime,
            TargetAccessedUtc = aTime,
            TargetModifiedUtc = mTime,
            FileSizeBytes = fileSize,
            IsInformational = true,
            IsSuspicious = false
        };

        int curr = start + 76;

        // HasLinkTargetIDList = 0x01
        if ((flags & 0x01) != 0 && curr + 2 <= data.Length)
        {
            ushort idListSize = BitConverter.ToUInt16(data, curr);
            curr += 2 + idListSize;
        }

        // HasLinkInfo = 0x02
        if ((flags & 0x02) != 0 && curr + 4 <= data.Length)
        {
            int linkInfoSize = BitConverter.ToInt32(data, curr);
            if (linkInfoSize >= 28 && curr + linkInfoSize <= data.Length)
            {
                int localBasePathOffset = BitConverter.ToInt32(data, curr + 16);
                if (localBasePathOffset > 0 && curr + localBasePathOffset < data.Length)
                {
                    string path = ReadNullTerminatedAscii(data, curr + localBasePathOffset);
                    entry.TargetPath = path;
                }

                int headerSize = BitConverter.ToInt32(data, curr + 4);
                if (headerSize >= 36 && curr + 32 <= data.Length)
                {
                    int localBasePathOffsetUnicode = BitConverter.ToInt32(data, curr + 28);
                    if (localBasePathOffsetUnicode > 0 && curr + localBasePathOffsetUnicode + 2 < data.Length)
                    {
                        string uPath = ReadNullTerminatedUnicode(data, curr + localBasePathOffsetUnicode);
                        if (!string.IsNullOrWhiteSpace(uPath))
                        {
                            entry.TargetPath = uPath;
                        }
                    }
                }

                curr += linkInfoSize;
            }
        }

        if (string.IsNullOrWhiteSpace(entry.TargetPath) && curr < data.Length)
        {
            int scanLen = Math.Min(data.Length - curr, 1024);
            string remainderAscii = Encoding.ASCII.GetString(data, curr, scanLen);
            int driveIdx = remainderAscii.IndexOf(@":\", StringComparison.Ordinal);
            if (driveIdx > 0)
            {
                char driveLetter = remainderAscii[driveIdx - 1];
                if (char.IsLetter(driveLetter))
                {
                    int endIdx = remainderAscii.IndexOf('\0', driveIdx);
                    if (endIdx > driveIdx)
                    {
                        entry.TargetPath = driveLetter + remainderAscii.Substring(driveIdx, endIdx - driveIdx);
                    }
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(entry.TargetPath))
        {
            string ext = Path.GetExtension(entry.TargetPath).ToLowerInvariant();
            string lower = entry.TargetPath.ToLowerInvariant();

            // ONLY mark as suspicious if the target is an executable/script/driver AND contains cheat keywords
            if (ExecutableExtensions.Contains(ext))
            {
                foreach (var kw in SuspiciousCheatKeywords)
                {
                    if (lower.Contains(kw))
                    {
                        entry.IsSuspicious = true;
                        entry.IsInformational = false;
                        break;
                    }
                }
            }
            else
            {
                // Normal documents, PDFs, media, text files are strictly informational
                entry.IsSuspicious = false;
                entry.IsInformational = true;
            }
        }

        return entry;
    }

    private static string ReadNullTerminatedAscii(byte[] data, int start)
    {
        int end = start;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, start, end - start);
    }

    private static string ReadNullTerminatedUnicode(byte[] data, int start)
    {
        int end = start;
        while (end + 1 < data.Length && !(data[end] == 0 && data[end + 1] == 0)) end += 2;
        return Encoding.Unicode.GetString(data, start, end - start);
    }

    private static DateTime? SafeFileTime(long ft)
    {
        try { return DateTime.FromFileTimeUtc(ft); } catch { return null; }
    }

    public static List<JumpListEntry> ScanRecentDestinations()
    {
        var rawResults = new List<JumpListEntry>();
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string recent = Path.Combine(appData, @"Microsoft\Windows\Recent");

        if (!Directory.Exists(recent))
            return rawResults;

        string[] targets = new[]
        {
            recent,
            Path.Combine(recent, "AutomaticDestinations"),
            Path.Combine(recent, "CustomDestinations")
        };

        foreach (var dir in targets)
        {
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir))
                {
                    try
                    {
                        byte[] bytes = File.ReadAllBytes(file);
                        var parsed = ParseStreamOrFile(bytes, file);
                        rawResults.AddRange(parsed);
                    }
                    catch { }
                }
            }
            catch { }
        }

        // Deduplicate entries by target path to avoid inflating counts
        var deduplicated = new List<JumpListEntry>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in rawResults)
        {
            if (string.IsNullOrWhiteSpace(entry.TargetPath)) continue;
            if (seenPaths.Add(entry.TargetPath))
            {
                deduplicated.Add(entry);
            }
        }

        return deduplicated;
    }
}
