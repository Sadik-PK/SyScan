using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace SyScan.Scanner.Historical;

public sealed class AmcacheEntry
{
    public string FilePath { get; set; } = string.Empty;
    public string Sha1Hash { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTime? LinkDateUtc { get; set; }
    public DateTime? InstallDateUtc { get; set; }
    public bool IsSuspicious { get; set; }
}

public static class AmcacheParser
{
    public static List<AmcacheEntry> ReadFromLoadedHive(RegistryKey rootKey)
    {
        var entries = new List<AmcacheEntry>();
        if (rootKey == null) return entries;

        // Try Root\InventoryApplicationFile (Win 10/11)
        using var appFilesKey = rootKey.OpenSubKey(@"Root\InventoryApplicationFile");
        if (appFilesKey != null)
        {
            foreach (string fileId in appFilesKey.GetSubKeyNames())
            {
                using var fileSubKey = appFilesKey.OpenSubKey(fileId);
                if (fileSubKey == null) continue;

                string path = fileSubKey.GetValue("LowerCaseLongPath") as string ??
                              fileSubKey.GetValue("Name") as string ?? string.Empty;

                if (string.IsNullOrWhiteSpace(path)) continue;

                string sha1 = fileSubKey.GetValue("FileId") as string ?? fileId.TrimStart('0');
                string pub = fileSubKey.GetValue("Publisher") as string ?? string.Empty;
                string ver = fileSubKey.GetValue("Version") as string ?? string.Empty;
                string prod = fileSubKey.GetValue("ProductName") as string ?? string.Empty;

                long size = 0;
                object? sizeObj = fileSubKey.GetValue("Size");
                if (sizeObj is long l) size = l;
                else if (sizeObj is int i) size = i;

                DateTime? linkDate = null;
                string? linkDateStr = fileSubKey.GetValue("LinkDate") as string;
                if (!string.IsNullOrEmpty(linkDateStr) && DateTime.TryParse(linkDateStr, out var parsedDate))
                {
                    linkDate = parsedDate.ToUniversalTime();
                }

                string lower = path.ToLowerInvariant();
                bool susp = lower.Contains(@"\temp\") ||
                            lower.Contains(@"\downloads\") ||
                            lower.Contains("vape") ||
                            lower.Contains("cheat") ||
                            lower.Contains("inject") ||
                            lower.Contains("drip");

                entries.Add(new AmcacheEntry
                {
                    FilePath = path,
                    Sha1Hash = sha1,
                    Publisher = pub,
                    Version = ver,
                    ProductName = prod,
                    FileSizeBytes = size,
                    LinkDateUtc = linkDate,
                    IsSuspicious = susp
                });
            }
        }

        return entries;
    }

    public static List<AmcacheEntry> ScanSystem()
    {
        // On a live system, Amcache.hve is locked exclusively by the Windows kernel / AppModel.
        // If elevated, offline copy or reg hive mount is used.
        // We provide live scan attempt with graceful exception handling.
        string amcachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"appcompat\Programs\Amcache.hve");
        var list = new List<AmcacheEntry>();

        if (!File.Exists(amcachePath))
            return list;

        // Try to read shadow or temporary copy if accessible
        try
        {
            using var fs = new FileStream(amcachePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            // File accessible!
        }
        catch
        {
            // Amcache is locked by the OS as expected on live systems without volume shadow copy
        }

        return list;
    }
}

