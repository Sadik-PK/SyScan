using System;
using System.Collections.Generic;
using System.IO;

namespace SyScan.Scanner.Historical;

public sealed class SrumRecord
{
    public string ApplicationId { get; set; } = string.Empty;
    public string AppName { get; set; } = string.Empty;
    public DateTime? TimestampUtc { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public long CpuCycles { get; set; }
    public TimeSpan ForegroundDuration { get; set; }
    public bool IsSuspicious { get; set; }
}

public sealed class SrumInvestigationResult
{
    public bool SrumDatabaseAccessible { get; set; }
    public string DatabasePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTime? LastModifiedUtc { get; set; }
    public List<SrumRecord> Records { get; set; } = new();
    public string StatusMessage { get; set; } = string.Empty;
}

public static class SrumParser
{
    public static SrumInvestigationResult Analyze(string? srumDbPath = null)
    {
        string path = srumDbPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"sru\SRUDB.dat");

        var result = new SrumInvestigationResult
        {
            DatabasePath = path
        };

        if (!File.Exists(path))
        {
            result.SrumDatabaseAccessible = false;
            result.StatusMessage = "SRUM database (SRUDB.dat) not present or accessible.";
            return result;
        }

        try
        {
            var info = new FileInfo(path);
            result.FileSizeBytes = info.Length;
            result.LastModifiedUtc = info.LastWriteTimeUtc;
            result.SrumDatabaseAccessible = true;
            result.StatusMessage = $"SRUM database verified ({info.Length:N0} bytes, Last modified: {info.LastWriteTimeUtc:u}).";

            // If file can be opened for shared read, inspect ESE headers
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] header = new byte[16];
            int read = fs.Read(header, 0, header.Length);

            // ESE Magic is 0x89abcdef at offset 4
            if (read >= 8)
            {
                uint magic = BitConverter.ToUInt32(header, 4);
                if (magic == 0x89abcdef)
                {
                    result.StatusMessage += " Valid Extensible Storage Engine (ESE) database signature confirmed.";
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            result.SrumDatabaseAccessible = false;
            result.StatusMessage = "SRUM database exists but requires Windows Administrator privileges to inspect.";
        }
        catch (Exception ex)
        {
            result.SrumDatabaseAccessible = false;
            result.StatusMessage = $"SRUM access error: {ex.Message}";
        }

        return result;
    }
}

