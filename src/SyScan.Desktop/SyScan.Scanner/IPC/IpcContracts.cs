using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SyScan.Scanner.IPC;

public static class IpcCommands
{
    public const string Ping = "Ping";
    public const string GetRecon = "GetRecon";
    public const string ScanPrefetch = "ScanPrefetch";
    public const string ScanAmcache = "ScanAmcache";
    public const string ScanShimcache = "ScanShimcache";
    public const string ScanBamDam = "ScanBamDam";
    public const string ScanSrum = "ScanSrum";
    public const string ScanEventLogs = "ScanEventLogs";
    public const string ScanUsnJournal = "ScanUsnJournal";
    public const string ScanServicesAndDrivers = "ScanServicesAndDrivers";
    public const string ScanProcesses = "ScanProcesses";
    public const string InventoryDrives = "InventoryDrives";
    public const string Shutdown = "Shutdown";
}

public sealed class CollectorRequest
{
    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("sessionNonce")]
    public string SessionNonce { get; set; } = string.Empty;

    [JsonPropertyName("scanSessionId")]
    public string ScanSessionId { get; set; } = string.Empty;

    [JsonPropertyName("command")]
    public string Command { get; set; } = string.Empty;

    [JsonPropertyName("parameters")]
    public Dictionary<string, string> Parameters { get; set; } = new();
}

public sealed class CollectorResponse
{
    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("isElevated")]
    public bool IsElevated { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "Completed";

    [JsonPropertyName("recordsCount")]
    public int RecordsCount { get; set; }

    [JsonPropertyName("dataJson")]
    public string DataJson { get; set; } = string.Empty;

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }
}

public sealed class SystemReconData
{
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public string CurrentUserSid { get; set; } = string.Empty;
    public string CurrentUserName { get; set; } = string.Empty;
    public bool IsAdministrator { get; set; }
    public List<DriveReconInfo> Drives { get; set; } = new();
    public List<string> UserProfiles { get; set; } = new();
    public DateTime BootTimeUtc { get; set; }
    public string ScannerVersion { get; set; } = "2.2.0";
    public string DetectionRuleVersion { get; set; } = "2026.11.01";
}

public sealed class DriveReconInfo
{
    public string Name { get; set; } = string.Empty;
    public string VolumeLabel { get; set; } = string.Empty;
    public string DriveFormat { get; set; } = string.Empty;
    public long TotalSizeBytes { get; set; }
    public long AvailableFreeBytes { get; set; }
    public bool IsReady { get; set; }
}
