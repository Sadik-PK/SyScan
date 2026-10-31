using System;
using System.IO;

namespace SyScan.Scanner.Ntfs;

public sealed class TimestompCheckResult
{
    public string FilePath { get; set; } = string.Empty;
    public bool TimestompDetected { get; set; }
    public string DetectionReason { get; set; } = string.Empty;
    public DateTime CreationTimeUtc { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
    public DateTime? ParentDirectoryCreationUtc { get; set; }
}

public static class TimestompDetector
{
    public static TimestompCheckResult AnalyzeFile(string filePath)
    {
        var result = new TimestompCheckResult { FilePath = filePath };

        if (!File.Exists(filePath))
            return result;

        try
        {
            var fileInfo = new FileInfo(filePath);
            result.CreationTimeUtc = fileInfo.CreationTimeUtc;
            result.LastWriteTimeUtc = fileInfo.LastWriteTimeUtc;

            // Check 1: Zeroed sub-second precision
            // NTFS stores timestamps with 100-nanosecond precision.
            // Tools that call basic APIs or scripts often truncate sub-seconds to 0 milliseconds or 0 ticks below seconds.
            long creationTicks = fileInfo.CreationTimeUtc.Ticks;
            long subSeconds = creationTicks % TimeSpan.TicksPerSecond;

            if (subSeconds == 0 && fileInfo.CreationTimeUtc.Year > 2000)
            {
                result.TimestompDetected = true;
                result.DetectionReason = "Sub-second timestamp precision is completely zeroed (signature of programmatic SetFileTime manipulation).";
                return result;
            }

            // Check 2: File Creation predates parent folder creation significantly
            if (fileInfo.Directory != null && fileInfo.Directory.Exists)
            {
                var dirCreation = fileInfo.Directory.CreationTimeUtc;
                result.ParentDirectoryCreationUtc = dirCreation;

                // If file creation time is older than the parent directory by more than 30 days
                // and file is located in Temp, Downloads, or AppData
                string dirPath = fileInfo.DirectoryName?.ToLowerInvariant() ?? "";
                if ((dirPath.Contains(@"\temp") || dirPath.Contains(@"\downloads")) &&
                    fileInfo.CreationTimeUtc < dirCreation.AddDays(-30))
                {
                    result.TimestompDetected = true;
                    result.DetectionReason = $"File creation time ({fileInfo.CreationTimeUtc:yyyy-MM-dd}) significantly predates containing directory creation ({dirCreation:yyyy-MM-dd}) in ephemeral folder.";
                    return result;
                }
            }

            // Check 3: Impossibly future timestamp
            if (fileInfo.CreationTimeUtc > DateTime.UtcNow.AddHours(2) ||
                fileInfo.LastWriteTimeUtc > DateTime.UtcNow.AddHours(2))
            {
                result.TimestompDetected = true;
                result.DetectionReason = "File timestamp is set to a future date.";
                return result;
            }
        }
        catch
        {
            // Permission or lock error
        }

        return result;
    }
}

