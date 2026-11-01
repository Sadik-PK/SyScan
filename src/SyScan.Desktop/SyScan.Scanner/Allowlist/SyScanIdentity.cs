using System;
using System.IO;

namespace SyScan.Scanner.Allowlist;

public static class SyScanIdentity
{
    private static readonly string[] SyScanFileNames = new[]
    {
        "syscan.exe",
        "syscan.collector.exe",
        "syscan.dll",
        "syscan.scanner.dll",
        "syscan.core.dll",
        "syscan.infrastructure.dll"
    };

    public static bool IsSyScanComponent(string? filePath, string? processName = null)
    {
        if (!string.IsNullOrEmpty(processName))
        {
            string lowerProc = processName.ToLowerInvariant();
            if (lowerProc is "syscan" or "syscan.collector" or "syscan.desktop")
                return true;
        }

        if (!string.IsNullOrEmpty(filePath))
        {
            string fileName = Path.GetFileName(filePath).ToLowerInvariant();
            foreach (var name in SyScanFileNames)
            {
                if (fileName.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check if within running SyScan directory
            string appBase = AppContext.BaseDirectory.TrimEnd('\\', '/');
            if (filePath.StartsWith(appBase, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
