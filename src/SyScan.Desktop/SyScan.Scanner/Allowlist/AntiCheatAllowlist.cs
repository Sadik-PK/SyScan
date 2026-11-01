using System;
using System.IO;
using SyScan.Scanner.FileSystem;

namespace SyScan.Scanner.Allowlist;

public static class AntiCheatAllowlist
{
    private static readonly string[] KnownAntiCheatServiceNames = new[]
    {
        "easyanticheat",
        "easyanticheat_eos",
        "easyanticheatsys",
        "beservice",
        "battleye",
        "bedaisy",
        "vgc",
        "vgk",
        "ricochet",
        "bhmd"
    };

    private static readonly string[] KnownAntiCheatPublishers = new[]
    {
        "EasyAntiCheat",
        "Epic Games Inc",
        "BattlEye Innovations",
        "Riot Games, Inc.",
        "Riot Games",
        "Activision Publishing, Inc."
    };

    public static bool IsLegitimateAntiCheatService(string serviceName, string displayName, string imagePath)
    {
        string lowerSvc = serviceName.ToLowerInvariant();
        string lowerDisplay = displayName.ToLowerInvariant();
        string lowerPath = imagePath.ToLowerInvariant();

        foreach (var name in KnownAntiCheatServiceNames)
        {
            if (lowerSvc.Equals(name, StringComparison.OrdinalIgnoreCase) ||
                lowerSvc.StartsWith(name + "_", StringComparison.OrdinalIgnoreCase) ||
                lowerDisplay.Contains(name, StringComparison.OrdinalIgnoreCase))
            {
                // Validate expected legitimate paths (Program Files, Common Files, System32)
                if (lowerPath.Contains(@"\program files") ||
                    lowerPath.Contains(@"\common files\easyanticheat") ||
                    lowerPath.Contains(@"\system32\drivers\"))
                {
                    return true;
                }

                // If path exists, check signature
                string cleanPath = ExtractExecutablePath(imagePath);
                if (File.Exists(cleanPath))
                {
                    var sig = AuthenticodeVerifier.Verify(cleanPath);
                    if (sig.IsSigned && (sig.IsTrustedVendor || IsAntiCheatPublisher(sig.Subject)))
                    {
                        return true;
                    }
                }
                else
                {
                    // Clean service definition matching expected service names
                    return true;
                }
            }
        }

        return false;
    }

    public static bool IsLegitimateAntiCheatDriver(string driverName, string driverPath)
    {
        string lowerName = driverName.ToLowerInvariant();
        if (lowerName is "easyanticheat.sys" or "easyanticheat_eos.sys" or "bedaisy.sys" or "vgk.sys")
        {
            if (File.Exists(driverPath))
            {
                var sig = AuthenticodeVerifier.Verify(driverPath);
                if (sig.IsSigned && (sig.IsTrustedVendor || IsAntiCheatPublisher(sig.Subject)))
                    return true;
            }
            return true;
        }

        return false;
    }

    private static bool IsAntiCheatPublisher(string? subject)
    {
        if (string.IsNullOrEmpty(subject)) return false;
        foreach (var pub in KnownAntiCheatPublishers)
        {
            if (subject.Contains(pub, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string ExtractExecutablePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return string.Empty;
        string trimmed = rawPath.Trim();
        if (trimmed.StartsWith("\"") && trimmed.IndexOf("\"", 1) > 0)
        {
            return trimmed.Substring(1, trimmed.IndexOf("\"", 1) - 1);
        }
        int spaceIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (spaceIdx > 0)
        {
            return trimmed.Substring(0, spaceIdx + 4).Trim('"');
        }
        return trimmed;
    }
}
