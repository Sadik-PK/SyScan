using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using SyScan.Scanner.FileSystem;

namespace SyScan.Scanner.Games;

public sealed class R6SiegeProfile : IGameProfile
{
    public string GameId => "r6siege";
    public string GameName => "Tom Clancy's Rainbow Six Siege";

    private static readonly string[] ProxyDllNames = new[]
    {
        "dxgi.dll", "d3d11.dll", "version.dll", "dbghelp.dll", "xinput1_3.dll", "dinput8.dll"
    };

    public Task<GameInvestigationResult> InvestigateAsync(CancellationToken cancellationToken = default)
    {
        var result = new GameInvestigationResult
        {
            GameId = GameId,
            GameName = GameName
        };

        // Probe common install locations
        var searchRoots = new List<string>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "SteamLibrary", "steamapps", "common", "Tom Clancy's Rainbow Six Siege"));
            searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam", "steamapps", "common", "Tom Clancy's Rainbow Six Siege"));
            searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Ubisoft", "Ubisoft Game Launcher", "games", "Tom Clancy's Rainbow Six Siege"));
            searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Ubisoft", "Ubisoft Game Launcher", "games", "Tom Clancy's Rainbow Six Siege"));
        }

        foreach (var candidate in searchRoots)
        {
            if (Directory.Exists(candidate))
            {
                result.GameInstalled = true;
                result.InstallationPaths.Add(candidate);
                InspectSiegeRoot(candidate, result, cancellationToken);
            }
        }

        return Task.FromResult(result);
    }

    private static void InspectSiegeRoot(string rootPath, GameInvestigationResult result, CancellationToken cancellationToken)
    {
        // Check for unsigned DLL proxies placed directly next to RainbowSix.exe
        foreach (var proxyDll in ProxyDllNames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string fullPath = Path.Combine(rootPath, proxyDll);
            if (File.Exists(fullPath))
            {
                var sig = AuthenticodeVerifier.Verify(fullPath);
                // Legitimate Microsoft DXGI / D3D11 DLLs reside in System32, NOT in game directory!
                // Placing them next to game executable is standard DLL hijacking / cheat injection technique
                bool isTrusted = sig.IsSigned && (sig.IsTrustedVendor || (sig.Subject != null && sig.Subject.Contains("Microsoft")));

                if (!isTrusted)
                {
                    result.Findings.Add(new GameFinding
                    {
                        RuleId = "R6_SUSPICIOUS_PROXY_DLL",
                        FindingName = $"Unsigned / Proxy DLL in Siege Directory: {proxyDll}",
                        Description = $"Found proxy DLL '{proxyDll}' in game root directory without valid vendor signature.",
                        Severity = "Critical",
                        ArtifactType = "DllInjection",
                        FilePath = fullPath,
                        TimestampUtc = File.GetLastWriteTimeUtc(fullPath),
                        Metadata = new()
                        {
                            { "IsSigned", sig.IsSigned.ToString() },
                            { "Signer", sig.Subject ?? "Unknown" }
                        }
                    });
                }
            }
        }
    }
}
