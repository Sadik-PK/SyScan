using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using SyScan.Scanner.FileSystem;

namespace SyScan.Scanner.Games;

public sealed class MinecraftProfile : IGameProfile
{
    public string GameId => "minecraft";
    public string GameName => "Minecraft";

    private static readonly string[] SuspiciousKeywords = new[]
    {
        "vape", "drip", "raven", "liquidbounce", "wurst", "meteor",
        "inertia", "aristois", "sigma", "koid", "whiteout", "entropy",
        "prestige", "doomsday", "tuke", "autoclicker", "reach", "velocity",
        "bleachhack", "baritone"
    };

    public async Task<GameInvestigationResult> InvestigateAsync(CancellationToken cancellationToken = default)
    {
        var result = new GameInvestigationResult
        {
            GameId = GameId,
            GameName = GameName
        };

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var candidateDirs = new List<string>
        {
            Path.Combine(appData, ".minecraft"),
            Path.Combine(userProfile, ".lunarclient"),
            Path.Combine(appData, ".feather"),
            Path.Combine(appData, "PrismLauncher"),
            Path.Combine(appData, ".technic"),
            Path.Combine(localAppData, "Programs", "Modrinth App"),
            Path.Combine(userProfile, "curseforge", "minecraft"),
            // Also inspect user Downloads and Desktop for stored Minecraft utility clients
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop")
        };

        foreach (var dir in candidateDirs)
        {
            if (Directory.Exists(dir))
            {
                result.GameInstalled = true;
                result.InstallationPaths.Add(dir);
            }
        }

        // 1. Inspect all discovered directories for JAR files (mods, loaders, downloaded clients)
        foreach (var dir in result.InstallationPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await InspectJarDirectoryAsync(dir, result, cancellationToken);
        }

        // 2. Inspect Logs & Decompress .log.gz
        string mcDir = Path.Combine(appData, ".minecraft");
        if (Directory.Exists(mcDir))
        {
            string logsDir = Path.Combine(mcDir, "logs");
            if (Directory.Exists(logsDir))
            {
                await ScanLogsDirectoryAsync(logsDir, result, cancellationToken);
            }
        }

        return result;
    }

    private async Task InspectJarDirectoryAsync(string dir, GameInvestigationResult result, CancellationToken ct)
    {
        string[] jarFiles;
        try
        {
            // If scanning Downloads or Desktop, search top directory only to prevent infinite crawl
            var searchOption = (dir.EndsWith("Downloads", StringComparison.OrdinalIgnoreCase) ||
                                dir.EndsWith("Desktop", StringComparison.OrdinalIgnoreCase))
                ? SearchOption.TopDirectoryOnly
                : SearchOption.AllDirectories;

            jarFiles = Directory.GetFiles(dir, "*.jar", searchOption);
        }
        catch
        {
            return;
        }

        result.ModsScanned += jarFiles.Length;

        foreach (var jarFile in jarFiles)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // Perform deep Jar analysis (manifest, fabric.mod.json, packages)
                var jarAnalysis = JarAnalyzer.AnalyzeJar(jarFile);

                if (jarAnalysis.IsKnownCheatClient)
                {
                    bool inDownloads = jarFile.Contains(@"\downloads\", StringComparison.OrdinalIgnoreCase);
                    bool inDesktop = jarFile.Contains(@"\desktop\", StringComparison.OrdinalIgnoreCase);
                    string locationContext = inDownloads
                        ? "Found on disk (in Downloads directory)"
                        : inDesktop
                            ? "Found on disk (in Desktop directory)"
                            : "Installed in game mod directory";

                    result.Findings.Add(new GameFinding
                    {
                        RuleId = "MC_KNOWN_UTILITY_CLIENT",
                        FindingName = $"Known Minecraft Utility Client: {jarAnalysis.KnownClientName ?? "Meteor Client"}",
                        Description = $"{jarAnalysis.DetectionReason}. Location: {locationContext} ({jarFile}).",
                        Severity = "Critical",
                        ArtifactType = "ModJar",
                        FilePath = jarFile,
                        TimestampUtc = File.GetLastWriteTimeUtc(jarFile),
                        Metadata = new Dictionary<string, string>
                        {
                            { "Sha256", jarAnalysis.Sha256Hash },
                            { "ClientName", jarAnalysis.KnownClientName ?? "Meteor Client" },
                            { "DiscoveryContext", locationContext },
                            { "MainClass", jarAnalysis.MainClass ?? "N/A" },
                            { "Version", jarAnalysis.MinecraftMod?.Version ?? "N/A" }
                        }
                    });
                }
                else
                {
                    // Fallback to name heuristic for suspicious keywords if jar analysis didn't flag it
                    string fileName = Path.GetFileName(jarFile).ToLowerInvariant();
                    foreach (var kw in SuspiciousKeywords)
                    {
                        if (fileName.Contains(kw))
                        {
                            result.Findings.Add(new GameFinding
                            {
                                RuleId = "MC_SUSPICIOUS_MOD_NAME",
                                FindingName = $"Suspicious Minecraft Mod Binary: {Path.GetFileName(jarFile)}",
                                Description = $"Mod filename matches suspicious Minecraft client/cheat keyword: '{kw}'",
                                Severity = "High",
                                ArtifactType = "Mod",
                                FilePath = jarFile,
                                TimestampUtc = File.GetLastWriteTimeUtc(jarFile)
                            });
                            break;
                        }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }

    private async Task ScanLogsDirectoryAsync(string logsDir, GameInvestigationResult result, CancellationToken cancellationToken)
    {
        string[] logFiles;
        try
        {
            logFiles = Directory.GetFiles(logsDir, "*.*");
        }
        catch
        {
            return;
        }

        foreach (var logFile in logFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string ext = Path.GetExtension(logFile).ToLowerInvariant();

            if (ext == ".log" || ext == ".txt")
            {
                result.LogsScanned++;
                await ScanPlainLogAsync(logFile, result, cancellationToken);
            }
            else if (ext == ".gz")
            {
                result.LogsScanned++;
                await ScanGzLogAsync(logFile, result, cancellationToken);
            }
        }
    }

    private async Task ScanPlainLogAsync(string filePath, GameInvestigationResult result, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            string? line;
            int lineNum = 0;

            while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
            {
                lineNum++;
                CheckLogLine(line, filePath, lineNum, result);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task ScanGzLogAsync(string filePath, GameInvestigationResult result, CancellationToken cancellationToken)
    {
        try
        {
            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var gzStream = new GZipStream(fileStream, CompressionMode.Decompress);
            using var reader = new StreamReader(gzStream);
            string? line;
            int lineNum = 0;

            while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
            {
                lineNum++;
                CheckLogLine(line, filePath, lineNum, result);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static void CheckLogLine(string line, string sourceFile, int lineNum, GameInvestigationResult result)
    {
        string lower = line.ToLowerInvariant();

        // Check for Java Agent injection
        if (lower.Contains("-javaagent:") || lower.Contains("agentpath") || lower.Contains("instrumentation"))
        {
            // Ignore legitimate agents like telemetry or profiling if clean
            if (lower.Contains("vape") || lower.Contains("cheat") || lower.Contains("temp") || lower.Contains(".tmp"))
            {
                result.Findings.Add(new GameFinding
                {
                    RuleId = "MC_SUSPICIOUS_JAVA_AGENT",
                    FindingName = "Suspicious Java Agent Injection Detected",
                    Description = $"Log entry indicates JVM launched with suspicious agent parameter: '{line.Trim()}'",
                    Severity = "Critical",
                    ArtifactType = "JavaAgent",
                    FilePath = sourceFile,
                    Metadata = new() { { "LineNumber", lineNum.ToString() }, { "Snippet", line.Trim() } }
                });
                return;
            }
        }

        // Check for Meteor Client / utility client loaded in logs
        if (lower.Contains("meteor-client") || lower.Contains("meteor client") || lower.Contains("meteordevelopment"))
        {
            result.Findings.Add(new GameFinding
            {
                RuleId = "MC_LOG_METEOR_CLIENT",
                FindingName = "Observed Meteor Client Loaded in Game Runtime Log",
                Description = $"Historical log entry confirms Meteor Client was actively executed: '{line.Trim()}'",
                Severity = "Critical",
                ArtifactType = "Log",
                FilePath = sourceFile,
                Metadata = new() { { "LineNumber", lineNum.ToString() }, { "Snippet", line.Trim() } }
            });
            return;
        }

        foreach (var kw in SuspiciousKeywords)
        {
            if (lower.Contains(kw) && (lower.Contains("injected") || lower.Contains("hooked") || lower.Contains("module") || lower.Contains("loaded")))
            {
                result.Findings.Add(new GameFinding
                {
                    RuleId = "MC_LOG_CHEAT_EVIDENCE",
                    FindingName = $"Cheat Signature in Historical Log: {kw}",
                    Description = $"Found historical evidence of '{kw}' injection in game log: '{line.Trim()}'",
                    Severity = "High",
                    ArtifactType = "Log",
                    FilePath = sourceFile,
                    Metadata = new() { { "LineNumber", lineNum.ToString() }, { "Snippet", line.Trim() } }
                });
                break;
            }
        }
    }
}
