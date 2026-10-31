using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.Games;

public sealed class MinecraftProfile : IGameProfile
{
    public string GameId => "minecraft";
    public string GameName => "Minecraft";

    private static readonly string[] SuspiciousKeywords = new[]
    {
        "vape", "drip", "raven", "liquidbounce", "wurst", "meteor",
        "inertia", "aristois", "sigma", "koid", "whiteout", "entropy",
        "prestige", "doomsday", "tuke", "autoclicker", "reach", "velocity"
    };

    public async Task<GameInvestigationResult> InvestigateAsync(CancellationToken cancellationToken = default)
    {
        var result = new GameInvestigationResult
        {
            GameId = GameId,
            GameName = GameName
        };

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var candidateDirs = new List<string>
        {
            Path.Combine(appData, ".minecraft"),
            Path.Combine(userProfile, ".lunarclient"),
            Path.Combine(appData, ".feather"),
            Path.Combine(appData, "PrismLauncher"),
            Path.Combine(appData, ".technic")
        };

        foreach (var dir in candidateDirs)
        {
            if (Directory.Exists(dir))
            {
                result.GameInstalled = true;
                result.InstallationPaths.Add(dir);
            }
        }

        if (!result.GameInstalled)
            return result;

        string mcDir = Path.Combine(appData, ".minecraft");
        if (Directory.Exists(mcDir))
        {
            // 1. Inspect Mods Directory
            string modsDir = Path.Combine(mcDir, "mods");
            if (Directory.Exists(modsDir))
            {
                try
                {
                    var modFiles = Directory.GetFiles(modsDir, "*.jar", SearchOption.AllDirectories);
                    result.ModsScanned += modFiles.Length;

                    foreach (var modFile in modFiles)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string fileName = Path.GetFileName(modFile).ToLowerInvariant();

                        foreach (var kw in SuspiciousKeywords)
                        {
                            if (fileName.Contains(kw))
                            {
                                result.Findings.Add(new GameFinding
                                {
                                    RuleId = "MC_SUSPICIOUS_MOD_NAME",
                                    FindingName = $"Detected Cheat Mod: {Path.GetFileName(modFile)}",
                                    Description = $"Mod filename matches known Minecraft blacklisted client/cheat signature: '{kw}'",
                                    Severity = "High",
                                    ArtifactType = "Mod",
                                    FilePath = modFile,
                                    TimestampUtc = File.GetLastWriteTimeUtc(modFile)
                                });
                                break;
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            // 2. Inspect Logs & Decompress .log.gz
            string logsDir = Path.Combine(mcDir, "logs");
            if (Directory.Exists(logsDir))
            {
                await ScanLogsDirectoryAsync(logsDir, result, cancellationToken);
            }
        }

        return result;
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

