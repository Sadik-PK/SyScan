using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.Games;

public sealed class RobloxProfile : IGameProfile
{
    public string GameId => "roblox";
    public string GameName => "Roblox";

    private static readonly string[] RobloxExecutors = new[]
    {
        "synapse", "krnl", "fluxus", "wave", "solara",
        "delta", "electron", "celery", "swift", "krampus", "oxygen"
    };

    public async Task<GameInvestigationResult> InvestigateAsync(CancellationToken cancellationToken = default)
    {
        var result = new GameInvestigationResult
        {
            GameId = GameId,
            GameName = GameName
        };

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string robloxDir = Path.Combine(localAppData, "Roblox");
        string bloxstrapDir = Path.Combine(localAppData, "Bloxstrap");

        if (Directory.Exists(robloxDir))
        {
            result.GameInstalled = true;
            result.InstallationPaths.Add(robloxDir);
        }

        if (Directory.Exists(bloxstrapDir))
        {
            result.GameInstalled = true;
            result.InstallationPaths.Add(bloxstrapDir);
        }

        if (!result.GameInstalled)
            return result;

        // 1. Check Roblox Versions for proxy DLLs or injector files
        string versionsDir = Path.Combine(robloxDir, "Versions");
        if (Directory.Exists(versionsDir))
        {
            try
            {
                var files = Directory.GetFiles(versionsDir, "*.dll", SearchOption.AllDirectories);
                result.ModsScanned += files.Length;

                foreach (var file in files)
                {
                    string name = Path.GetFileName(file).ToLowerInvariant();
                    foreach (var exec in RobloxExecutors)
                    {
                        if (name.Contains(exec))
                        {
                            result.Findings.Add(new GameFinding
                            {
                                RuleId = "ROBLOX_EXECUTOR_DLL",
                                FindingName = $"Detected Roblox Script Executor: {Path.GetFileName(file)}",
                                Description = $"Identified known executor binary in Roblox installation: '{exec}'",
                                Severity = "Critical",
                                ArtifactType = "Executor",
                                FilePath = file,
                                TimestampUtc = File.GetLastWriteTimeUtc(file)
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        // 2. Scan Roblox Logs
        string logsDir = Path.Combine(robloxDir, "logs");
        if (Directory.Exists(logsDir))
        {
            try
            {
                var logFiles = Directory.GetFiles(logsDir, "*.log");
                result.LogsScanned += logFiles.Length;

                foreach (var logFile in logFiles)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await ScanLogFileAsync(logFile, result, cancellationToken);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        return result;
    }

    private static async Task ScanLogFileAsync(string filePath, GameInvestigationResult result, CancellationToken cancellationToken)
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
                string lower = line.ToLowerInvariant();
                foreach (var exec in RobloxExecutors)
                {
                    if (lower.Contains(exec))
                    {
                        result.Findings.Add(new GameFinding
                        {
                            RuleId = "ROBLOX_LOG_EXECUTOR",
                            FindingName = $"Roblox Executor Log Signature: {exec}",
                            Description = $"Roblox client log recorded trace of script executor activity: '{line.Trim()}'",
                            Severity = "High",
                            ArtifactType = "Log",
                            FilePath = filePath,
                            Metadata = new() { { "LineNumber", lineNum.ToString() }, { "Snippet", line.Trim() } }
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

