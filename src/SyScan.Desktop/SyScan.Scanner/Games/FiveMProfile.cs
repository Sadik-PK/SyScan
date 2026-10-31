using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.Games;

public sealed class FiveMProfile : IGameProfile
{
    public string GameId => "fivem";
    public string GameName => "FiveM (Grand Theft Auto V)";

    private static readonly string[] FivemCheatSignatures = new[]
    {
        "eulen", "redengine", "hammafia", "skript", "nexus",
        "hoppam", "desudo", "dopamine", "lynx", "lux", "tiago"
    };

    public async Task<GameInvestigationResult> InvestigateAsync(CancellationToken cancellationToken = default)
    {
        var result = new GameInvestigationResult
        {
            GameId = GameId,
            GameName = GameName
        };

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string fivemRoot = Path.Combine(localAppData, "FiveM", "FiveM.app");

        if (!Directory.Exists(fivemRoot))
        {
            return result;
        }

        result.GameInstalled = true;
        result.InstallationPaths.Add(fivemRoot);

        // 1. Inspect plugins and mods directories
        string pluginsDir = Path.Combine(fivemRoot, "plugins");
        string modsDir = Path.Combine(fivemRoot, "mods");

        InspectFolderForDlls(pluginsDir, "FiveM Plugins", result);
        InspectFolderForDlls(modsDir, "FiveM Mods", result);

        // 2. Inspect CitizenFX_log.log
        string mainLog = Path.Combine(fivemRoot, "CitizenFX_log.log");
        if (File.Exists(mainLog))
        {
            result.LogsScanned++;
            await ScanLogFileAsync(mainLog, result, cancellationToken);
        }

        string logsSubdir = Path.Combine(fivemRoot, "logs");
        if (Directory.Exists(logsSubdir))
        {
            try
            {
                foreach (var log in Directory.GetFiles(logsSubdir, "*.log"))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result.LogsScanned++;
                    await ScanLogFileAsync(log, result, cancellationToken);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        return result;
    }

    private static void InspectFolderForDlls(string dirPath, string category, GameInvestigationResult result)
    {
        if (!Directory.Exists(dirPath)) return;

        try
        {
            var files = Directory.GetFiles(dirPath, "*.asi", SearchOption.AllDirectories);
            var dlls = Directory.GetFiles(dirPath, "*.dll", SearchOption.AllDirectories);

            var all = new List<string>(files);
            all.AddRange(dlls);

            result.ModsScanned += all.Count;

            foreach (var file in all)
            {
                string name = Path.GetFileName(file).ToLowerInvariant();
                foreach (var sig in FivemCheatSignatures)
                {
                    if (name.Contains(sig))
                    {
                        result.Findings.Add(new GameFinding
                        {
                            RuleId = "FIVEM_UNAPPROVED_MODULE",
                            FindingName = $"Detected Cheat Module: {Path.GetFileName(file)}",
                            Description = $"Known GTA V / FiveM cheat signature detected in {category}: '{sig}'",
                            Severity = "Critical",
                            ArtifactType = "DllInjection",
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
                foreach (var sig in FivemCheatSignatures)
                {
                    if (lower.Contains(sig) && (lower.Contains("load") || lower.Contains("inject") || lower.Contains("resource") || lower.Contains("lua")))
                    {
                        result.Findings.Add(new GameFinding
                        {
                            RuleId = "FIVEM_LOG_EVIDENCE",
                            FindingName = $"FiveM Cheat Evidence: {sig}",
                            Description = $"FiveM log indicates cheat module/executor activity: '{line.Trim()}'",
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

