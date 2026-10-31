using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SyScan.Scanner.Games;

public sealed class GameFinding
{
    public string RuleId { get; set; } = string.Empty;
    public string FindingName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = "High"; // Low, Medium, High, Critical
    public string ArtifactType { get; set; } = string.Empty; // Mod, Log, JavaAgent, DllInjection, Executor
    public string FilePath { get; set; } = string.Empty;
    public DateTime? TimestampUtc { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public sealed class GameInvestigationResult
{
    public string GameName { get; set; } = string.Empty;
    public string GameId { get; set; } = string.Empty;
    public bool GameInstalled { get; set; }
    public List<string> InstallationPaths { get; set; } = new();
    public List<GameFinding> Findings { get; set; } = new();
    public int LogsScanned { get; set; }
    public int ModsScanned { get; set; }
    public int SuspiciousItemsCount => Findings.Count;
}

public interface IGameProfile
{
    string GameId { get; }
    string GameName { get; }
    Task<GameInvestigationResult> InvestigateAsync(CancellationToken cancellationToken = default);
}

