namespace SyScan.Core.Entities;

public class DetectionRule : BaseEntity
{
    public string RuleId { get; set; } = string.Empty;  // e.g. DET-001
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; }
    public int DefaultConfidence { get; set; }

    /// <summary>JSON array of applicable game IDs, or ["*"] for all.</summary>
    public string SupportedGames { get; set; } = "[\"*\"]";

    /// <summary>e.g. SHA256, YARA, Heuristic, FilePath</summary>
    public string RuleType { get; set; } = string.Empty;

    /// <summary>Rule logic payload (hash, YARA rule text, etc.)</summary>
    public string RuleContent { get; set; } = string.Empty;

    public string? FalsePositiveNotes { get; set; }
    public bool IsActive { get; set; } = true;
    public int Version { get; set; } = 1;

    public ICollection<DetectionRuleVersion> Versions { get; set; } = new List<DetectionRuleVersion>();
    public ICollection<ScanFinding> Findings { get; set; } = new List<ScanFinding>();
}

