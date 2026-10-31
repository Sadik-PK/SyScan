namespace SyScan.Core.Entities;

public enum FindingSeverity
{
    Information = 0,
    Warning = 1,
    Suspicious = 2,
    Detection = 3,
    Critical = 4
}

public enum FindingCategory
{
    Detection,
    Warning,
    Suspicious,
    Information,
    Integrity
}

public class ScanFinding : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    public string FindingId { get; set; } = string.Empty; // e.g. FND-001
    public Guid? DetectionRuleId { get; set; }
    public DetectionRule? DetectionRule { get; set; }

    public string ModuleId { get; set; } = string.Empty;
    public FindingCategory Category { get; set; }
    public FindingSeverity Severity { get; set; }

    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public string? FilePath { get; set; }
    public string? FileHash { get; set; }
    public DateTime? ArtifactTimestamp { get; set; }

    /// <summary>JSON: supporting artifact references.</summary>
    public string? SupportingArtifacts { get; set; }

    /// <summary>Confidence score 0-100.</summary>
    public int Confidence { get; set; }

    public string? FalsePositiveNotes { get; set; }
    public string? Explanation { get; set; }

    public bool ReviewedByModerator { get; set; } = false;
    public string? ModeratorNotes { get; set; }
}

