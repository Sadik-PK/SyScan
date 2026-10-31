namespace SyScan.Core.Entities;

public class DetectionRuleVersion : BaseEntity
{
    public Guid DetectionRuleId { get; set; }
    public DetectionRule DetectionRule { get; set; } = null!;

    public int Version { get; set; }
    public string RuleContent { get; set; } = string.Empty;
    public string ChangeSummary { get; set; } = string.Empty;
    public Guid ChangedByUserId { get; set; }
}

