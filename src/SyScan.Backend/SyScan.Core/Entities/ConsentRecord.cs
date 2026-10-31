namespace SyScan.Core.Entities;

public class ConsentRecord : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    /// <summary>Hash of the configuration at time of consent. If config changes, new consent required.</summary>
    public string ConfigurationHash { get; set; } = string.Empty;

    public bool Approved { get; set; }
    public DateTime DecidedAt { get; set; } = DateTime.UtcNow;

    /// <summary>IP address recorded at consent time.</summary>
    public string? ParticipantIp { get; set; }

    public string? DeclineReason { get; set; }
}

