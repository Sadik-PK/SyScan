namespace SyScan.Core.Entities;

public enum ScanStatus
{
    Created = 0,
    Invited = 1,
    Opened = 2,
    Connected = 3,
    AwaitingConsent = 4,
    Declined = 5,
    Scanning = 6,
    Uploading = 7,
    Completed = 8,
    Interrupted = 9,
    Cancelled = 10,
    Expired = 11,
    Failed = 12
}

public class ScanSession : BaseEntity
{
    /// <summary>Human-readable scan identifier, e.g. SS-8F29A61C.</summary>
    public string ScanId { get; set; } = string.Empty;

    public Guid OrganizationId { get; set; }
    public Organization Organization { get; set; } = null!;

    public Guid CreatedByUserId { get; set; }
    public User CreatedByUser { get; set; } = null!;

    public string ParticipantLabel { get; set; } = string.Empty;
    public string GameId { get; set; } = string.Empty;
    public string ScanProfileId { get; set; } = string.Empty;
    public ScanStatus Status { get; set; } = ScanStatus.Created;

    public string? ScannerSessionToken { get; set; }
    public DateTime? ConnectedAt { get; set; }
    public DateTime? ScanStartedAt { get; set; }
    public DateTime? ScanCompletedAt { get; set; }

    public ScanInvitation? Invitation { get; set; }
    public ScanConfiguration? Configuration { get; set; }
    public ICollection<ScanEvent> Events { get; set; } = new List<ScanEvent>();
    public ICollection<ScanFinding> Findings { get; set; } = new List<ScanFinding>();
    public ICollection<EvidenceRecord> EvidenceRecords { get; set; } = new List<EvidenceRecord>();
    public ICollection<ConsentRecord> ConsentRecords { get; set; } = new List<ConsentRecord>();
    public ScanReport? Report { get; set; }
}

