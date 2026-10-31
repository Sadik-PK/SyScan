namespace SyScan.Core.Entities;

public enum ScanEventType
{
    SessionCreated,
    InvitationGenerated,
    InvitationOpened,
    ApplicationConnected,
    ApplicationDisconnected,
    ApplicationReconnected,
    ConsentGranted,
    ConsentDeclined,
    ScanStarted,
    ModuleStarted,
    ModuleCompleted,
    ModuleFailed,
    FindingDetected,
    EvidenceUploaded,
    ScanCompleted,
    ScanCancelled,
    ScanFailed,
    ConfigurationChanged,
    ReconsentRequired,
    Warning,
    Error
}

public class ScanEvent : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    public ScanEventType EventType { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? ModuleId { get; set; }
    public string? Details { get; set; }
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
}

