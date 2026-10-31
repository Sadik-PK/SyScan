namespace SyScan.Core.Entities;

public class EvidenceRecord : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    public string ModuleId { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;

    /// <summary>SHA-256 of the evidence bundle before storage.</summary>
    public string ContentHash { get; set; } = string.Empty;

    public long FileSizeBytes { get; set; }
    public string StoragePath { get; set; } = string.Empty;
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
}

