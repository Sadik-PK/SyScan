namespace SyScan.Core.Entities;

public class ScanReport : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    public string ReportVersion { get; set; } = "1.0";

    /// <summary>Full JSON report document.</summary>
    public string ReportJson { get; set; } = string.Empty;

    /// <summary>SHA-256 of the report JSON for integrity verification.</summary>
    public string ReportHash { get; set; } = string.Empty;

    public string? PdfStoragePath { get; set; }
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public bool IsFinalized { get; set; } = false;
}

