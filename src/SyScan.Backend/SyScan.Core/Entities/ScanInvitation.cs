namespace SyScan.Core.Entities;

public class ScanInvitation : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    /// <summary>URL-safe token sent to participant. Stored only as hash.</summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>Unique URL-safe token prefix for lookup (first 8 chars of token, not secret).</summary>
    public string TokenPrefix { get; set; } = string.Empty;

    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; } = false;
    public DateTime? UsedAt { get; set; }
    public string? UsedByIp { get; set; }
}

