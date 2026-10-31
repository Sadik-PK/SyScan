namespace SyScan.Core.Entities;

public class ScanConfiguration : BaseEntity
{
    public Guid ScanSessionId { get; set; }
    public ScanSession ScanSession { get; set; } = null!;

    /// <summary>SHA-256 hash of the serialized configuration. Used for consent locking.</summary>
    public string ConfigurationHash { get; set; } = string.Empty;

    /// <summary>JSON string array of enabled module IDs.</summary>
    public string EnabledModules { get; set; } = "[]";

    /// <summary>JSON string of module-specific settings.</summary>
    public string? ModuleSettings { get; set; }

    public int InvitationExpiryMinutes { get; set; } = 60;
}
