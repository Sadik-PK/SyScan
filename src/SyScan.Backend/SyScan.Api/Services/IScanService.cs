using SyScan.Core.Entities;

namespace SyScan.Api.Services;

public interface IScanService
{
    Task<ScanSession> CreateScanAsync(CreateScanRequest request, Guid createdByUserId, Guid organizationId);
    Task<ScanSession?> GetScanAsync(string scanId, Guid organizationId);
    Task<IEnumerable<ScanSession>> ListScansAsync(Guid organizationId, int page = 1, int pageSize = 20);
    Task<bool> CancelScanAsync(string scanId, Guid requestingUserId);
    Task UpdateScanStatusAsync(Guid scanSessionId, ScanStatus newStatus);
    Task RecordScanEventAsync(Guid scanSessionId, ScanEventType eventType, string message, string? moduleId = null, string? details = null);
    Task<string> GenerateScannerSessionTokenAsync(Guid scanSessionId);
}

public record CreateScanRequest(
    string ParticipantLabel,
    string GameId,
    string ScanProfileId,
    string[] EnabledModules,
    int InvitationExpiryMinutes = 60
);

