using SyScan.Core.Entities;

namespace SyScan.Api.Services;

public interface IInvitationService
{
    Task<(ScanInvitation invitation, string rawToken)> CreateInvitationAsync(Guid scanSessionId, int expiryMinutes);
    Task<InvitationValidationResult> ValidateInvitationAsync(string rawToken);
    Task<PairResult> PairInvitationAsync(string rawToken, string clientIp);
}

public record InvitationValidationResult(
    bool IsValid,
    string? Error,
    Guid? ScanSessionId,
    string? ScanId,
    string? OrganizationName,
    string? GameId,
    string? ParticipantLabel,
    string[]? EnabledModules
);

public record PairResult(bool Success, string? Error, string? SessionToken, string? ScanId);

