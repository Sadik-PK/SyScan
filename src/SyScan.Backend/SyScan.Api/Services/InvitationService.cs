using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Services;

public class InvitationService : IInvitationService
{
    private readonly SyScanDbContext _db;
    private readonly IScanService _scanService;
    private readonly IAuditService _audit;

    public InvitationService(SyScanDbContext db, IScanService scanService, IAuditService audit)
    {
        _db = db;
        _scanService = scanService;
        _audit = audit;
    }

    public async Task<(ScanInvitation invitation, string rawToken)> CreateInvitationAsync(Guid scanSessionId, int expiryMinutes)
    {
        // Invalidate any existing unused invitations for this session
        var existing = await _db.ScanInvitations
            .Where(i => i.ScanSessionId == scanSessionId && !i.IsUsed)
            .ToListAsync();
        _db.ScanInvitations.RemoveRange(existing);

        // Generate a cryptographically random 32-byte token
        var rawTokenBytes = RandomNumberGenerator.GetBytes(32);
        var rawToken = Base64UrlEncode(rawTokenBytes);
        var tokenHash = HashToken(rawToken);
        var tokenPrefix = rawToken[..8]; // Not secret, used for lookup

        var invitation = new ScanInvitation
        {
            ScanSessionId = scanSessionId,
            TokenHash = tokenHash,
            TokenPrefix = tokenPrefix,
            ExpiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes),
            IsUsed = false
        };

        _db.ScanInvitations.Add(invitation);

        // Update scan status
        var scan = await _db.ScanSessions.FindAsync(scanSessionId);
        if (scan is not null) scan.Status = ScanStatus.Invited;

        await _db.SaveChangesAsync();
        await _scanService.RecordScanEventAsync(scanSessionId, ScanEventType.InvitationGenerated, "Invitation generated.");

        return (invitation, rawToken);
    }

    public async Task<InvitationValidationResult> ValidateInvitationAsync(string rawToken)
    {
        var (invitation, scan) = await FindInvitationAsync(rawToken);

        if (invitation is null || scan is null)
            return new InvitationValidationResult(false, "Invitation not found or expired.", null, null, null, null, null, null);

        if (invitation.IsUsed)
            return new InvitationValidationResult(false, "Invitation has already been used.", null, null, null, null, null, null);

        if (invitation.ExpiresAt < DateTime.UtcNow)
            return new InvitationValidationResult(false, "Invitation has expired.", null, null, null, null, null, null);

        if (scan.Status == ScanStatus.Cancelled || scan.Status == ScanStatus.Expired)
            return new InvitationValidationResult(false, "Scan has been cancelled or expired.", null, null, null, null, null, null);

        var modules = !string.IsNullOrEmpty(scan.Configuration?.EnabledModules)
            ? JsonSerializer.Deserialize<string[]>(scan.Configuration.EnabledModules) ?? []
            : [];

        return new InvitationValidationResult(
            true, null, scan.Id, scan.ScanId,
            scan.Organization?.Name ?? "Unknown Organization",
            scan.GameId, scan.ParticipantLabel, modules);
    }

    public async Task<PairResult> PairInvitationAsync(string rawToken, string clientIp)
    {
        var (invitation, scan) = await FindInvitationAsync(rawToken);

        if (invitation is null || scan is null)
            return new PairResult(false, "Invitation not found.", null, null);

        if (invitation.IsUsed)
            return new PairResult(false, "Invitation already used.", null, null);

        if (invitation.ExpiresAt < DateTime.UtcNow)
            return new PairResult(false, "Invitation expired.", null, null);

        // Mark as used
        invitation.IsUsed = true;
        invitation.UsedAt = DateTime.UtcNow;
        invitation.UsedByIp = clientIp;

        // Issue scanner session token
        var sessionToken = await _scanService.GenerateScannerSessionTokenAsync(scan.Id);
        scan.ScannerSessionToken = HashToken(sessionToken); // Store hash only
        scan.Status = ScanStatus.Connected;
        scan.ConnectedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync();

        await _scanService.RecordScanEventAsync(scan.Id, ScanEventType.ApplicationConnected,
            "Desktop application connected and paired.");

        await _audit.LogAsync("InvitationPaired", entityType: "ScanSession",
            entityId: scan.ScanId, ipAddress: clientIp);

        return new PairResult(true, null, sessionToken, scan.ScanId);
    }

    private async Task<(ScanInvitation?, ScanSession?)> FindInvitationAsync(string rawToken)
    {
        if (string.IsNullOrEmpty(rawToken) || rawToken.Length < 8)
            return (null, null);

        var prefix = rawToken[..8];
        var hash = HashToken(rawToken);

        var invitation = await _db.ScanInvitations
            .Include(i => i.ScanSession)
                .ThenInclude(s => s.Configuration)
            .Include(i => i.ScanSession)
                .ThenInclude(s => s.Organization)
            .FirstOrDefaultAsync(i => i.TokenPrefix == prefix && i.TokenHash == hash);

        return (invitation, invitation?.ScanSession);
    }

    private static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

