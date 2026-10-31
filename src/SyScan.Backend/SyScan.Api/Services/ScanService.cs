using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Services;

public class ScanService : IScanService
{
    private readonly SyScanDbContext _db;
    private readonly IConfiguration _config;
    private readonly IScanEventBroadcaster _broadcaster;

    public ScanService(SyScanDbContext db, IConfiguration config, IScanEventBroadcaster broadcaster)
    {
        _db = db;
        _config = config;
        _broadcaster = broadcaster;
    }

    public async Task<ScanSession> CreateScanAsync(CreateScanRequest request, Guid createdByUserId, Guid organizationId)
    {
        var scanId = GenerateScanId();

        var modulesJson = JsonSerializer.Serialize(request.EnabledModules);
        var configHash = ComputeConfigHash(request.EnabledModules);

        var session = new ScanSession
        {
            ScanId = scanId,
            OrganizationId = organizationId,
            CreatedByUserId = createdByUserId,
            ParticipantLabel = request.ParticipantLabel,
            GameId = request.GameId,
            ScanProfileId = request.ScanProfileId,
            Status = ScanStatus.Created
        };

        var config = new ScanConfiguration
        {
            ScanSession = session,
            EnabledModules = modulesJson,
            ConfigurationHash = configHash,
            InvitationExpiryMinutes = request.InvitationExpiryMinutes
        };

        session.Configuration = config;

        _db.ScanSessions.Add(session);
        await _db.SaveChangesAsync();

        await RecordScanEventAsync(session.Id, ScanEventType.SessionCreated, $"Scan session {scanId} created.");

        return session;
    }

    public async Task<ScanSession?> GetScanAsync(string scanId, Guid organizationId)
    {
        return await _db.ScanSessions
            .Include(s => s.Configuration)
            .Include(s => s.Invitation)
            .Include(s => s.Findings)
            .Include(s => s.Events.OrderBy(e => e.OccurredAt))
            .Include(s => s.Organization)
            .FirstOrDefaultAsync(s => s.ScanId == scanId && s.OrganizationId == organizationId);
    }

    public async Task<IEnumerable<ScanSession>> ListScansAsync(Guid organizationId, int page = 1, int pageSize = 20)
    {
        return await _db.ScanSessions
            .Where(s => s.OrganizationId == organizationId)
            .OrderByDescending(s => s.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Include(s => s.Organization)
            .ToListAsync();
    }

    public async Task<bool> CancelScanAsync(string scanId, Guid requestingUserId)
    {
        var scan = await _db.ScanSessions.FirstOrDefaultAsync(s => s.ScanId == scanId);
        if (scan is null) return false;
        if (scan.Status is ScanStatus.Completed or ScanStatus.Cancelled or ScanStatus.Expired)
            return false;

        scan.Status = ScanStatus.Cancelled;
        await _db.SaveChangesAsync();

        await RecordScanEventAsync(scan.Id, ScanEventType.ScanCancelled, "Scan cancelled by administrator.");
        await _broadcaster.BroadcastStatusChangeAsync(scanId, ScanStatus.Cancelled);
        return true;
    }

    public async Task UpdateScanStatusAsync(Guid scanSessionId, ScanStatus newStatus)
    {
        var scan = await _db.ScanSessions.FindAsync(scanSessionId);
        if (scan is null) return;
        scan.Status = newStatus;
        await _db.SaveChangesAsync();
        await _broadcaster.BroadcastStatusChangeAsync(scan.ScanId, newStatus);
    }

    public async Task RecordScanEventAsync(Guid scanSessionId, ScanEventType eventType, string message, string? moduleId = null, string? details = null)
    {
        var ev = new ScanEvent
        {
            ScanSessionId = scanSessionId,
            EventType = eventType,
            Message = message,
            ModuleId = moduleId,
            Details = details,
            OccurredAt = DateTime.UtcNow
        };

        _db.ScanEvents.Add(ev);
        await _db.SaveChangesAsync();

        // Broadcast to SignalR — fetch scan ID
        var scan = await _db.ScanSessions.FindAsync(scanSessionId);
        if (scan is not null)
            await _broadcaster.BroadcastEventAsync(scan.ScanId, eventType, message, new { moduleId, details });
    }

    public async Task<string> GenerateScannerSessionTokenAsync(Guid scanSessionId)
    {
        var jwtSettings = _config.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim("scan_session_id", scanSessionId.ToString()),
            new Claim("token_type", "scanner"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: "scanner",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(8),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateScanId()
    {
        var bytes = RandomNumberGenerator.GetBytes(4);
        return "SS-" + Convert.ToHexString(bytes).ToUpperInvariant();
    }

    private static string ComputeConfigHash(string[] modules)
    {
        var json = JsonSerializer.Serialize(modules.OrderBy(m => m));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

