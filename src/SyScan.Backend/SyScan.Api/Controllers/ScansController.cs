using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SyScan.Api.Services;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Controllers;

[ApiController]
[Route("api/scans")]
[Authorize]
public class ScansController : ControllerBase
{
    private readonly IScanService _scanService;
    private readonly IInvitationService _invitationService;
    private readonly SyScanDbContext _db;
    private readonly IAuditService _audit;

    public ScansController(IScanService scanService, IInvitationService invitationService,
        SyScanDbContext db, IAuditService audit)
    {
        _scanService = scanService;
        _invitationService = invitationService;
        _db = db;
        _audit = audit;
    }

    private Guid CurrentUserId
    {
        get
        {
            var raw = User.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? User.FindFirstValue("sub")
                      ?? User.FindFirstValue("id");
            return Guid.TryParse(raw, out var id) ? id : Guid.Empty;
        }
    }

    private async Task<Guid?> GetCurrentOrganizationIdAsync()
    {
        var userId = CurrentUserId;
        if (userId == Guid.Empty) return null;

        var member = await _db.OrganizationMembers.FirstOrDefaultAsync(m => m.UserId == userId && m.IsActive);
        if (member != null) return member.OrganizationId;

        // Auto-assign default organization if none associated
        var user = await _db.Users.FindAsync(userId);
        if (user == null) return null;

        var org = await _db.Organizations.FirstOrDefaultAsync(o => o.IsActive);
        if (org == null)
        {
            org = new Organization
            {
                Name = $"{user.DisplayName}'s Team",
                Slug = "org-" + Guid.NewGuid().ToString("N")[..8],
                IsActive = true
            };
            _db.Organizations.Add(org);
            await _db.SaveChangesAsync();
        }

        var newMember = new OrganizationMember
        {
            OrganizationId = org.Id,
            UserId = user.Id,
            Role = OrganizationRole.SuperAdmin,
            IsActive = true
        };
        _db.OrganizationMembers.Add(newMember);
        await _db.SaveChangesAsync();

        return org.Id;
    }

    /// <summary>List scans for the current organization.</summary>
    [HttpGet]
    public async Task<IActionResult> ListScans([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var orgId = await GetCurrentOrganizationIdAsync();
        if (orgId is null) return Forbid();

        var scans = await _scanService.ListScansAsync(orgId.Value, page, pageSize);
        return Ok(scans.Select(s => new ScanSummaryDto(
            s.ScanId, s.ParticipantLabel, s.GameId, s.Status.ToString(),
            s.CreatedAt, s.ConnectedAt, s.ScanCompletedAt)));
    }

    /// <summary>Create a new scan session.</summary>
    [HttpPost]
    public async Task<IActionResult> CreateScan([FromBody] CreateScanDto request)
    {
        var orgId = await GetCurrentOrganizationIdAsync();
        if (orgId is null) return Forbid();

        var session = await _scanService.CreateScanAsync(
            new CreateScanRequest(request.ParticipantLabel, request.GameId, request.ScanProfileId,
                request.EnabledModules, request.InvitationExpiryMinutes),
            CurrentUserId, orgId.Value);

        // Auto-generate invitation
        var (invitation, rawToken) = await _invitationService.CreateInvitationAsync(
            session.Id, request.InvitationExpiryMinutes);

        await _audit.LogAsync("ScanCreated", CurrentUserId, orgId, "ScanSession", session.ScanId);

        return CreatedAtAction(nameof(GetScan), new { scanId = session.ScanId }, new ScanCreatedDto(
            session.ScanId,
            session.Id,
            rawToken,
            $"/invite/{rawToken}",
            invitation.ExpiresAt,
            session.Status.ToString()
        ));
    }

    /// <summary>Get scan details.</summary>
    [HttpGet("{scanId}")]
    public async Task<IActionResult> GetScan(string scanId)
    {
        var orgId = await GetCurrentOrganizationIdAsync();
        if (orgId is null) return Forbid();

        var scan = await _scanService.GetScanAsync(scanId, orgId.Value);
        if (scan is null) return NotFound();

        return Ok(new ScanDetailDto(
            scan.ScanId, scan.ParticipantLabel, scan.GameId, scan.ScanProfileId,
            scan.Status.ToString(), scan.CreatedAt, scan.ConnectedAt, scan.ScanStartedAt,
            scan.ScanCompletedAt,
            scan.Events.Select(e => new ScanEventDto(e.EventType.ToString(), e.Message, e.ModuleId, e.OccurredAt)),
            scan.Findings.Select(f => new ScanFindingDto(f.FindingId, f.ModuleId, f.Category.ToString(),
                f.Severity.ToString(), f.Title, f.Description, f.FilePath, f.Confidence, f.ArtifactTimestamp ?? f.CreatedAt))
        ));
    }

    /// <summary>Get full forensic report for a scan.</summary>
    [HttpGet("{scanId}/report")]
    public async Task<IActionResult> GetScanReport(string scanId)
    {
        var orgId = await GetCurrentOrganizationIdAsync();
        if (orgId is null) return Forbid();

        var scan = await _db.ScanSessions
            .Include(s => s.Configuration)
            .Include(s => s.Findings)
            .Include(s => s.ConsentRecords)
            .Include(s => s.Events.OrderBy(e => e.OccurredAt))
            .Include(s => s.Organization)
            .Include(s => s.CreatedByUser)
            .FirstOrDefaultAsync(s => s.ScanId == scanId && s.OrganizationId == orgId);

        if (scan is null) return NotFound();

        var criticalFindings = scan.Findings.Count(f => f.Severity == FindingSeverity.Critical);
        var warningFindings = scan.Findings.Count(f => f.Severity == FindingSeverity.Warning);
        var suspiciousFindings = scan.Findings.Count(f => f.Severity == FindingSeverity.Suspicious);
        var infoFindings = scan.Findings.Count(f => f.Severity == FindingSeverity.Information);

        var consentAt = scan.ConsentRecords.OrderByDescending(c => c.DecidedAt).FirstOrDefault()?.DecidedAt;

        return Ok(new
        {
            scanId = scan.ScanId,
            organization = scan.Organization?.Name ?? "Unknown Organization",
            investigator = scan.CreatedByUser?.DisplayName ?? "System",
            participant = scan.ParticipantLabel,
            game = scan.GameId,
            profile = scan.ScanProfileId,
            status = scan.Status.ToString(),
            timestamps = new
            {
                created = scan.CreatedAt,
                connected = scan.ConnectedAt,
                consent = consentAt,
                started = scan.ScanStartedAt,
                completed = scan.ScanCompletedAt,
                generated = DateTime.UtcNow,
                durationSeconds = scan.ScanCompletedAt.HasValue && scan.ScanStartedAt.HasValue
                    ? (int)(scan.ScanCompletedAt.Value - scan.ScanStartedAt.Value).TotalSeconds
                    : 0
            },
            summary = new
            {
                totalFindings = scan.Findings.Count,
                critical = criticalFindings,
                warning = warningFindings,
                suspicious = suspiciousFindings,
                informational = infoFindings,
                clean = criticalFindings == 0 && warningFindings == 0 && suspiciousFindings == 0
            },
            findings = scan.Findings.OrderByDescending(f => f.Severity).Select(f => new
            {
                f.FindingId,
                f.ModuleId,
                category = f.Category.ToString(),
                severity = f.Severity.ToString(),
                f.Title,
                f.Description,
                f.FilePath,
                f.FileHash,
                f.Confidence,
                timestamp = f.ArtifactTimestamp ?? f.CreatedAt,
                f.Explanation
            }),
            events = scan.Events.OrderBy(e => e.OccurredAt).Select(e => new
            {
                type = e.EventType.ToString(),
                e.Message,
                e.ModuleId,
                e.OccurredAt
            })
        });
    }

    /// <summary>Cancel an active scan.</summary>
    [HttpDelete("{scanId}")]
    public async Task<IActionResult> CancelScan(string scanId)
    {
        var success = await _scanService.CancelScanAsync(scanId, CurrentUserId);
        if (!success) return BadRequest(new { error = "Unable to cancel scan." });

        await _audit.LogAsync("ScanCancelled", CurrentUserId, entityType: "ScanSession", entityId: scanId);
        return NoContent();
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

public record ScanSummaryDto(
    string ScanId, string ParticipantLabel, string GameId, string Status,
    DateTime CreatedAt, DateTime? ConnectedAt, DateTime? CompletedAt);

public record CreateScanDto(
    string ParticipantLabel,
    string GameId,
    string ScanProfileId,
    string[] EnabledModules,
    int InvitationExpiryMinutes = 60);

public record ScanCreatedDto(
    string ScanId, Guid SessionId, string InvitationToken, string InvitationPath,
    DateTime ExpiresAt, string Status);

public record ScanDetailDto(
    string ScanId, string ParticipantLabel, string GameId, string ScanProfileId,
    string Status, DateTime CreatedAt, DateTime? ConnectedAt, DateTime? ScanStartedAt,
    DateTime? CompletedAt,
    IEnumerable<ScanEventDto> Events,
    IEnumerable<ScanFindingDto> Findings);

public record ScanEventDto(string EventType, string Message, string? ModuleId, DateTime OccurredAt);

public record ScanFindingDto(
    string FindingId, string ModuleId, string Category, string Severity,
    string Title, string Description, string? FilePath, int Confidence, DateTime OccurredAt);
