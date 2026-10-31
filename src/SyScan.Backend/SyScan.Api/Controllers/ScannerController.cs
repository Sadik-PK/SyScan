using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SyScan.Api.Services;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Controllers;

/// <summary>
/// Scanner API — endpoints called exclusively by the SyScan Desktop application.
/// All endpoints require a valid scanner session token (audience: "scanner").
/// </summary>
[ApiController]
[Route("api/scanner")]
[Authorize]
public class ScannerController : ControllerBase
{
    private readonly SyScanDbContext _db;
    private readonly IScanService _scanService;
    private readonly IScanEventBroadcaster _broadcaster;

    public ScannerController(SyScanDbContext db, IScanService scanService, IScanEventBroadcaster broadcaster)
    {
        _db = db;
        _scanService = scanService;
        _broadcaster = broadcaster;
    }

    private Guid? GetScanSessionId()
    {
        var claim = User.FindFirstValue("scan_session_id");
        return claim is null ? null : Guid.Parse(claim);
    }

    /// <summary>Record participant consent.</summary>
    [HttpPost("consent")]
    public async Task<IActionResult> RecordConsent([FromBody] ConsentDto request)
    {
        var scanSessionId = GetScanSessionId();
        if (scanSessionId is null) return Unauthorized();

        var scan = await _db.ScanSessions.Include(s => s.Configuration).FirstOrDefaultAsync(s => s.Id == scanSessionId);
        if (scan is null) return NotFound();

        // Verify config hash matches what was presented to user
        if (scan.Configuration?.ConfigurationHash != request.ConfigurationHash)
            return BadRequest(new { error = "Configuration has changed. Please restart the scan." });

        var consent = new ConsentRecord
        {
            ScanSessionId = scanSessionId.Value,
            ConfigurationHash = request.ConfigurationHash,
            Approved = request.Approved,
            DecidedAt = DateTime.UtcNow,
            ParticipantIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            DeclineReason = request.DeclineReason
        };

        _db.ConsentRecords.Add(consent);

        if (request.Approved)
        {
            scan.Status = ScanStatus.Scanning;
            scan.ScanStartedAt = DateTime.UtcNow;
            await _scanService.RecordScanEventAsync(scanSessionId.Value, ScanEventType.ConsentGranted,
                "Participant approved the scan.");
        }
        else
        {
            scan.Status = ScanStatus.Declined;
            await _scanService.RecordScanEventAsync(scanSessionId.Value, ScanEventType.ConsentDeclined,
                $"Participant declined the scan. Reason: {request.DeclineReason ?? "Not provided"}");
        }

        await _db.SaveChangesAsync();
        return Ok(new { status = scan.Status.ToString() });
    }

    /// <summary>Report module start.</summary>
    [HttpPost("modules/{moduleId}/start")]
    public async Task<IActionResult> ModuleStarted(string moduleId)
    {
        var scanSessionId = GetScanSessionId();
        if (scanSessionId is null) return Unauthorized();

        await _scanService.RecordScanEventAsync(scanSessionId.Value, ScanEventType.ModuleStarted,
            $"Module started: {moduleId}", moduleId);
        await _broadcaster.BroadcastModuleProgressAsync(
            (await GetScanIdAsync(scanSessionId.Value))!, moduleId, "Running", 0);

        return Ok();
    }

    /// <summary>Report module completion.</summary>
    [HttpPost("modules/{moduleId}/complete")]
    public async Task<IActionResult> ModuleCompleted(string moduleId, [FromBody] ModuleResultDto result)
    {
        var scanSessionId = GetScanSessionId();
        if (scanSessionId is null) return Unauthorized();

        await _scanService.RecordScanEventAsync(scanSessionId.Value, ScanEventType.ModuleCompleted,
            $"Module completed: {moduleId} — {result.FindingsCount} finding(s)", moduleId,
            JsonSerializer.Serialize(new { result.FindingsCount, result.Status, result.ErrorMessage }));

        var scanId = await GetScanIdAsync(scanSessionId.Value);
        if (scanId is not null)
            await _broadcaster.BroadcastModuleProgressAsync(scanId, moduleId, result.Status, 100);

        return Ok();
    }

    /// <summary>Submit a finding from the scanner.</summary>
    [HttpPost("findings")]
    public async Task<IActionResult> SubmitFinding([FromBody] SubmitFindingDto dto)
    {
        var scanSessionId = GetScanSessionId();
        if (scanSessionId is null) return Unauthorized();

        var scan = await _db.ScanSessions.FindAsync(scanSessionId);
        if (scan is null) return NotFound();

        // Determine next finding ID
        var count = await _db.ScanFindings.CountAsync(f => f.ScanSessionId == scanSessionId);
        var findingId = $"FND-{count + 1:D3}";

        var finding = new ScanFinding
        {
            ScanSessionId = scanSessionId.Value,
            FindingId = findingId,
            ModuleId = dto.ModuleId,
            Category = Enum.Parse<FindingCategory>(dto.Category),
            Severity = Enum.Parse<FindingSeverity>(dto.Severity),
            Title = dto.Title,
            Description = dto.Description,
            FilePath = dto.FilePath,
            FileHash = dto.FileHash,
            ArtifactTimestamp = dto.ArtifactTimestamp,
            Confidence = dto.Confidence,
            FalsePositiveNotes = dto.FalsePositiveNotes,
            Explanation = dto.Explanation,
            SupportingArtifacts = dto.SupportingArtifacts
        };

        _db.ScanFindings.Add(finding);
        await _db.SaveChangesAsync();

        await _scanService.RecordScanEventAsync(scanSessionId.Value, ScanEventType.FindingDetected,
            $"Finding: [{dto.Severity}] {dto.Title}", dto.ModuleId);
        await _broadcaster.BroadcastFindingAsync(scan.ScanId, finding);

        return Ok(new { findingId });
    }

    /// <summary>Report scan completion.</summary>
    [HttpPost("complete")]
    public async Task<IActionResult> CompleteScan([FromBody] CompleteScanDto dto)
    {
        var scanSessionId = GetScanSessionId();
        if (scanSessionId is null) return Unauthorized();

        var scan = await _db.ScanSessions.FindAsync(scanSessionId);
        if (scan is null) return NotFound();

        scan.Status = ScanStatus.Completed;
        scan.ScanCompletedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _scanService.RecordScanEventAsync(scanSessionId.Value, ScanEventType.ScanCompleted,
            $"Scan completed. Total findings: {dto.TotalFindings}");
        await _broadcaster.BroadcastStatusChangeAsync(scan.ScanId, ScanStatus.Completed);

        return Ok();
    }

    private async Task<string?> GetScanIdAsync(Guid scanSessionId)
    {
        var scan = await _db.ScanSessions.FindAsync(scanSessionId);
        return scan?.ScanId;
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

public record ConsentDto(bool Approved, string ConfigurationHash, string? DeclineReason = null);

public record ModuleResultDto(string Status, int FindingsCount, string? ErrorMessage = null);

public record SubmitFindingDto(
    string ModuleId,
    string Category,
    string Severity,
    string Title,
    string Description,
    int Confidence,
    string? FilePath = null,
    string? FileHash = null,
    DateTime? ArtifactTimestamp = null,
    string? FalsePositiveNotes = null,
    string? Explanation = null,
    string? SupportingArtifacts = null);

public record CompleteScanDto(int TotalFindings, string[] CompletedModules, string[] FailedModules);

