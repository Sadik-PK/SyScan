using Microsoft.AspNetCore.SignalR;
using SyScan.Core.Entities;

namespace SyScan.Api.Services;

public class ScanEventBroadcaster : IScanEventBroadcaster
{
    private readonly IHubContext<Hubs.ScanHub> _hub;

    public ScanEventBroadcaster(IHubContext<Hubs.ScanHub> hub) => _hub = hub;

    public async Task BroadcastEventAsync(string scanId, ScanEventType eventType, string message, object? payload = null)
    {
        await _hub.Clients.Group($"scan:{scanId}").SendAsync("ScanEvent", new
        {
            scanId,
            eventType = eventType.ToString(),
            message,
            payload,
            occurredAt = DateTime.UtcNow
        });
    }

    public async Task BroadcastStatusChangeAsync(string scanId, ScanStatus newStatus)
    {
        await _hub.Clients.Group($"scan:{scanId}").SendAsync("StatusChanged", new
        {
            scanId,
            status = newStatus.ToString(),
            occurredAt = DateTime.UtcNow
        });
    }

    public async Task BroadcastFindingAsync(string scanId, ScanFinding finding)
    {
        await _hub.Clients.Group($"scan:{scanId}").SendAsync("NewFinding", new
        {
            scanId,
            finding = new
            {
                finding.FindingId,
                finding.ModuleId,
                finding.Category,
                finding.Severity,
                finding.Title,
                finding.Description,
                finding.FilePath,
                finding.FileHash,
                finding.Confidence,
                finding.ArtifactTimestamp,
                finding.Explanation
            }
        });
    }

    public async Task BroadcastModuleProgressAsync(string scanId, string moduleId, string status, int progressPercent)
    {
        await _hub.Clients.Group($"scan:{scanId}").SendAsync("ModuleProgress", new
        {
            scanId,
            moduleId,
            status,
            progressPercent,
            occurredAt = DateTime.UtcNow
        });
    }
}

