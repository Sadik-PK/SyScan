using SyScan.Core.Entities;

namespace SyScan.Api.Services;

public interface IScanEventBroadcaster
{
    Task BroadcastEventAsync(string scanId, ScanEventType eventType, string message, object? payload = null);
    Task BroadcastStatusChangeAsync(string scanId, ScanStatus newStatus);
    Task BroadcastFindingAsync(string scanId, ScanFinding finding);
    Task BroadcastModuleProgressAsync(string scanId, string moduleId, string status, int progressPercent);
}

