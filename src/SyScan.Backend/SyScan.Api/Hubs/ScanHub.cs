using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace SyScan.Api.Hubs;

/// <summary>
/// Real-time SignalR hub for scan monitoring.
/// Admins join a scan group to receive live events.
/// Scanners (desktop app) push events via the REST API, which internally broadcasts to this hub.
/// </summary>
[Authorize]
public class ScanHub : Hub
{
    /// <summary>Admin joins a specific scan's monitoring group.</summary>
    public async Task JoinScanGroup(string scanId)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, $"scan:{scanId}");
        await Clients.Caller.SendAsync("JoinedScanGroup", new { scanId, message = $"Monitoring scan {scanId}." });
    }

    public async Task LeaveScanGroup(string scanId)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"scan:{scanId}");
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        // Groups are automatically cleaned up by SignalR on disconnect
        await base.OnDisconnectedAsync(exception);
    }
}

