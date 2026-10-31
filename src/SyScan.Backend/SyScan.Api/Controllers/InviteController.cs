using Microsoft.AspNetCore.Mvc;
using SyScan.Api.Services;

namespace SyScan.Api.Controllers;

/// <summary>Public endpoint for invitation validation and pairing — no auth required.</summary>
[ApiController]
[Route("api/invite")]
public class InviteController : ControllerBase
{
    private readonly IInvitationService _invitationService;

    public InviteController(IInvitationService invitationService)
    {
        _invitationService = invitationService;
    }

    /// <summary>
    /// Validate an invitation token.
    /// Used by the web UI to show scan details before download,
    /// and by the desktop app to verify the invitation before pairing.
    /// </summary>
    [HttpGet("{token}")]
    public async Task<IActionResult> ValidateInvitation(string token)
    {
        var result = await _invitationService.ValidateInvitationAsync(token);

        if (!result.IsValid)
            return BadRequest(new { error = result.Error });

        return Ok(new
        {
            result.ScanId,
            result.OrganizationName,
            result.GameId,
            result.ParticipantLabel,
            result.EnabledModules
        });
    }

    /// <summary>
    /// Pair an invitation: validates the token, marks it as used, and returns a scanner session token.
    /// Only callable once per invitation.
    /// </summary>
    [HttpPost("{token}/pair")]
    public async Task<IActionResult> PairInvitation(string token)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var result = await _invitationService.PairInvitationAsync(token, clientIp);

        if (!result.Success)
            return BadRequest(new { error = result.Error });

        return Ok(new
        {
            result.SessionToken,
            result.ScanId
        });
    }
}

