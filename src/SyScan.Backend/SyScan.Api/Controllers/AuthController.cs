using Microsoft.AspNetCore.Mvc;
using SyScan.Api.Services;

namespace SyScan.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _auth;
    private readonly IAuditService _audit;

    public AuthController(IAuthService auth, IAuditService audit)
    {
        _auth = auth;
        _audit = audit;
    }

    /// <summary>Authenticate an admin/moderator user.</summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var result = await _auth.LoginAsync(request.Email, request.Password);
        if (!result.Success)
            return Unauthorized(new { error = result.Error });

        await _audit.LogAsync("Login", result.User!.Id, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            token = result.Token,
            user = result.User,
            expiresIn = 3600
        });
    }

    /// <summary>Register a new user (admin only in production; open for initial setup).</summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var result = await _auth.RegisterAsync(request.Email, request.Password, request.DisplayName);
        if (!result.Success)
            return Conflict(new { error = result.Error });

        return Ok(new
        {
            token = result.Token,
            user = result.User
        });
    }
}

public record LoginRequest(string Email, string Password);
public record RegisterRequest(string Email, string Password, string DisplayName);

