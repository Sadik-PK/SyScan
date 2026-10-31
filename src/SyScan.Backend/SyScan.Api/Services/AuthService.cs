using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SyScan.Core.Entities;
using SyScan.Infrastructure.Data;

namespace SyScan.Api.Services;

public class AuthService : IAuthService
{
    private readonly SyScanDbContext _db;
    private readonly IConfiguration _config;
    private readonly ILogger<AuthService> _logger;

    public AuthService(SyScanDbContext db, IConfiguration config, ILogger<AuthService> logger)
    {
        _db = db;
        _config = config;
        _logger = logger;
    }

    public async Task<AuthResult> LoginAsync(string email, string password)
    {
        var normalizedEmail = email.Trim().ToLowerInvariant();
        var user = await _db.Users
            .Include(u => u.OrganizationMemberships)
                .ThenInclude(m => m.Organization)
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail);

        if (user is null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            return new AuthResult(false, null, "Invalid email or password.", null);

        if (!user.IsActive)
            return new AuthResult(false, null, "Account is disabled.", null);

        // Ensure user has at least one organization
        if (!user.OrganizationMemberships.Any(m => m.IsActive))
        {
            await EnsureDefaultOrganizationForUserAsync(user);
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        var token = GenerateToken(user, "syscan-web");
        return new AuthResult(true, token, null, new UserDto(user.Id, user.Email, user.DisplayName));
    }

    public async Task<AuthResult> RegisterAsync(string email, string password, string displayName)
    {
        var normalizedEmail = email.Trim().ToLowerInvariant();
        if (await _db.Users.AnyAsync(u => u.Email == normalizedEmail))
            return new AuthResult(false, null, "Email already registered.", null);

        var user = new User
        {
            Email = normalizedEmail,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
            DisplayName = displayName.Trim()
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        // Create initial organization for the new user
        await EnsureDefaultOrganizationForUserAsync(user);
        await _db.SaveChangesAsync();

        var token = GenerateToken(user, "syscan-web");
        return new AuthResult(true, token, null, new UserDto(user.Id, user.Email, user.DisplayName));
    }

    private async Task EnsureDefaultOrganizationForUserAsync(User user)
    {
        var orgSlug = "org-" + Guid.NewGuid().ToString("N")[..8];
        var orgName = $"{user.DisplayName}'s Team";

        var org = new Organization
        {
            Name = orgName,
            Slug = orgSlug,
            IsActive = true
        };
        _db.Organizations.Add(org);

        var member = new OrganizationMember
        {
            Organization = org,
            User = user,
            Role = OrganizationRole.SuperAdmin,
            IsActive = true
        };
        _db.OrganizationMembers.Add(member);
    }

    private string GenerateToken(User user, string audience)
    {
        var jwtSettings = _config.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var role = user.OrganizationMemberships.FirstOrDefault()?.Role.ToString() ?? "Admin";

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Name, user.DisplayName),
            new(JwtRegisteredClaimNames.Name, user.DisplayName),
            new(ClaimTypes.Role, role),
            new("role", role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var expiry = DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["ExpiryMinutes"] ?? "60"));

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: audience,
            claims: claims,
            expires: expiry,
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
