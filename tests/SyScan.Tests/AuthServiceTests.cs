using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SyScan.Api.Services;
using SyScan.Infrastructure.Data;
using Xunit;

namespace SyScan.Tests;

public class AuthServiceTests
{
    private static (SyScanDbContext db, IAuthService authService) CreateAuthService()
    {
        var options = new DbContextOptionsBuilder<SyScanDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        var db = new SyScanDbContext(options);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Key"] = "TEST_SECRET_KEY_FOR_TESTS_AT_LEAST_32_BYTES_LONG",
                ["Jwt:Issuer"] = "syscan-api",
                ["Jwt:Audience"] = "syscan-web",
                ["Jwt:ExpiryMinutes"] = "60"
            })
            .Build();

        var authService = new AuthService(db, config, NullLogger<AuthService>.Instance);
        return (db, authService);
    }

    [Fact]
    public async Task Register_CreatesUserWithHashedPasswordAndOrg()
    {
        var (db, authService) = CreateAuthService();

        var result = await authService.RegisterAsync("moderator@org.com", "SecurePass123!", "Mod Alice");

        Assert.True(result.Success);
        Assert.NotNull(result.Token);
        Assert.NotNull(result.User);
        Assert.Equal("moderator@org.com", result.User.Email);

        // Verify password is not plaintext
        var userInDb = await db.Users.Include(u => u.OrganizationMemberships).FirstOrDefaultAsync(u => u.Email == "moderator@org.com");
        Assert.NotNull(userInDb);
        Assert.NotEqual("SecurePass123!", userInDb.PasswordHash);
        Assert.True(BCrypt.Net.BCrypt.Verify("SecurePass123!", userInDb.PasswordHash));
        Assert.Single(userInDb.OrganizationMemberships);
    }

    [Fact]
    public async Task Register_DuplicateEmail_Fails()
    {
        var (_, authService) = CreateAuthService();

        var first = await authService.RegisterAsync("duplicate@test.com", "Password123!", "User 1");
        Assert.True(first.Success);

        var second = await authService.RegisterAsync("duplicate@test.com", "Password456!", "User 2");
        Assert.False(second.Success);
        Assert.Contains("already registered", second.Error ?? "");
    }

    [Fact]
    public async Task Login_ValidCredentials_ReturnsJwtToken()
    {
        var (_, authService) = CreateAuthService();

        await authService.RegisterAsync("lead@syscan.internal", "SuperSecretPass!", "Lead Investigator");

        var loginResult = await authService.LoginAsync("lead@syscan.internal", "SuperSecretPass!");
        Assert.True(loginResult.Success);
        Assert.NotNull(loginResult.Token);
        Assert.NotEmpty(loginResult.Token);
    }

    [Fact]
    public async Task Login_InvalidPassword_Fails()
    {
        var (_, authService) = CreateAuthService();

        await authService.RegisterAsync("user@test.com", "CorrectPassword123", "User");

        var loginResult = await authService.LoginAsync("user@test.com", "WrongPassword");
        Assert.False(loginResult.Success);
        Assert.Contains("Invalid email or password", loginResult.Error ?? "");
    }
}
