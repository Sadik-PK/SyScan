namespace SyScan.Api.Services;

public interface IAuthService
{
    Task<AuthResult> LoginAsync(string email, string password);
    Task<AuthResult> RegisterAsync(string email, string password, string displayName);
}

public record AuthResult(bool Success, string? Token, string? Error, UserDto? User);

public record UserDto(Guid Id, string Email, string DisplayName);

