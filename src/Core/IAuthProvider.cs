using AuthBroker.Core.Models;

namespace AuthBroker.Core;

/// <summary>
/// Result of a token validation operation.
/// </summary>
public class ValidationResult
{
    public bool IsValid { get; set; }
    public System.Security.Claims.ClaimsPrincipal? Principal { get; set; }
    public string? FailureReason { get; set; }
}

/// <summary>
/// Portable contract that all authentication providers must implement.
/// </summary>
public interface IAuthProvider
{
    /// <summary>
    /// Authenticates a user with username/password credentials.
    /// </summary>
    Task<IAuthResult<AuthResponse>> LoginAsync(AuthRequest request);

    /// <summary>
    /// Registers a new user with the given credentials.
    /// </summary>
    Task<IAuthResult<RegisterResponse>> RegisterAsync(AuthRequest request);

    /// <summary>
    /// Refreshes an expired access token using a refresh token.
    /// </summary>
    Task<IAuthResult<AuthResponse>> RefreshTokenAsync(string refreshToken, string tenantId);

    /// <summary>
    /// Invalidates a refresh token, ending the session.
    /// </summary>
    Task<IAuthResult> LogoutAsync(string refreshToken, string tenantId);

    /// <summary>
    /// Validates an access token and returns the validation result.
    /// </summary>
    Task<IAuthResult<ValidationResult>> ValidateTokenAsync(string accessToken, string tenantId);

    /// <summary>
    /// Retrieves the user profile for the authenticated user.
    /// </summary>
    Task<IAuthResult<UserProfile>> GetUserProfileAsync(string accessToken, string tenantId);

    /// <summary>
    /// Confirms a user's email address using the provider's verification mechanism.
    /// </summary>
    Task<IAuthResult> ConfirmEmailAsync(string id, string tenantId);
}
