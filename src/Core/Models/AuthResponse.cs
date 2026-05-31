namespace AuthBroker.Core.Models;

/// <summary>
/// Authentication response returned after successful login or token refresh.
/// </summary>
public class AuthResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// User ID returned by the provider (populated on registration, may be empty on login/refresh).
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Email returned by the provider (populated on registration, may be empty on login/refresh).
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Extra claims injected by token enrichment (tenant_id, tenant_name, etc.).
    /// </summary>
    public Dictionary<string, object>? EnrichedClaims { get; set; }
}
