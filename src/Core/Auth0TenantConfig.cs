namespace AuthBroker.Core;

/// <summary>
/// Configuration for a single Auth0 tenant, loaded from the <c>Auth</c> array in appsettings.
/// Each entry in the array is a complete tenant configuration.
/// </summary>
public class Auth0TenantConfig
{
    public string TenantId { get; set; } = string.Empty;
    public string TenantName { get; set; } = string.Empty;
    public string? TenantDomain { get; set; }
    public string Domain { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string? Audience { get; set; }
    public string? RolesClaim { get; set; }
}
