namespace AuthBroker.Core;

/// <summary>
/// Configuration for a single tenant, loaded from appsettings.json.
/// </summary>
public class TenantConfig
{
    public string TenantId { get; set; } = string.Empty;
    public string TenantName { get; set; } = string.Empty;
    public string? TenantDomain { get; set; }
    public ProviderType ProviderType { get; set; }

    /// <summary>
    /// Provider-specific configuration key/value pairs.
    /// For Keycloak: "realm", "clientId", "clientSecret".
    /// Other providers define their own keys.
    /// </summary>
    public Dictionary<string, string> ProviderMetadata { get; set; } = new();
}
