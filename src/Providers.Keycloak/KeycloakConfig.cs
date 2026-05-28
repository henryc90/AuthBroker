namespace AuthBroker.Providers.Keycloak;

/// <summary>
/// Global Keycloak connection configuration (shared across all tenants).
/// Per-tenant settings (realm, clientId, clientSecret) come from TenantConfig.ProviderMetadata.
/// </summary>
public class KeycloakConfig
{
    /// <summary>
    /// Keycloak base URL, e.g. "http://localhost:8080".
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Keycloak admin API URL, e.g. "http://localhost:8080".
    /// </summary>
    public string AdminUrl { get; set; } = string.Empty;
}
