using AuthBroker.Core;

namespace AuthBroker.Providers.Auth0;

/// <summary>
/// Global Auth0 connection configuration (shared across all tenants).
/// Per-tenant settings (domain, clientId, clientSecret) come from TenantConfig.ProviderMetadata.
/// </summary>
public class Auth0Config
{
    public string Domain { get; set; }
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string Audience { get; set; }
    public string RolesClaim { get; set; }
}