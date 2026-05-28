using System.Text.Json.Serialization;

namespace AuthBroker.Core.Models;

/// <summary>
/// OIDC Discovery document — only the fields we consume.
/// Shared across all auth providers (Keycloak, Auth0, etc.).
/// </summary>
public class OidcDiscovery
{
    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; set; } = string.Empty;

    [JsonPropertyName("userinfo_endpoint")]
    public string UserinfoEndpoint { get; set; } = string.Empty;
}
