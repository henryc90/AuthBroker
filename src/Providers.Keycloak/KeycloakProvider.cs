using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthBroker.Core;
using AuthBroker.Core.Models;
using Microsoft.Extensions.Options;

namespace AuthBroker.Providers.Keycloak;

/// <summary>
/// Implements <see cref="IAuthProvider"/> against Keycloak's OIDC endpoints and Admin REST API.
/// Global connection settings (BaseUrl, AdminUrl) come from <see cref="KeycloakConfig"/>.
/// Per-tenant settings (realm, clientId, clientSecret) come from <see cref="TenantConfig.ProviderMetadata"/>.
/// OIDC discovery documents are cached per realm.
/// </summary>
public class KeycloakProvider : IAuthProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly KeycloakConfig _config;
    private readonly IOptionsMonitor<TenantConfig> _tenantConfigMonitor;
    private readonly ConcurrentDictionary<string, OidcDiscovery> _discoveryCache = new();

    public KeycloakProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<KeycloakConfig> config,
        IOptionsMonitor<TenantConfig> tenantConfigMonitor)
    {
        _httpClientFactory = httpClientFactory;
        _config = config.Value;
        _tenantConfigMonitor = tenantConfigMonitor;
    }

    // ---------------------------------------------------------------
    //  IAuthProvider implementation
    // ---------------------------------------------------------------

    public async Task<IAuthResult<AuthResponse>> LoginAsync(AuthRequest request)
    {
        try
        {
            var tenant = GetTenant(request.TenantId);
            var realmUrl = RealmUrl(tenant);
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            var discovery = await GetDiscoveryAsync(realmUrl);
            var client = _httpClientFactory.CreateClient();

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = request.Username,
                ["password"] = request.Password,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = "openid"
            };

            var httpResponse = await client.PostAsync(
                discovery.TokenEndpoint, new FormUrlEncodedContent(formData));

            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<AuthResponse>(401, "Invalid credentials");

            httpResponse.EnsureSuccessStatusCode();

            var tokenResponse = await httpResponse.Content
                .ReadFromJsonAsync<KeycloakTokenResponse>();

            if (tokenResponse is null)
                return new AuthErrorResult<AuthResponse>(502, "Invalid response from provider");

            var authResponse = MapToAuthResponse(tokenResponse);
            EnrichResponse(authResponse, tenant);

            return new AuthSuccessResult<AuthResponse>(authResponse);
        }
        catch (HttpRequestException)
        {
            return new AuthErrorResult<AuthResponse>(503, "Provider unavailable");
        }
    }

    public async Task<IAuthResult<AuthResponse>> RegisterAsync(AuthRequest request)
    {
        try
        {
            var tenant = GetTenant(request.TenantId);
            var realmUrl = RealmUrl(tenant);
            var realm = tenant.ProviderMetadata.GetValueOrDefault("realm", "");
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            var discovery = await GetDiscoveryAsync(realmUrl);
            var client = _httpClientFactory.CreateClient();

            // Step 1: Obtain an admin token via client_credentials grant
            var adminFormData = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret
            };

            var adminTokenResponse = await client.PostAsync(
                discovery.TokenEndpoint, new FormUrlEncodedContent(adminFormData));

            if (!adminTokenResponse.IsSuccessStatusCode)
                return new AuthErrorResult<AuthResponse>(502, "Failed to obtain admin token");

            var adminTokenJson = await adminTokenResponse.Content.ReadFromJsonAsync<KeycloakTokenResponse>();

            var adminToken = adminTokenJson?.AccessToken ?? string.Empty;

            // Step 2: Create the user via Keycloak Admin REST API
            var userPayload = new
            {
                username = request.Username,
                enabled = true,
                credentials = new[]
                {
                    new
                    {
                        type = "password",
                        value = request.Password,
                        temporary = false
                    }
                }
            };

            var createRequest = new HttpRequestMessage(
                HttpMethod.Post,
                $"{_config.AdminUrl}/admin/realms/{realm}/users")
            {
                Content = JsonContent.Create(userPayload),
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) }
            };

            var createResponse = await client.SendAsync(createRequest);
            if (!createResponse.IsSuccessStatusCode)
                return new AuthErrorResult<AuthResponse>(502, "Failed to create user");

            // Step 3: Login as the newly created user
            return await LoginAsync(request);
        }
        catch (HttpRequestException)
        {
            return new AuthErrorResult<AuthResponse>(503, "Provider unavailable");
        }
    }

    public async Task<IAuthResult<AuthResponse>> RefreshTokenAsync(string refreshToken, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var realmUrl = RealmUrl(tenant);
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            var discovery = await GetDiscoveryAsync(realmUrl);
            var client = _httpClientFactory.CreateClient();

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret
            };

            var httpResponse = await client.PostAsync(
                discovery.TokenEndpoint, new FormUrlEncodedContent(formData));

            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<AuthResponse>(401, "Invalid or expired refresh token");

            httpResponse.EnsureSuccessStatusCode();

            var tokenResponse = await httpResponse.Content
                .ReadFromJsonAsync<KeycloakTokenResponse>();

            if (tokenResponse is null)
                return new AuthErrorResult<AuthResponse>(502, "Invalid response from provider");

            var authResponse = MapToAuthResponse(tokenResponse);

            // Enrich the refreshed token with tenant claims
            EnrichResponse(authResponse, tenant);

            return new AuthSuccessResult<AuthResponse>(authResponse);
        }
        catch (HttpRequestException)
        {
            return new AuthErrorResult<AuthResponse>(503, "Provider unavailable");
        }
    }

    public async Task<IAuthResult> LogoutAsync(string refreshToken, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var realmUrl = RealmUrl(tenant);
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            var discovery = await GetDiscoveryAsync(realmUrl);
            var client = _httpClientFactory.CreateClient();

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "revoke_token",
                ["token"] = refreshToken,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret
            };

            // Best-effort logout — ignore failures so the client always gets a clean response
            _ = await client.PostAsync(discovery.TokenEndpoint, new FormUrlEncodedContent(formData));
        }
        catch (HttpRequestException)
        {
            // Swallow — logout is best-effort
        }

        return new AuthSuccessResult();
    }

    public async Task<IAuthResult<ValidationResult>> ValidateTokenAsync(string accessToken, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var realmUrl = RealmUrl(tenant);

            var discovery = await GetDiscoveryAsync(realmUrl);
            var client = _httpClientFactory.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserinfoEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthSuccessResult<ValidationResult>(
                    new ValidationResult
                    {
                        IsValid = false,
                        FailureReason = "Token expired or invalid"
                    });

            if (!response.IsSuccessStatusCode)
                return new AuthSuccessResult<ValidationResult>(
                    new ValidationResult
                    {
                        IsValid = false,
                        FailureReason = $"Token validation failed with status {response.StatusCode}"
                    });

            var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();
            var claims = new List<Claim>();

            foreach (var property in userInfo.EnumerateObject())
            {
                claims.Add(new Claim(property.Name, property.Value.ToString() ?? string.Empty));
            }

            var identity = new ClaimsIdentity(claims, "Keycloak");
            var principal = new ClaimsPrincipal(identity);

            return new AuthSuccessResult<ValidationResult>(
                new ValidationResult
                {
                    IsValid = true,
                    Principal = principal
                });
        }
        catch (HttpRequestException)
        {
            return new AuthSuccessResult<ValidationResult>(
                new ValidationResult
                {
                    IsValid = false,
                    FailureReason = "Provider unavailable"
                });
        }
    }

    public async Task<IAuthResult<UserProfile>> GetUserProfileAsync(string accessToken, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var realmUrl = RealmUrl(tenant);

            var discovery = await GetDiscoveryAsync(realmUrl);
            var client = _httpClientFactory.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserinfoEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<UserProfile>(401, "Token expired or invalid");

            response.EnsureSuccessStatusCode();

            var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();
            var profile = MapToUserProfile(userInfo);

            return new AuthSuccessResult<UserProfile>(profile);
        }
        catch (HttpRequestException)
        {
            return new AuthErrorResult<UserProfile>(503, "Provider unavailable");
        }
    }

    // ---------------------------------------------------------------
    //  Internal helpers
    // ---------------------------------------------------------------

    private TenantConfig GetTenant(string tenantId)
    {
        return _tenantConfigMonitor.Get(tenantId)
            ?? throw new InvalidOperationException($"Tenant '{tenantId}' not found");
    }

    private static (string clientId, string clientSecret) GetClientCredentials(TenantConfig tenant)
    {
        var clientId = tenant.ProviderMetadata.GetValueOrDefault("clientId", "");
        var clientSecret = tenant.ProviderMetadata.GetValueOrDefault("clientSecret", "");
        return (clientId, clientSecret);
    }

    private string RealmUrl(TenantConfig tenant)
    {
        var realm = tenant.ProviderMetadata.GetValueOrDefault("realm", "");
        return $"{_config.BaseUrl}/realms/{realm}";
    }

    /// <summary>
    /// Fetches (and caches) the OIDC discovery document for the given realm URL.
    /// Cache is per-realm, so each tenant gets its own cached document.
    /// </summary>
    private async Task<OidcDiscovery> GetDiscoveryAsync(string realmUrl)
    {
        if (_discoveryCache.TryGetValue(realmUrl, out var cached))
            return cached;

        var client = _httpClientFactory.CreateClient();
        var response = await client.GetAsync(
            $"{realmUrl}/.well-known/openid-configuration");

        response.EnsureSuccessStatusCode();

        var discovery = await response.Content.ReadFromJsonAsync<OidcDiscovery>()
            ?? throw new InvalidOperationException(
                "OIDC discovery returned null. Check the realm configuration.");

        _discoveryCache[realmUrl] = discovery;
        return discovery;
    }

    /// <summary>
    /// Injects tenant metadata (<c>tenant_id</c>, <c>tenant_name</c>, <c>tenant_domain</c>)
    /// into the <see cref="AuthResponse.EnrichedClaims"/> dictionary.
    /// </summary>
    private static void EnrichResponse(AuthResponse response, TenantConfig tenant)
    {
        response.EnrichedClaims ??= new Dictionary<string, object>();
        response.EnrichedClaims["tenant_id"] = tenant.TenantId;
        response.EnrichedClaims["tenant_name"] = tenant.TenantName;

        if (!string.IsNullOrEmpty(tenant.TenantDomain))
            response.EnrichedClaims["tenant_domain"] = tenant.TenantDomain;
    }

    /// <summary>
    /// Maps a <see cref="KeycloakTokenResponse"/> to an <see cref="AuthResponse"/>.
    /// </summary>
    private static AuthResponse MapToAuthResponse(KeycloakTokenResponse tokenResponse)
    {
        return new AuthResponse
        {
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken,
            ExpiresIn = tokenResponse.ExpiresIn,
            TokenType = string.IsNullOrEmpty(tokenResponse.TokenType)
                ? "Bearer"
                : tokenResponse.TokenType
        };
    }

    /// <summary>
    /// Maps the userinfo <see cref="JsonElement"/> to a <see cref="UserProfile"/>.
    /// </summary>
    private static UserProfile MapToUserProfile(JsonElement userInfo)
    {
        var profile = new UserProfile
        {
            Id = userInfo.TryGetProperty("sub", out var sub)
                ? sub.GetString() ?? string.Empty
                : string.Empty,
            Username = userInfo.TryGetProperty("preferred_username", out var username)
                ? username.GetString() ?? string.Empty
                : string.Empty,
            Email = userInfo.TryGetProperty("email", out var email)
                ? email.GetString() ?? string.Empty
                : string.Empty,
        };

        // Extract roles from realm_access.roles (Keycloak-specific)
        if (userInfo.TryGetProperty("realm_access", out var realmAccess) &&
            realmAccess.TryGetProperty("roles", out var rolesElement) &&
            rolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var role in rolesElement.EnumerateArray())
            {
                var roleValue = role.GetString();
                if (roleValue is not null)
                    profile.Roles.Add(roleValue);
            }
        }

        return profile;
    }
}

// ---------------------------------------------------------------
//  Internal models (Keycloak-specific wire formats)
// ---------------------------------------------------------------

/// <summary>
/// Keycloak token endpoint response.
/// </summary>
internal class KeycloakTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";
}
