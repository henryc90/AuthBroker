using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthBroker.Core;
using AuthBroker.Core.Models;
using Microsoft.Extensions.Options;

namespace AuthBroker.Providers.Auth0;

/// <summary>
/// Implements <see cref="IAuthProvider"/> against Auth0's OIDC endpoints and auth API.
/// Global connection settings (DefaultDomain) come from <see cref="Auth0Config"/>.
/// Per-tenant settings (domain, clientId, clientSecret, audience) come from <see cref="TenantConfig.ProviderMetadata"/>.
/// OIDC discovery documents are cached per domain.
/// </summary>
public class Auth0Provider : IAuthProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly Auth0Config _config;
    private readonly IOptionsMonitor<TenantConfig> _tenantConfigMonitor;
    private readonly ConcurrentDictionary<string, OidcDiscovery> _discoveryCache = new();

    public Auth0Provider(
        IHttpClientFactory httpClientFactory,
        IOptions<Auth0Config> config,
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
            var domain = GetTenantDomain(tenant);
            var domainUrl = $"https://{domain}";
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                return new AuthErrorResult<AuthResponse>(502, "Provider configuration incomplete: missing client credentials");

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = request.Username,
                ["password"] = request.Password,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = "openid offline_access"
            };

            // Add audience if configured for this tenant
            if (tenant.ProviderMetadata.TryGetValue("audience", out var audience) && !string.IsNullOrEmpty(audience))
            {
                formData["audience"] = audience;
            }

            var client = _httpClientFactory.CreateClient();
            var httpResponse = await client.PostAsync($"{domainUrl}/oauth/token", new FormUrlEncodedContent(formData));

            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<AuthResponse>(401, "Invalid credentials");

            httpResponse.EnsureSuccessStatusCode();

            var tokenResponse = await httpResponse.Content
                .ReadFromJsonAsync<Auth0TokenResponse>();

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
            if (string.IsNullOrEmpty(_config.ClientId) || string.IsNullOrEmpty(_config.ClientSecret))
                return new AuthErrorResult<AuthResponse>(502, "Provider configuration incomplete: missing client credentials");

            var formData = new Dictionary<string, string>
            {
                ["client_id"] = _config.ClientId,
                ["email"] = request.Username,
                ["password"] = request.Password,
                ["connection"] = "Username-Password-Authentication"//TODO: make connection configurable per tenant if needed
            };

            var client = _httpClientFactory.CreateClient();
            HttpContent content = new StringContent(JsonSerializer.Serialize(formData), Encoding.UTF8, "application/json");
            var httpResponse = await client.PostAsync($"https://{_config.Domain}/dbconnections/signup", content);
            //https://dev-2t325rkudymr1htg.us.auth0.com/dbconnections/signup
            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<AuthResponse>(401, "Invalid credentials");
            if (!httpResponse.IsSuccessStatusCode)
            {
                string error = await httpResponse.Content.ReadAsStringAsync();
                throw new Exception(error);
            }
            
            var auth0RegisterResponse = await httpResponse.Content.ReadFromJsonAsync<Auth0RegisterResponse>();

            if (auth0RegisterResponse is null)
                return new AuthErrorResult<AuthResponse>(502, "Invalid response from provider");


            return new AuthSuccessResult<AuthResponse>(new AuthResponse() { });
        }
        catch (HttpRequestException e)
        {
            return new AuthErrorResult<AuthResponse>(503, "Provider unavailable");
        }
        catch (Exception e)
        {
            return new AuthErrorResult<AuthResponse>(503, e.Message);
        }
        throw new NotSupportedException(
            "Auth0 registration requires the Management API and is not supported in this version.");
    }

    public async Task<IAuthResult<AuthResponse>> RefreshTokenAsync(string refreshToken, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var domain = GetTenantDomain(tenant);
            var domainUrl = $"https://{domain}";
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                return new AuthErrorResult<AuthResponse>(502, "Provider configuration incomplete: missing client credentials");

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret
            };

            var client = _httpClientFactory.CreateClient();
            var httpResponse = await client.PostAsync(
                $"{domainUrl}/oauth/token", new FormUrlEncodedContent(formData));

            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<AuthResponse>(401, "Invalid or expired refresh token");

            httpResponse.EnsureSuccessStatusCode();

            var tokenResponse = await httpResponse.Content
                .ReadFromJsonAsync<Auth0TokenResponse>();

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
            var domain = GetTenantDomain(tenant);
            var domainUrl = $"https://{domain}";
            var (clientId, clientSecret) = GetClientCredentials(tenant);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                return new AuthErrorResult(502, "Provider configuration incomplete: missing client credentials");

            var client = _httpClientFactory.CreateClient();
            var formData = new Dictionary<string, string>
            {
                ["token"] = refreshToken,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret
            };

            // Best-effort logout via token revocation — swallow failures
            _ = await client.PostAsync(
                $"{domainUrl}/oauth/revoke", new FormUrlEncodedContent(formData));
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
            var domain = GetTenantDomain(tenant);
            var domainUrl = $"https://{domain}";

            var discovery = await GetDiscoveryAsync(domainUrl);
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

            var identity = new ClaimsIdentity(claims, "Auth0");
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
            var domain = GetTenantDomain(tenant);
            var domainUrl = $"https://{domain}";

            var discovery = await GetDiscoveryAsync(domainUrl);
            var client = _httpClientFactory.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserinfoEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<UserProfile>(401, "Token expired or invalid");

            response.EnsureSuccessStatusCode();

            var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();
            var profile = MapToUserProfile(userInfo, tenant);

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

    /// <summary>
    /// Extracts the Auth0 domain from tenant metadata, falling back to the global default.
    /// Returns just the domain name (e.g., "my-tenant.us.auth0.com") — without protocol.
    /// </summary>
    private string GetTenantDomain(TenantConfig tenant)
    {
        if (tenant.ProviderMetadata.TryGetValue("domain", out var domain) &&
            !string.IsNullOrEmpty(domain))
            return domain;
            throw new InvalidOperationException(
                "Auth0 domain not configured. Set 'domain' in tenant ProviderMetadata or configure DefaultDomain in Auth0Config.");
    }

    /// <summary>
    /// Fetches (and caches) the OIDC discovery document for the given Auth0 domain URL.
    /// Cache is per-domain, so each tenant gets its own cached document.
    /// </summary>
    private async Task<OidcDiscovery> GetDiscoveryAsync(string domainUrl)
    {
        if (_discoveryCache.TryGetValue(domainUrl, out var cached))
            return cached;

        var client = _httpClientFactory.CreateClient();
        var response = await client.GetAsync(
            $"{domainUrl}/.well-known/openid-configuration");

        response.EnsureSuccessStatusCode();

        var discovery = await response.Content.ReadFromJsonAsync<OidcDiscovery>()
            ?? throw new InvalidOperationException(
                "OIDC discovery returned null. Check the Auth0 domain configuration.");

        _discoveryCache[domainUrl] = discovery;
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
    /// Maps an <see cref="Auth0TokenResponse"/> to an <see cref="AuthResponse"/>.
    /// </summary>
    private static AuthResponse MapToAuthResponse(Auth0TokenResponse tokenResponse)
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
    /// Auth0-specific: uses <c>sub</c>, <c>email</c>, <c>nickname</c>/<c>preferred_username</c>,
    /// and a configurable roles claim path (default: <c>https://schemas.auth0.com/roles</c>).
    /// </summary>
    private static UserProfile MapToUserProfile(JsonElement userInfo, TenantConfig tenant)
    {
        var profile = new UserProfile
        {
            Id = userInfo.TryGetProperty("sub", out var sub)
                ? sub.GetString() ?? string.Empty
                : string.Empty,
            Username = userInfo.TryGetProperty("nickname", out var nickname)
                ? nickname.GetString() ?? string.Empty
                : userInfo.TryGetProperty("preferred_username", out var preferred)
                    ? preferred.GetString() ?? string.Empty
                    : string.Empty,
            Email = userInfo.TryGetProperty("email", out var email)
                ? email.GetString() ?? string.Empty
                : string.Empty,
        };

        // Extract roles from a configurable claim path (Auth0-specific)
        var rolesClaim = tenant.ProviderMetadata.GetValueOrDefault(
            "rolesClaim", "https://schemas.auth0.com/roles");

        if (userInfo.TryGetProperty(rolesClaim, out var rolesElement) &&
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
//  Internal models (Auth0-specific wire formats)
// ---------------------------------------------------------------

/// <summary>
/// Auth0 token endpoint response.
/// </summary>
internal class Auth0TokenResponse
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

internal class Auth0RegisterResponse
{
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("email_verified")]
    public bool EmailVerified { get; set; }

    [JsonPropertyName("_id")]
    public string Id { get; set; } = string.Empty;

}
