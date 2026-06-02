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
/// Each tenant is configured via <see cref="Auth0TenantConfig"/> from the <c>Auth</c> array.
/// OIDC discovery documents are cached per domain.
/// </summary>
public class Auth0Provider : IAuthProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsMonitor<Auth0TenantConfig> _tenantConfigMonitor;
    private readonly ConcurrentDictionary<string, OidcDiscovery> _discoveryCache = new();

    public Auth0Provider(
        IHttpClientFactory httpClientFactory,
        IOptionsMonitor<Auth0TenantConfig> tenantConfigMonitor)
    {
        _httpClientFactory = httpClientFactory;
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
            var domainUrl = $"https://{tenant.Domain}";

            if (string.IsNullOrEmpty(tenant.ClientId) || string.IsNullOrEmpty(tenant.ClientSecret))
                return new AuthErrorResult<AuthResponse>(502, "Provider configuration incomplete: missing client credentials");

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = request.Username,
                ["password"] = request.Password,
                ["client_id"] = tenant.ClientId,
                ["client_secret"] = tenant.ClientSecret,
                ["scope"] = "openid offline_access"
            };

            if (!string.IsNullOrEmpty(tenant.Audience))
                formData["audience"] = tenant.Audience;

            var client = _httpClientFactory.CreateClient();
            var httpResponse = await client.PostAsync($"{domainUrl}/oauth/token", new FormUrlEncodedContent(formData));

            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<AuthResponse>(401, "Invalid credentials");
            if (!httpResponse.IsSuccessStatusCode)
            {
                return new AuthErrorResult<AuthResponse>((int)httpResponse.StatusCode, await httpResponse.Content.ReadAsStringAsync());
                
            }
            var tokenResponse = await httpResponse.Content
                .ReadFromJsonAsync<Auth0TokenResponse>();

            if (tokenResponse is null)
                return new AuthErrorResult<AuthResponse>(502, "Invalid response from provider");

            var authResponse = MapToAuthResponse(tokenResponse);
            EnrichResponse(authResponse, tenant);

            return new AuthSuccessResult<AuthResponse>(authResponse);
        }
        catch (Exception e)
        {
            return new AuthErrorResult<AuthResponse>(503, "Provider unavailable");
        }
    }

    public async Task<IAuthResult<RegisterResponse>> RegisterAsync(AuthRequest request)
    {
        try
        {
            var tenant = GetTenant(request.TenantId);

            if (string.IsNullOrEmpty(tenant.ClientId) || string.IsNullOrEmpty(tenant.ClientSecret))
                return new AuthErrorResult<RegisterResponse>(502, "Provider configuration incomplete: missing client credentials");

            var formData = new Dictionary<string, string>
            {
                ["client_id"] = tenant.ClientId,
                ["email"] = request.Email,
                ["username"] = request.Username,
                ["password"] = request.Password,
                ["connection"] = "Username-Password-Authentication"
            };

            var client = _httpClientFactory.CreateClient();
            var content = new StringContent(JsonSerializer.Serialize(formData), Encoding.UTF8, "application/json");
            var httpResponse = await client.PostAsync($"https://{tenant.Domain}/dbconnections/signup", content);

            if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                return new AuthErrorResult<RegisterResponse>(401, "Invalid credentials");

            if (!httpResponse.IsSuccessStatusCode)
            {
                var error = await httpResponse.Content.ReadAsStringAsync();
                throw new Exception(error);
            }

            var auth0RegisterResponse = await httpResponse.Content.ReadFromJsonAsync<Auth0RegisterResponse>();

            if (auth0RegisterResponse is null)
                return new AuthErrorResult<RegisterResponse>(502, "Invalid response from provider");

            return new AuthSuccessResult<RegisterResponse>(new RegisterResponse
            {
                Id = auth0RegisterResponse.Id,
                Email = auth0RegisterResponse.Email
            });
        }
        catch (HttpRequestException)
        {
            return new AuthErrorResult<RegisterResponse>(503, "Provider unavailable");
        }
        catch (Exception e)
        {
            return new AuthErrorResult<RegisterResponse>(503, e.Message);
        }
    }

    public async Task<IAuthResult<AuthResponse>> RefreshTokenAsync(string refreshToken, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var domainUrl = $"https://{tenant.Domain}";

            if (string.IsNullOrEmpty(tenant.ClientId) || string.IsNullOrEmpty(tenant.ClientSecret))
                return new AuthErrorResult<AuthResponse>(502, "Provider configuration incomplete: missing client credentials");

            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = tenant.ClientId,
                ["client_secret"] = tenant.ClientSecret
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
            var domainUrl = $"https://{tenant.Domain}";

            if (string.IsNullOrEmpty(tenant.ClientId) || string.IsNullOrEmpty(tenant.ClientSecret))
                return new AuthErrorResult(502, "Provider configuration incomplete: missing client credentials");

            var client = _httpClientFactory.CreateClient();
            var formData = new Dictionary<string, string>
            {
                ["token"] = refreshToken,
                ["client_id"] = tenant.ClientId,
                ["client_secret"] = tenant.ClientSecret
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
            var domainUrl = $"https://{tenant.Domain}";

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
            var domainUrl = $"https://{tenant.Domain}";

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

    public async Task<IAuthResult> ConfirmEmailAsync(string id, string tenantId)
    {
        try
        {
            var tenant = GetTenant(tenantId);
            var domainUrl = $"https://{tenant.Domain}";

            // 1. Get Management API token
            var mgmtToken = await GetManagementApiTokenAsync(domainUrl, tenant.ClientId, tenant.ClientSecret);

            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", mgmtToken);

            // 2. Mark email as verified
            var patchBody = new StringContent( JsonSerializer.Serialize(new { email_verified = true }), Encoding.UTF8, "application/json");
            
            if (!id.ToLower().StartsWith("auth0|"))
                id = $"auth0|{id}";

            var patchResponse = await client.PatchAsync(
                $"{domainUrl}/api/v2/users/{id}", patchBody);

            if (!patchResponse.IsSuccessStatusCode) {
                return new AuthErrorResult(502, await patchResponse.Content.ReadAsStringAsync());
            }

            return new AuthSuccessResult();
        }
        catch (HttpRequestException)
        {
            return new AuthErrorResult(503, "Provider unavailable");
        }
    }

    // ---------------------------------------------------------------
    //  Internal helpers
    // ---------------------------------------------------------------

    private Auth0TenantConfig GetTenant(string tenantId)
    {
        return _tenantConfigMonitor.Get(tenantId)
            ?? throw new InvalidOperationException($"Tenant '{tenantId}' not found");
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
    /// Obtains a Management API access token using client credentials grant.
    /// </summary>
    private async Task<string> GetManagementApiTokenAsync(string domainUrl, string clientId, string clientSecret)
    {
        var client = _httpClientFactory.CreateClient();
        var formData = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["audience"] = $"{domainUrl}/api/v2/"
        };

        var response = await client.PostAsync(
            $"{domainUrl}/oauth/token", new FormUrlEncodedContent(formData));

        response.EnsureSuccessStatusCode();

        var tokenResponse = await response.Content.ReadFromJsonAsync<ManagementApiTokenResponse>()
            ?? throw new InvalidOperationException("Failed to get Management API token");

        return tokenResponse.AccessToken;
    }

    /// <summary>
    /// Injects tenant metadata (<c>tenant_id</c>, <c>tenant_name</c>, <c>tenant_domain</c>)
    /// into the <see cref="AuthResponse.EnrichedClaims"/> dictionary.
    /// </summary>
    private static void EnrichResponse(AuthResponse response, Auth0TenantConfig tenant)
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
    private static UserProfile MapToUserProfile(JsonElement userInfo, Auth0TenantConfig tenant)
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

        var rolesClaim = !string.IsNullOrEmpty(tenant.RolesClaim)
            ? tenant.RolesClaim
            : "https://schemas.auth0.com/roles";

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

internal class ManagementApiTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;
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
