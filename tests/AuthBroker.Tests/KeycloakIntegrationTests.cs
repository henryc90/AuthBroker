using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthBroker.Core;
using AuthBroker.Core.Models;
using AuthBroker.Providers.Keycloak;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using Testcontainers.Keycloak;

namespace AuthBroker.Tests;

/// <summary>
/// End-to-end integration tests against a real Keycloak instance running in a container.
/// Requires Docker to be available on the test host.
/// </summary>
public class KeycloakIntegrationTests : IAsyncLifetime
{
    private const string RealmName = "test-realm";
    private const string ClientId = "test-client";
    private const string ClientSecret = "test-secret-for-client";
    private const string TestUsername = "testuser";
    private const string TestPassword = "testpass123";

    private readonly KeycloakContainer _keycloakContainer;
    private string _baseUrl = string.Empty;

    public KeycloakIntegrationTests()
    {
        _keycloakContainer = new KeycloakBuilder("quay.io/keycloak/keycloak:26.1")
            .WithUsername("admin")
            .WithPassword("admin")
            .WithPortBinding(8080, true)
            .Build();
    }

    public async Task InitializeAsync()
    {
        // Start container
        await _keycloakContainer.StartAsync();

        var host = _keycloakContainer.Hostname;
        var port = _keycloakContainer.GetMappedPublicPort(8080);
        _baseUrl = $"http://{host}:{port}";

        // Bootstrap: create realm, client, and user via admin API
        await BootstrapKeycloakAsync();
    }

    public async Task DisposeAsync()
    {
        await _keycloakContainer.DisposeAsync();
    }

    // ---------------------------------------------------------------
    //  Tests
    // ---------------------------------------------------------------

    [Fact]
    public async Task Login_returns_tokens()
    {
        // Arrange
        var provider = CreateProvider();

        // Act
        var result = await provider.LoginAsync(
            new AuthRequest(TestUsername, TestPassword, RealmName));

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.AccessToken.Should().NotBeNullOrEmpty();
        result.Data.RefreshToken.Should().NotBeNullOrEmpty();
        result.Data.ExpiresIn.Should().BeGreaterThan(0);
        result.Data.TokenType.Should().Be("Bearer");
    }

    [Fact]
    public async Task Refresh_returns_new_tokens()
    {
        // Arrange
        var provider = CreateProvider();
        var loginResult = await provider.LoginAsync(
            new AuthRequest(TestUsername, TestPassword, RealmName));
        loginResult.IsSuccess.Should().BeTrue();

        // Act
        var refreshResult = await provider.RefreshTokenAsync(loginResult.Data!.RefreshToken, RealmName);

        // Assert
        refreshResult.IsSuccess.Should().BeTrue();
        refreshResult.Data.Should().NotBeNull();
        refreshResult.Data!.AccessToken.Should().NotBeNullOrEmpty();
        refreshResult.Data.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_invalid_credentials_returns_401()
    {
        // Arrange
        var provider = CreateProvider();

        // Act
        var result = await provider.LoginAsync(
            new AuthRequest(TestUsername, "wrong-password", RealmName));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Invalid credentials");
    }

    [Fact]
    public async Task GetUserProfile_returns_mapped_profile()
    {
        // Arrange
        var provider = CreateProvider();
        var loginResult = await provider.LoginAsync(
            new AuthRequest(TestUsername, TestPassword, RealmName));
        loginResult.IsSuccess.Should().BeTrue();

        // Act
        var profileResult = await provider.GetUserProfileAsync(loginResult.Data!.AccessToken, RealmName);

        // Assert
        profileResult.IsSuccess.Should().BeTrue();
        profileResult.Data.Should().NotBeNull();
        profileResult.Data!.Username.Should().Be(TestUsername);
        profileResult.Data.Email.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Logout_succeeds()
    {
        // Arrange
        var provider = CreateProvider();
        var loginResult = await provider.LoginAsync(
            new AuthRequest(TestUsername, TestPassword, RealmName));
        loginResult.IsSuccess.Should().BeTrue();

        // Act
        var logoutResult = await provider.LogoutAsync(loginResult.Data!.RefreshToken, RealmName);

        // Assert
        logoutResult.IsSuccess.Should().BeTrue();
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    /// <summary>
    /// Creates a <see cref="KeycloakProvider"/> wired to the running container.
    /// </summary>
    private KeycloakProvider CreateProvider()
    {
        var httpClient = new HttpClient();
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var config = Options.Create(new KeycloakConfig
        {
            BaseUrl = _baseUrl,
            AdminUrl = _baseUrl
        });

        var tenantMonitorMock = new Mock<IOptionsMonitor<TenantConfig>>();
        tenantMonitorMock.Setup(m => m.Get(It.IsAny<string>()))
            .Returns(new TenantConfig
            {
                TenantId = RealmName,
                TenantName = "Test Realm",
                TenantDomain = "test.local",
                ProviderType = ProviderType.Keycloak,
                ProviderMetadata = new()
                {
                    ["realm"] = RealmName,
                    ["clientId"] = ClientId,
                    ["clientSecret"] = ClientSecret
                }
            });

        return new KeycloakProvider(factoryMock.Object, config, tenantMonitorMock.Object);
    }

    /// <summary>
    /// Bootstraps the Keycloak instance with a realm, client, and user.
    /// </summary>
    private async Task BootstrapKeycloakAsync()
    {
        using var adminClient = new HttpClient();
        var adminToken = await GetAdminTokenAsync(adminClient);

        await CreateRealmAsync(adminClient, adminToken);
        await CreateClientAsync(adminClient, adminToken);
        await CreateUserAsync(adminClient, adminToken);
    }

    private async Task<string> GetAdminTokenAsync(HttpClient client)
    {
        var formData = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = "admin",
            ["password"] = "admin",
            ["client_id"] = "admin-cli"
        };

        var response = await client.PostAsync(
            $"{_baseUrl}/realms/master/protocol/openid-connect/token",
            new FormUrlEncodedContent(formData));

        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("access_token").GetString()!;
    }

    private async Task CreateRealmAsync(HttpClient client, string adminToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/admin/realms")
        {
            Content = JsonContent.Create(new
            {
                id = RealmName,
                realm = RealmName,
                enabled = true
            }),
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) }
        };

        var response = await client.SendAsync(request);
        response.StatusCode.Should().BeOneOf(HttpStatusCode.Created, HttpStatusCode.Conflict);
    }

    private async Task CreateClientAsync(HttpClient client, string adminToken)
    {
        // First check if the client already exists
        var checkRequest = new HttpRequestMessage(
            HttpMethod.Get,
            $"{_baseUrl}/admin/realms/{RealmName}/clients?clientId={ClientId}")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) }
        };
        var checkResponse = await client.SendAsync(checkRequest);
        var existingClients = await checkResponse.Content.ReadFromJsonAsync<JsonElement>();
        if (existingClients.ValueKind == JsonValueKind.Array && existingClients.GetArrayLength() > 0)
            return; // Client already exists

        var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"{_baseUrl}/admin/realms/{RealmName}/clients")
        {
            Content = JsonContent.Create(new
            {
                clientId = ClientId,
                enabled = true,
                publicClient = false,
                secret = ClientSecret,
                serviceAccountsEnabled = true,
                directAccessGrantsEnabled = true,
                standardFlowEnabled = false,
                authorizationServicesEnabled = false,
                redirectUris = new[] { "*" }
            }),
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) }
        };

        var response = await client.SendAsync(request);
        // 409 Conflict is acceptable if the client was created in a previous attempt
        response.StatusCode.Should().BeOneOf(HttpStatusCode.Created, HttpStatusCode.Conflict);
    }

    private async Task CreateUserAsync(HttpClient client, string adminToken)
    {
        // Helper: find user ID by username
        async Task<string?> FindUserId()
        {
            var req = new HttpRequestMessage(HttpMethod.Get,
                $"{_baseUrl}/admin/realms/{RealmName}/users?username={TestUsername}")
            { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) } };
            var resp = await client.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
            return json.ValueKind == JsonValueKind.Array && json.GetArrayLength() > 0
                ? json[0].GetProperty("id").GetString()
                : null;
        }

        // Skip if user already exists
        if (await FindUserId() is not null)
            return;

        // Step 1: Create user with all required fields
        // NOTE: Keycloak 26+ requires firstName+lastName for password grant
        // (see https://github.com/keycloak/keycloak/issues/36108)
        var createPayload = new
        {
            username = TestUsername,
            email = $"{TestUsername}@test.local",
            emailVerified = true,
            firstName = "Test",
            lastName = "User",
            enabled = true,
            requiredActions = Array.Empty<string>()
        };

        var createRequest = new HttpRequestMessage(HttpMethod.Post,
            $"{_baseUrl}/admin/realms/{RealmName}/users")
        {
            Content = JsonContent.Create(createPayload),
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) }
        };
        var createResp = await client.SendAsync(createRequest);
        createResp.StatusCode.Should().BeOneOf(HttpStatusCode.Created, HttpStatusCode.Conflict);

        // Step 2: Get user ID
        var userId = await FindUserId();
        userId.Should().NotBeNull();

        // Step 3: Set password via reset-password
        var passwordPayload = new { type = "password", value = TestPassword, temporary = false };
        var pwReq = new HttpRequestMessage(HttpMethod.Put,
            $"{_baseUrl}/admin/realms/{RealmName}/users/{userId}/reset-password")
        {
            Content = JsonContent.Create(passwordPayload),
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", adminToken) }
        };
        var pwResp = await client.SendAsync(pwReq);
        pwResp.StatusCode.Should().BeOneOf(HttpStatusCode.NoContent, HttpStatusCode.OK);
    }
}
