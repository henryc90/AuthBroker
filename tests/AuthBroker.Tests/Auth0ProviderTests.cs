using System.Net;
using AuthBroker.Core;
using AuthBroker.Core.Models;
using AuthBroker.Providers.Auth0;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;

namespace AuthBroker.Tests;

public class Auth0ProviderTests
{
    private const string Auth0Domain = "test.us.auth0.com";
    private const string DiscoveryUrl = "https://test.us.auth0.com/.well-known/openid-configuration";
    private const string TokenEndpoint = "https://test.us.auth0.com/oauth/token";
    private const string UserinfoEndpoint = "https://test.us.auth0.com/userinfo";
    private const string RevokeEndpoint = "https://test.us.auth0.com/oauth/revoke";

    private static readonly string DiscoveryJson =
        $$"""{"token_endpoint":"{{TokenEndpoint}}","userinfo_endpoint":"{{UserinfoEndpoint}}"}""";

    private static readonly string TokenSuccessJson =
        """{"access_token":"test-access-token","refresh_token":"test-refresh-token","expires_in":86400,"token_type":"Bearer"}""";

    private static readonly string UserinfoSuccessJson =
        """{"sub":"auth0|12345","email":"user@example.com","email_verified":true,"nickname":"testuser","preferred_username":"testuser","https://schemas.auth0.com/roles":["admin","user"]}""";

    private static readonly Auth0Config Auth0Config = new()
    {
        DefaultDomain = Auth0Domain
    };

    // ---------------------------------------------------------------
    //  LoginAsync
    // ---------------------------------------------------------------

    [Fact]
    public async Task LoginAsync_valid_credentials_returns_AuthResponse()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
                return ResponseHelper.Ok(TokenSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.AccessToken.Should().Be("test-access-token");
        result.Data.RefreshToken.Should().Be("test-refresh-token");
        result.Data.ExpiresIn.Should().Be(86400);
        result.Data.TokenType.Should().Be("Bearer");
        result.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task LoginAsync_includes_audience_when_configured()
    {
        // Arrange
        string? capturedBody = null;
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
            {
                capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return ResponseHelper.Ok(TokenSuccessJson);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler, monitor =>
        {
            var config = new TenantConfig
            {
                TenantId = "test-tenant",
                TenantName = "Test Tenant",
                TenantDomain = "example.com",
                ProviderType = ProviderType.Auth0,
                ProviderMetadata = new Dictionary<string, string>
                {
                    ["clientId"] = "test-client-id",
                    ["clientSecret"] = "test-client-secret",
                    ["audience"] = "https://api.example.com"
                }
            };
            monitor.Setup(m => m.Get(It.IsAny<string>())).Returns(config);
        });

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeTrue();
        capturedBody.Should().NotBeNull();
        capturedBody.Should().Contain("audience=https%3A%2F%2Fapi.example.com");
    }

    [Fact]
    public async Task LoginAsync_includes_offline_access_scope()
    {
        // Arrange
        string? capturedBody = null;
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
            {
                capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return ResponseHelper.Ok(TokenSuccessJson);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeTrue();
        capturedBody.Should().NotBeNull();
        capturedBody.Should().Contain("scope=openid+offline_access");
    }

    [Fact]
    public async Task LoginAsync_invalid_credentials_returns_401()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "wrong", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Invalid credentials");
    }

    [Fact]
    public async Task LoginAsync_provider_unreachable_returns_503()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ =>
            throw new HttpRequestException("Connection refused"));

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "pwd", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(503);
        result.ErrorMessage.Should().Be("Provider unavailable");
    }

    [Fact]
    public async Task LoginAsync_missing_clientId_returns_502()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        var provider = CreateProvider(handler, monitor =>
        {
            var config = new TenantConfig
            {
                TenantId = "test-tenant",
                TenantName = "Test Tenant",
                ProviderType = ProviderType.Auth0,
                ProviderMetadata = new Dictionary<string, string>
                {
                    ["clientSecret"] = "test-client-secret"
                }
            };
            monitor.Setup(m => m.Get(It.IsAny<string>())).Returns(config);
        });

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(502);
        result.ErrorMessage.Should().Contain("missing client credentials");
    }

    [Fact]
    public async Task LoginAsync_missing_clientSecret_returns_502()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        var provider = CreateProvider(handler, monitor =>
        {
            var config = new TenantConfig
            {
                TenantId = "test-tenant",
                TenantName = "Test Tenant",
                ProviderType = ProviderType.Auth0,
                ProviderMetadata = new Dictionary<string, string>
                {
                    ["clientId"] = "test-client-id"
                }
            };
            monitor.Setup(m => m.Get(It.IsAny<string>())).Returns(config);
        });

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(502);
        result.ErrorMessage.Should().Contain("missing client credentials");
    }

    // ---------------------------------------------------------------
    //  RefreshTokenAsync
    // ---------------------------------------------------------------

    [Fact]
    public async Task RefreshTokenAsync_returns_new_tokens()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
                return ResponseHelper.Ok(
                    """{"access_token":"new-access","refresh_token":"new-refresh","expires_in":43200,"token_type":"Bearer"}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.RefreshTokenAsync("old-refresh-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.AccessToken.Should().Be("new-access");
        result.Data.RefreshToken.Should().Be("new-refresh");
        result.Data.ExpiresIn.Should().Be(43200);
    }

    [Fact]
    public async Task RefreshTokenAsync_invalid_token_returns_401()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.RefreshTokenAsync("expired-refresh-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Invalid or expired refresh token");
    }

    // ---------------------------------------------------------------
    //  LogoutAsync
    // ---------------------------------------------------------------

    [Fact]
    public async Task LogoutAsync_always_returns_success()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/revoke"))
                return ResponseHelper.Ok("{}");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LogoutAsync("test-refresh-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task LogoutAsync_swallows_exceptions()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ =>
            throw new HttpRequestException("Connection refused"));

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LogoutAsync("test-refresh-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.StatusCode.Should().Be(200);
    }

    // ---------------------------------------------------------------
    //  ValidateTokenAsync
    // ---------------------------------------------------------------

    [Fact]
    public async Task ValidateTokenAsync_valid_token_returns_IsValid_true()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/userinfo"))
                return ResponseHelper.Ok(
                    """{"sub":"auth0|12345","email":"user@example.com","nickname":"testuser"}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.ValidateTokenAsync("valid-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.IsValid.Should().BeTrue();
        result.Data.Principal.Should().NotBeNull();
    }

    [Fact]
    public async Task ValidateTokenAsync_expired_token_returns_IsValid_false()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/userinfo"))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.ValidateTokenAsync("expired-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue(); // ValidationResult wrapper is always a success
        result.Data.Should().NotBeNull();
        result.Data!.IsValid.Should().BeFalse();
        result.Data.FailureReason.Should().Be("Token expired or invalid");
    }

    [Fact]
    public async Task ValidateTokenAsync_http_error_returns_IsValid_false()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            throw new HttpRequestException("Connection refused");
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.ValidateTokenAsync("any-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.IsValid.Should().BeFalse();
        result.Data.FailureReason.Should().Be("Provider unavailable");
    }

    // ---------------------------------------------------------------
    //  GetUserProfileAsync
    // ---------------------------------------------------------------

    [Fact]
    public async Task GetUserProfileAsync_returns_mapped_UserProfile()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/userinfo"))
                return ResponseHelper.Ok(UserinfoSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("valid-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Id.Should().Be("auth0|12345");
        result.Data.Email.Should().Be("user@example.com");
        result.Data.Username.Should().Be("testuser");
    }

    [Fact]
    public async Task GetUserProfileAsync_extracts_roles_from_custom_claim()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/userinfo"))
                return ResponseHelper.Ok(UserinfoSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("valid-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Roles.Should().BeEquivalentTo(["admin", "user"]);
    }

    [Fact]
    public async Task GetUserProfileAsync_missing_optional_claims_uses_empty_strings()
    {
        // Arrange — userinfo response with only "sub", no email or nickname
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/userinfo"))
                return ResponseHelper.Ok("""{"sub":"auth0|12345"}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("valid-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Id.Should().Be("auth0|12345");
        result.Data.Email.Should().BeEmpty();
        result.Data.Username.Should().BeEmpty();
        result.Data.Roles.Should().BeEmpty();
    }

    [Fact]
    public async Task GetUserProfileAsync_expired_token_returns_401()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/userinfo"))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("expired-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Token expired or invalid");
    }

    [Fact]
    public async Task GetUserProfileAsync_provider_unreachable_returns_503()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ =>
            throw new HttpRequestException("Connection refused"));

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("any-token", "test-tenant");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(503);
        result.ErrorMessage.Should().Be("Provider unavailable");
    }

    // ---------------------------------------------------------------
    //  RegisterAsync
    // ---------------------------------------------------------------

    [Fact]
    public async Task RegisterAsync_throws_NotSupportedException()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.NotFound));

        var provider = CreateProvider(handler);

        // Act
        var act = async () => await provider.RegisterAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        await act.Should().ThrowAsync<NotSupportedException>()
            .WithMessage("*Management API*");
    }

    // ---------------------------------------------------------------
    //  LoginAsync enrichment
    // ---------------------------------------------------------------

    [Fact]
    public async Task LoginAsync_enriches_response_with_tenant_claims()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/oauth/token"))
                return ResponseHelper.Ok(TokenSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("testuser", "password", "test-tenant"));

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data!.EnrichedClaims.Should().NotBeNull();
        result.Data.EnrichedClaims!["tenant_id"].Should().Be("test-tenant");
        result.Data.EnrichedClaims["tenant_name"].Should().Be("Test Tenant");
        result.Data.EnrichedClaims["tenant_domain"].Should().Be("example.com");
    }

    // ---------------------------------------------------------------
    //  Factory
    // ---------------------------------------------------------------

    private static Auth0Provider CreateProvider(
        HttpMessageHandler handler,
        Action<Mock<IOptionsMonitor<TenantConfig>>>? configureTenant = null)
    {
        var httpClient = new HttpClient(handler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var tenantConfig = new TenantConfig
        {
            TenantId = "test-tenant",
            TenantName = "Test Tenant",
            TenantDomain = "example.com",
            ProviderType = ProviderType.Auth0,
            ProviderMetadata = new Dictionary<string, string>
            {
                ["clientId"] = "test-client-id",
                ["clientSecret"] = "test-client-secret"
            }
        };

        var tenantMonitorMock = new Mock<IOptionsMonitor<TenantConfig>>();
        tenantMonitorMock.Setup(m => m.Get(It.IsAny<string>())).Returns(tenantConfig);

        configureTenant?.Invoke(tenantMonitorMock);

        return new Auth0Provider(
            factoryMock.Object,
            Options.Create(Auth0Config),
            tenantMonitorMock.Object);
    }
}
