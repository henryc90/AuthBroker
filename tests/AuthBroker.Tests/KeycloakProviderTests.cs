using System.Net;
using AuthBroker.Core;
using AuthBroker.Core.Models;
using AuthBroker.Providers.Keycloak;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;

namespace AuthBroker.Tests;

public class KeycloakProviderTests
{
    private const string RealmUrl = "http://keycloak:8080/realms/test";
    private const string TokenEndpoint = "http://keycloak:8080/realms/test/protocol/openid-connect/token";
    private const string UserinfoEndpoint = "http://keycloak:8080/realms/test/protocol/openid-connect/userinfo";

    private static readonly string DiscoveryJson =
        $$"""{"token_endpoint":"{{TokenEndpoint}}","userinfo_endpoint":"{{UserinfoEndpoint}}"}""";

    private static readonly string TokenSuccessJson =
        """{"access_token":"access-token-123","refresh_token":"refresh-token-456","expires_in":300,"token_type":"Bearer"}""";

    private static readonly KeycloakConfig KeycloakConfig = new()
    {
        BaseUrl = "http://keycloak:8080",
        AdminUrl = "http://keycloak:8080"
    };

    private static readonly TenantConfig TenantConfig = new()
    {
        TenantId = "acme-corp",
        TenantName = "Acme Corp",
        TenantDomain = "acme.com",
        ProviderType = ProviderType.Keycloak,
        ProviderMetadata = new()
        {
            ["realm"] = "test",
            ["clientId"] = "test-client",
            ["clientSecret"] = "test-secret"
        }
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
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/token"))
                return ResponseHelper.Ok(TokenSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("jdoe", "pwd", "acme-corp"));

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.AccessToken.Should().Be("access-token-123");
        result.Data.RefreshToken.Should().Be("refresh-token-456");
        result.Data.ExpiresIn.Should().Be(300);
        result.Data.TokenType.Should().Be("Bearer");
        result.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task LoginAsync_invalid_credentials_returns_401()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/token"))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("jdoe", "wrong", "acme-corp"));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Invalid credentials");
    }

    [Fact]
    public async Task LoginAsync_keycloak_unreachable_returns_503()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ =>
            throw new HttpRequestException("Connection refused"));

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("jdoe", "pwd", "acme-corp"));

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(503);
        result.ErrorMessage.Should().Be("Provider unavailable");
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
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/token"))
                return ResponseHelper.Ok(
                    """{"access_token":"new-access","refresh_token":"new-refresh","expires_in":600,"token_type":"Bearer"}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.RefreshTokenAsync("old-refresh-token", "acme-corp");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.AccessToken.Should().Be("new-access");
        result.Data.RefreshToken.Should().Be("new-refresh");
        result.Data.ExpiresIn.Should().Be(600);
    }

    [Fact]
    public async Task RefreshTokenAsync_invalid_token_returns_401()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/token"))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.RefreshTokenAsync("expired-refresh-token", "acme-corp");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Invalid or expired refresh token");
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
                    """{"sub":"user-1","preferred_username":"jdoe","email":"jdoe@acme.com"}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.ValidateTokenAsync("valid-token", "acme-corp");

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
        var result = await provider.ValidateTokenAsync("expired-token", "acme-corp");

        // Assert
        result.IsSuccess.Should().BeTrue(); // ValidationResult is always a success wrapper
        result.Data.Should().NotBeNull();
        result.Data!.IsValid.Should().BeFalse();
        result.Data.FailureReason.Should().Be("Token expired or invalid");
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
                return ResponseHelper.Ok(
                    """{"sub":"user-1","preferred_username":"jdoe","email":"jdoe@acme.com","realm_access":{"roles":["user","admin"]}}""");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("valid-token", "acme-corp");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Id.Should().Be("user-1");
        result.Data.Username.Should().Be("jdoe");
        result.Data.Email.Should().Be("jdoe@acme.com");
        result.Data.Roles.Should().BeEquivalentTo(["user", "admin"]);
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
        var result = await provider.GetUserProfileAsync("expired-token", "acme-corp");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(401);
        result.ErrorMessage.Should().Be("Token expired or invalid");
    }

    [Fact]
    public async Task GetUserProfileAsync_keycloak_unreachable_returns_503()
    {
        // Arrange
        var handler = new TestHttpMessageHandler(_ =>
            throw new HttpRequestException("Connection refused"));

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.GetUserProfileAsync("any-token", "acme-corp");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be(503);
        result.ErrorMessage.Should().Be("Provider unavailable");
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
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/token"))
                return ResponseHelper.Ok(TokenSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LogoutAsync("refresh-token", "acme-corp");

        // Assert — logout is always best-effort success
        result.IsSuccess.Should().BeTrue();
        result.StatusCode.Should().Be(200);
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
            if (url.Contains(".well-known/openid-configuration"))
                return ResponseHelper.Ok(DiscoveryJson);
            if (url.Contains("/token"))
                return ResponseHelper.Ok(TokenSuccessJson);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        // Act
        var result = await provider.LoginAsync(new AuthRequest("jdoe", "pwd", "acme-corp"));

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Data!.EnrichedClaims.Should().NotBeNull();
        result.Data.EnrichedClaims!["tenant_id"].Should().Be("acme-corp");
        result.Data.EnrichedClaims["tenant_name"].Should().Be("Acme Corp");
        result.Data.EnrichedClaims["tenant_domain"].Should().Be("acme.com");
    }

    // ---------------------------------------------------------------
    //  Factory
    // ---------------------------------------------------------------

    private static KeycloakProvider CreateProvider(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var tenantMonitorMock = new Mock<IOptionsMonitor<TenantConfig>>();
        tenantMonitorMock.Setup(m => m.Get(It.IsAny<string>())).Returns(TenantConfig);

        return new KeycloakProvider(
            factoryMock.Object,
            Options.Create(KeycloakConfig),
            tenantMonitorMock.Object);
    }
}
