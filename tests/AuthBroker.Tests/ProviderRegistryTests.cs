using AuthBroker.Core;
using AuthBroker.Core.Models;
using AuthBroker.Providers.Auth0;
using AuthBroker.Providers.Keycloak;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace AuthBroker.Tests;

public class ProviderRegistryTests
{
    [Fact]
    public void Register_and_resolve_Keycloak_provider_returns_instance()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var services = new ServiceCollection()
            .AddKeycloakConfig()
            .BuildServiceProvider();

        registry.Register(ProviderType.Keycloak, sp =>
            new KeycloakProvider(
                sp.GetRequiredService<IHttpClientFactory>(),
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeycloakConfig>>(),
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<TenantConfig>>()));

        // Act
        var provider = registry.Resolve(ProviderType.Keycloak, services);

        // Assert
        provider.Should().NotBeNull();
        provider.Should().BeAssignableTo<IAuthProvider>();
    }

    [Fact]
    public void Resolve_unregistered_type_throws_KeyNotFoundException()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var services = new ServiceCollection().BuildServiceProvider();

        // Act
        var act = () => registry.Resolve(ProviderType.AzureAd, services);

        // Assert
        act.Should().Throw<KeyNotFoundException>()
            .WithMessage("*AzureAd*");
    }

    [Fact]
    public void Register_overwrites_existing_type()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var services = new ServiceCollection()
            .AddKeycloakConfig()
            .BuildServiceProvider();

        var firstFactoryInvoked = false;

        registry.Register(ProviderType.Keycloak, _ =>
        {
            firstFactoryInvoked = true;
            return new KeycloakProvider(
                services.GetRequiredService<IHttpClientFactory>(),
                services.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeycloakConfig>>(),
                services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<TenantConfig>>());
        });

        // Overwrite
        registry.Register(ProviderType.Keycloak, _ =>
        {
            firstFactoryInvoked = false;
            return new KeycloakProvider(
                services.GetRequiredService<IHttpClientFactory>(),
                services.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeycloakConfig>>(),
                services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<TenantConfig>>());
        });

        // Act
        var provider = registry.Resolve(ProviderType.Keycloak, services);

        // Assert
        provider.Should().NotBeNull();
        firstFactoryInvoked.Should().BeFalse("the second factory should have overwritten the first");
    }

    [Fact]
    public void Register_and_resolve_Auth0_provider_returns_instance()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var services = new ServiceCollection()
            .AddHttpClient()
            .BuildServiceProvider();

        registry.Register(ProviderType.Auth0, _ =>
            new Auth0Provider(
                services.GetRequiredService<IHttpClientFactory>(),
                Options.Create(new Auth0Config { DefaultDomain = "test.us.auth0.com" }),
                Mock.Of<IOptionsMonitor<TenantConfig>>()));

        // Act
        var provider = registry.Resolve(ProviderType.Auth0, services);

        // Assert
        provider.Should().NotBeNull();
        provider.Should().BeAssignableTo<IAuthProvider>();
    }
}

/// <summary>
/// Extension methods to set up the DI services needed for tests.
/// </summary>
internal static class TestServiceExtensions
{
    public static IServiceCollection AddKeycloakConfig(this IServiceCollection services)
    {
        services.AddHttpClient();
        services.AddSingleton(Microsoft.Extensions.Options.Options.Create(
            new KeycloakConfig
            {
                BaseUrl = "http://localhost:8080",
                AdminUrl = "http://localhost:8080"
            }));
        var tenantMonitor = new Moq.Mock<Microsoft.Extensions.Options.IOptionsMonitor<TenantConfig>>();
        tenantMonitor.Setup(m => m.Get(It.IsAny<string>()))
            .Returns(new TenantConfig
            {
                TenantId = "test",
                TenantName = "Test",
                ProviderType = ProviderType.Keycloak,
                ProviderMetadata = new()
                {
                    ["realm"] = "test",
                    ["clientId"] = "test-client",
                    ["clientSecret"] = "test-secret"
                }
            });
        services.AddSingleton(tenantMonitor.Object);
        return services;
    }
}
