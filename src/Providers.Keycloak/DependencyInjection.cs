using AuthBroker.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthBroker.Providers.Keycloak;

/// <summary>
/// Extension methods for registering Keycloak authentication services in the DI container.
/// </summary>
public static class KeycloakAuthExtensions
{
    /// <summary>
    /// Adds Keycloak authentication support:
    /// <list type="bullet">
    ///   <item>Binds <see cref="KeycloakConfig"/> from the <c>"Keycloak"</c> configuration section.</item>
    ///   <item>Registers the <c>IHttpClientFactory</c> infrastructure.</item>
    /// </list>
    /// </summary>
    public static IServiceCollection AddKeycloakAuth(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Bind KeycloakConfig from "Keycloak" section
        services.Configure<KeycloakConfig>(configuration.GetSection("Keycloak"));

        // Ensure IHttpClientFactory is registered
        services.AddHttpClient();

        return services;
    }
}
