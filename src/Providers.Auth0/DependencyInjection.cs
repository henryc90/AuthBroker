using AuthBroker.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthBroker.Providers.Auth0;

/// <summary>
/// Extension methods for registering Auth0 authentication services in the DI container.
/// </summary>
public static class Auth0AuthExtensions
{
    /// <summary>
    /// Adds Auth0 authentication support:
    /// <list type="bullet">
    ///   <item>Binds <see cref="Auth0Config"/> from the <c>"Auth0"</c> configuration section.</item>
    ///   <item>Registers the <c>IHttpClientFactory</c> infrastructure.</item>
    /// </list>
    /// NOTE: IProviderRegistry is NOT registered here. It must be registered in
    /// the API project's Program.cs (or a shared startup class).
    /// </summary>
    public static IServiceCollection AddAuth0Auth(this IServiceCollection services, IConfiguration configuration)
    {
        // Bind Auth0Config from "Auth0" section
        services.Configure<Auth0Config>(configuration.GetSection("Auth0"));

        // Ensure IHttpClientFactory is registered
        services.AddHttpClient();

        return services;
    }
}
