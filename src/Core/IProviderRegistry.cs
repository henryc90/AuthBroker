namespace AuthBroker.Core;

/// <summary>
/// Registry for resolving authentication providers by type at runtime.
/// Follows the service locator pattern, scoped to provider resolution only.
/// </summary>
public interface IProviderRegistry
{
    /// <summary>
    /// Registers a factory function for a given provider type.
    /// </summary>
    void Register(ProviderType type, Func<IServiceProvider, IAuthProvider> factory);

    /// <summary>
    /// Resolves an IAuthProvider instance for the given provider type.
    /// The serviceProvider is used to resolve scoped dependencies for the provider factory.
    /// </summary>
    IAuthProvider Resolve(ProviderType type, IServiceProvider serviceProvider);
}
