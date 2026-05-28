using System.Collections.Concurrent;
using AuthBroker.Core;
using Microsoft.Extensions.DependencyInjection;

namespace AuthBroker.Providers.Keycloak;

/// <summary>
/// Singleton registry that stores provider factory functions keyed by <see cref="ProviderType"/>.
/// When <c>Resolve</c> is called it creates a new provider instance using the supplied
/// <see cref="IServiceProvider"/> so that scoped dependencies can be resolved.
/// </summary>
public class ProviderRegistry : IProviderRegistry
{
    private readonly ConcurrentDictionary<ProviderType, Func<IServiceProvider, IAuthProvider>> _providers = new();

    /// <inheritdoc />
    public void Register(ProviderType type, Func<IServiceProvider, IAuthProvider> factory)
    {
        _providers[type] = factory;
    }

    /// <inheritdoc />
    public IAuthProvider Resolve(ProviderType type, IServiceProvider serviceProvider)
    {
        if (_providers.TryGetValue(type, out var factory))
            return factory(serviceProvider);

        throw new KeyNotFoundException($"No provider registered for type '{type}'.");
    }
}
