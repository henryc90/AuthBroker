using AuthBroker.Api.Endpoints;
using AuthBroker.Api.Middleware;
using AuthBroker.Core;
using AuthBroker.Providers.Auth0;
using AuthBroker.Providers.Keycloak;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Register ProviderRegistry as singleton
var registry = new ProviderRegistry();
builder.Services.AddSingleton<IProviderRegistry>(registry);

// Register config + HttpClient for each provider
builder.Services.AddKeycloakAuth(builder.Configuration);
builder.Services.AddAuth0Auth(builder.Configuration);

// Populate the registry with provider factories
registry.Register(ProviderType.Keycloak, sp =>
    new KeycloakProvider(
        sp.GetRequiredService<IHttpClientFactory>(),
        sp.GetRequiredService<IOptions<KeycloakConfig>>(),
        sp.GetRequiredService<IOptionsMonitor<TenantConfig>>()));

registry.Register(ProviderType.Auth0, sp =>
    new Auth0Provider(
        sp.GetRequiredService<IHttpClientFactory>(),
        sp.GetRequiredService<IOptions<Auth0Config>>(),
        sp.GetRequiredService<IOptionsMonitor<TenantConfig>>()));

// Register each tenant as a named TenantConfig option so IOptionsMonitor<TenantConfig>.Get(tenantId) works
foreach (var tenantSection in builder.Configuration.GetSection("Tenants").GetChildren())
{
    builder.Services.Configure<TenantConfig>(tenantSection.Key, tenantSection);
}

// Configure Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Tenant resolution middleware — must run before auth endpoints
app.UseMiddleware<TenantResolutionMiddleware>();

// Redirect root to Swagger UI in Development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.MapGet("/", () => Results.Redirect("/swagger"));
}

// Map unified authentication endpoints
app.MapAuthEndpoints();

app.Run();
