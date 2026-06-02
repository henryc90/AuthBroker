using AuthBroker.Api.Endpoints;
using AuthBroker.Api.Middleware;
using AuthBroker.Core;
using AuthBroker.Providers.Auth0;

var builder = WebApplication.CreateBuilder(args);

// Register Auth0 tenant configs from the "Auth" array as named options
// so IOptionsMonitor<Auth0TenantConfig>.Get(tenantId) works
var authTenants = builder.Configuration.GetSection("Auth").Get<List<Auth0TenantConfig>>();
if (authTenants is not null)
{
    foreach (var tenant in authTenants)
    {
        builder.Services.Configure<Auth0TenantConfig>(tenant.TenantId, options =>
        {
            options.TenantId = tenant.TenantId;
            options.TenantName = tenant.TenantName;
            options.TenantDomain = tenant.TenantDomain;
            options.Domain = tenant.Domain;
            options.ClientId = tenant.ClientId;
            options.ClientSecret = tenant.ClientSecret;
            options.Audience = tenant.Audience;
            options.RolesClaim = tenant.RolesClaim;
        });
    }
}

// Register Auth0 provider and session token service
builder.Services.AddHttpClient();
builder.Services.AddSingleton<SessionTokenService>();
builder.Services.AddSingleton<Auth0Provider>();

// Configure Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Healthcheck — outside tenant resolution
app.Map("/health", HealthEndpoints.MapHealthBranch);

// Tenant resolution middleware
app.UseMiddleware<TenantResolutionMiddleware>();

// Session token authentication middleware
app.UseMiddleware<SessionTokenMiddleware>();

// Redirect root to Swagger UI in Development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.MapGet("/", () => Results.Redirect("/swagger"));
}

// Map authentication endpoints
app.MapAuthEndpoints();

app.Run();
