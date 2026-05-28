using System.Text.Json;
using AuthBroker.Core;

namespace AuthBroker.Api.Middleware;

/// <summary>
/// Middleware that reads the <c>X-Tenant-ID</c> header from each request,
/// resolves the corresponding <see cref="TenantConfig"/> from configuration,
/// and stores it in <c>HttpContext.Items["TenantConfig"]</c> for downstream use.
/// </summary>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;

    public TenantResolutionMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Read X-Tenant-ID header
        if (!context.Request.Headers.TryGetValue("X-Tenant-ID", out var tenantIdValues) ||
            string.IsNullOrWhiteSpace(tenantIdValues.FirstOrDefault()))
        {
            context.Response.StatusCode = 400;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(new { error = "X-Tenant-ID header is required" }));
            return;
        }

        var tenantId = tenantIdValues.FirstOrDefault()!;

        // Resolve TenantConfig from IConfiguration — look up Tenants:{tenantId}
        var tenantConfig = _configuration
            .GetSection($"Tenants:{tenantId}")
            .Get<TenantConfig>();

        if (tenantConfig is null)
        {
            context.Response.StatusCode = 404;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(new { error = $"Tenant '{tenantId}' not found" }));
            return;
        }

        // Store for downstream use by endpoints
        context.Items["TenantConfig"] = tenantConfig;

        await _next(context);
    }
}
