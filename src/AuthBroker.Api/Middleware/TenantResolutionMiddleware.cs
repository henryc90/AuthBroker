using System.Text.Json;
using AuthBroker.Core;
using Microsoft.Extensions.Options;

namespace AuthBroker.Api.Middleware;

/// <summary>
/// Middleware that reads the <c>X-Tenant-ID</c> header from each request,
/// resolves the corresponding <see cref="Auth0TenantConfig"/> from the <c>Auth</c> configuration array,
/// and stores it in <c>HttpContext.Items["TenantConfig"]</c> for downstream use.
/// </summary>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<Auth0TenantConfig> _tenantConfigMonitor;

    public TenantResolutionMiddleware(RequestDelegate next, IOptionsMonitor<Auth0TenantConfig> tenantConfigMonitor)
    {
        _next = next;
        _tenantConfigMonitor = tenantConfigMonitor;
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

        // Resolve Auth0TenantConfig from named options
        var tenantConfig = _tenantConfigMonitor.Get(tenantId);

        if (tenantConfig is null || string.IsNullOrEmpty(tenantConfig.TenantId))
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
