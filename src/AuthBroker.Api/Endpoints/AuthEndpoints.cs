using System.Text.Json.Serialization;
using AuthBroker.Core;
using AuthBroker.Core.Models;

namespace AuthBroker.Api.Endpoints;

/// <summary>
/// Maps the unified authentication endpoints to the <see cref="WebApplication"/> pipeline.
/// All endpoints require <see cref="TenantResolutionMiddleware"/> to have run first,
/// which stores the resolved <see cref="TenantConfig"/> in <c>HttpContext.Items["TenantConfig"]</c>.
/// </summary>
public static class AuthEndpoints
{
    /// <summary>
    /// Maps all auth endpoints:
    /// <list type="bullet">
    ///   <item><c>POST /auth/login</c></item>
    ///   <item><c>POST /auth/register</c></item>
    ///   <item><c>POST /auth/refresh</c></item>
    ///   <item><c>POST /auth/logout</c></item>
    ///   <item><c>GET /auth/userinfo</c></item>
    /// </list>
    /// </summary>
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapPost("/auth/login", async (HttpContext context, AuthRequest request, IProviderRegistry registry) =>
        {
            var tenantConfig = GetTenantConfig(context);
            var provider = registry.Resolve(tenantConfig.ProviderType, context.RequestServices);
            var result = await provider.LoginAsync(request);
            return ToHttpResult(result);
        });

        app.MapPost("/auth/register", async (HttpContext context, AuthRequest request, IProviderRegistry registry) =>
        {
            var tenantConfig = GetTenantConfig(context);
            var provider = registry.Resolve(tenantConfig.ProviderType, context.RequestServices);
            var result = await provider.RegisterAsync(request);
            return ToHttpResult(result);
        });

        app.MapPost("/auth/refresh", async (HttpContext context, RefreshTokenBody body, IProviderRegistry registry) =>
        {
            var tenantConfig = GetTenantConfig(context);
            var provider = registry.Resolve(tenantConfig.ProviderType, context.RequestServices);

            var tenantId = body.TenantId ?? tenantConfig.TenantId;
            var result = await provider.RefreshTokenAsync(body.RefreshToken, tenantId);

            return ToHttpResult(result);
        });

        app.MapPost("/auth/logout", async (HttpContext context, RefreshTokenBody body, IProviderRegistry registry) =>
        {
            var tenantConfig = GetTenantConfig(context);
            var provider = registry.Resolve(tenantConfig.ProviderType, context.RequestServices);

            var tenantId = body.TenantId ?? tenantConfig.TenantId;
            var result = await provider.LogoutAsync(body.RefreshToken, tenantId);

            return ToHttpResult(result);
        });

        app.MapGet("/auth/userinfo", async (HttpContext context, IProviderRegistry registry) =>
        {
            var tenantConfig = GetTenantConfig(context);

            // Extract bearer token from Authorization header
            var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(
                    new { error = "Missing or invalid Authorization header" },
                    statusCode: 401);
            }

            var accessToken = authHeader["Bearer ".Length..].Trim();
            var provider = registry.Resolve(tenantConfig.ProviderType, context.RequestServices);
            var result = await provider.GetUserProfileAsync(accessToken, tenantConfig.TenantId);
            return ToHttpResult(result);
        });
    }

    /// <summary>
    /// Retrieves the <see cref="TenantConfig"/> stored by <see cref="TenantResolutionMiddleware"/>.
    /// </summary>
    private static TenantConfig GetTenantConfig(HttpContext context)
    {
        return (TenantConfig)context.Items["TenantConfig"]!;
    }

    /// <summary>
    /// Converts a generic <see cref="IAuthResult{T}"/> to an <see cref="IResult"/>.
    /// </summary>
    private static IResult ToHttpResult<T>(IAuthResult<T> result)
    {
        return result.IsSuccess
            ? Results.Ok(result.Data)
            : Results.Json(new { error = result.ErrorMessage }, statusCode: result.StatusCode);
    }

    /// <summary>
    /// Converts a non-generic <see cref="IAuthResult"/> (e.g. logout) to an <see cref="IResult"/>.
    /// </summary>
    private static IResult ToHttpResult(IAuthResult result)
    {
        return result.IsSuccess
            ? Results.Ok()
            : Results.Json(new { error = result.ErrorMessage }, statusCode: result.StatusCode);
    }
}

/// <summary>
/// Request body for <c>/auth/refresh</c> and <c>/auth/logout</c> endpoints.
/// </summary>
public record RefreshTokenBody(
    [property: JsonPropertyName("refresh_token")] string RefreshToken,
    [property: JsonPropertyName("tenant_id")] string? TenantId = null);
