using System.Text.Json.Serialization;
using AuthBroker.Core;
using AuthBroker.Core.Models;
using AuthBroker.Providers.Auth0;

namespace AuthBroker.Api.Endpoints;

/// <summary>
/// Maps the unified authentication endpoints to the <see cref="WebApplication"/> pipeline.
/// All endpoints require <see cref="Middleware.TenantResolutionMiddleware"/> to have run first,
/// which stores the resolved <see cref="Auth0TenantConfig"/> in <c>HttpContext.Items["TenantConfig"]</c>.
///
/// Protected endpoints use <see cref="Middleware.SessionTokenMiddleware"/> to authenticate
/// via session JWT (X-Session-Token) or opaque Auth0 token (Authorization: Bearer).
/// </summary>
public static class AuthEndpoints
{
    /// <summary>
    /// Maps all auth endpoints:
    /// <list type="bullet">
    ///   <item><c>POST /auth/login</c> — public, returns session_token</item>
    ///   <item><c>POST /auth/register</c> — public</item>
    ///   <item><c>POST /auth/refresh</c> — public, returns session_token</item>
    ///   <item><c>GET /auth/verify-email</c> — public</item>
    ///   <item><c>GET /auth/userinfo</c> — protected</item>
    ///   <item><c>POST /auth/logout</c> — protected</item>
    ///   <item><c>POST /auth/session</c> — public, explicit exchange (fallback si auto-exchange no funcionó)</item>
    /// </list>
    /// </summary>
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapPost("/auth/login", async (HttpContext context, AuthRequest request, Auth0Provider provider, SessionTokenService sessionService) =>
        {
            var result = await provider.LoginAsync(request);
            if (!result.IsSuccess)
                return ToHttpResult(result);

            // Auto-exchange: validate the opaque token and create a session JWT
            var validation = await provider.ValidateTokenAsync(result.Data!.AccessToken, request.TenantId);
            if (validation is { IsSuccess: true, Data.IsValid: true })
            {
                var tenantConfig = GetTenantConfig(context);
                var sessionJwt = sessionService.CreateToken(validation.Data.Principal!, tenantConfig);

                return Results.Ok(new
                {
                    access_token = result.Data.AccessToken,
                    refresh_token = result.Data.RefreshToken,
                    expires_in = result.Data.ExpiresIn,
                    token_type = result.Data.TokenType,
                    session_token = sessionJwt,
                });
            }

            // Fallback: return original response without session token
            return ToHttpResult(result);
        });

        app.MapPost("/auth/register", async (AuthRequest request, Auth0Provider provider) =>
        {
            var result = await provider.RegisterAsync(request);
            return ToHttpResult(result);
        });

        app.MapGet("/auth/verify-email", async (HttpContext context, Auth0Provider provider) =>
        {
            var id = context.Request.Query["id"].FirstOrDefault();

            if (string.IsNullOrEmpty(id))
                return Results.Json(new { error = "Missing required parameter: id" }, statusCode: 400);

            var tenantConfig = GetTenantConfig(context);
            var result = await provider.ConfirmEmailAsync(id, tenantConfig.TenantId);
            return ToHttpResult(result);
        });

        app.MapPost("/auth/refresh", async (HttpContext context, RefreshTokenBody body, Auth0Provider provider, SessionTokenService sessionService) =>
        {
            var tenantConfig = GetTenantConfig(context);
            var tenantId = body.TenantId ?? tenantConfig.TenantId;
            var result = await provider.RefreshTokenAsync(body.RefreshToken, tenantId);
            if (!result.IsSuccess)
                return ToHttpResult(result);

            // Auto-exchange: create a fresh session JWT from the new opaque token
            var validation = await provider.ValidateTokenAsync(result.Data!.AccessToken, tenantId);
            if (validation is { IsSuccess: true, Data.IsValid: true })
            {
                var sessionJwt = sessionService.CreateToken(validation.Data.Principal!, tenantConfig);

                return Results.Ok(new
                {
                    access_token = result.Data.AccessToken,
                    refresh_token = result.Data.RefreshToken,
                    expires_in = result.Data.ExpiresIn,
                    token_type = result.Data.TokenType,
                    session_token = sessionJwt,
                });
            }

            return ToHttpResult(result);
        });

        app.MapPost("/auth/logout", async (HttpContext context, RefreshTokenBody body, Auth0Provider provider) =>
        {
            var tenantConfig = GetTenantConfig(context);
            var tenantId = body.TenantId ?? tenantConfig.TenantId;
            var result = await provider.LogoutAsync(body.RefreshToken, tenantId);
            return ToHttpResult(result);
        });

        /// <summary>
        /// Exchanges an opaque Auth0 token for a signed session JWT.
        /// The session JWT can then be used via the X-Session-Token header
        /// for all subsequent requests without calling Auth0 again.
        /// </summary>
        app.MapPost("/auth/session", async (HttpContext context, Auth0Provider provider, SessionTokenService sessionService) =>
        {
            var tenantConfig = GetTenantConfig(context);

            var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new { error = "Se requiere Authorization: Bearer &lt;opaque_token&gt;" }, statusCode: 401);
            }

            var opaqueToken = authHeader["Bearer ".Length..].Trim();
            var result = await provider.ValidateTokenAsync(opaqueToken, tenantConfig.TenantId);

            if (result is not { IsSuccess: true, Data.IsValid: true })
            {
                return Results.Json(
                    new { error = result.Data?.FailureReason ?? "Token inválido o expirado" },
                    statusCode: 401);
            }

            var sessionJwt = sessionService.CreateToken(result.Data.Principal!, tenantConfig);

            return Results.Ok(new
            {
                session_token = sessionJwt,
                token_type = "Bearer",
                expires_in = 900, // 15 minutes
            });
        });

        /// <summary>
        /// Returns the user profile for the currently authenticated user.
        /// Works with both opaque tokens and session JWTs — if the opaque
        /// token was provided (first request), calls Auth0 for the full profile;
        /// otherwise reads from the session JWT claims.
        /// </summary>
        app.MapGet("/auth/userinfo", async (HttpContext context, Auth0Provider provider) =>
        {
            var tenantConfig = GetTenantConfig(context);

            // If we still have the opaque token (first request via Bearer), get full profile from Auth0
            var accessToken = context.Items["AccessToken"] as string;
            if (!string.IsNullOrEmpty(accessToken))
            {
                var result = await provider.GetUserProfileAsync(accessToken, tenantConfig.TenantId);
                return ToHttpResult(result);
            }

            // Otherwise build from session JWT claims
            if (context.User.Identity?.IsAuthenticated != true)
            {
                return Results.Json(new { error = "No autenticado" }, statusCode: 401);
            }

            return Results.Ok(new
            {
                sub = context.User.FindFirst("sub")?.Value,
                email = context.User.FindFirst("email")?.Value,
                nickname = context.User.FindFirst("nickname")?.Value,
                name = context.User.FindFirst("name")?.Value,
                roles = context.User.FindAll("https://schemas.auth0.com/roles").Select(c => c.Value).ToList(),
                tenant_id = context.User.FindFirst("tenant_id")?.Value,
            });
        });
    }

    /// <summary>
    /// Retrieves the <see cref="Auth0TenantConfig"/> stored by <see cref="Middleware.TenantResolutionMiddleware"/>.
    /// </summary>
    private static Auth0TenantConfig GetTenantConfig(HttpContext context)
    {
        return (Auth0TenantConfig)context.Items["TenantConfig"]!;
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


