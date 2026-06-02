using System.Text.Json;
using AuthBroker.Core;
using AuthBroker.Providers.Auth0;

namespace AuthBroker.Api.Middleware;

/// <summary>
/// Authenticates requests using either a session JWT (X-Session-Token header)
/// or an opaque Auth0 token (Authorization: Bearer header).
///
/// Flow:
/// 1. If the request has a valid X-Session-Token → validates it locally (fast, no Auth0 call).
/// 2. If not, falls back to Authorization: Bearer → validates against Auth0 /userinfo,
///    creates a new session JWT, and sets it in the X-Session-Token response header.
/// 3. If neither token is present → 401.
///
/// Public paths (login, register, refresh, verify-email, health) are excluded.
/// </summary>
public class SessionTokenMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly HashSet<string> PublicPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health",
        "/auth/login",
        "/auth/register",
        "/auth/refresh",
        "/auth/verify-email",
    };

    public SessionTokenMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(
        HttpContext context,
        SessionTokenService sessionService,
        Auth0Provider auth0Provider)
    {
        var path = context.Request.Path.Value ?? "";

        // 1. Public paths → skip authentication entirely
        if (PublicPaths.Any(p => path.StartsWith(p)))
        {
            await _next(context);
            return;
        }

        var tenantConfig = (Auth0TenantConfig)context.Items["TenantConfig"]!;

        // 2. Try session JWT first (fast path — no call to Auth0)
        var sessionToken = context.Request.Headers["X-Session-Token"].FirstOrDefault();
        if (!string.IsNullOrEmpty(sessionToken))
        {
            var principal = sessionService.ValidateToken(sessionToken, tenantConfig);
            if (principal is not null)
            {
                context.User = principal;
                await _next(context);
                return;
            }
            // Session token expired or invalid → fall through to opaque token
        }

        // 3. Fall back to opaque Bearer token → validate via Auth0 /userinfo
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(new
                {
                    error = "Se requiere un token de acceso. Usa X-Session-Token o Authorization: Bearer"
                }));
            return;
        }

        var opaqueToken = authHeader["Bearer ".Length..].Trim();
        var validationResult = await auth0Provider.ValidateTokenAsync(opaqueToken, tenantConfig.TenantId);

        if (validationResult is not { IsSuccess: true, Data.IsValid: true })
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(new
                {
                    error = validationResult.Data?.FailureReason ?? "Token inválido o expirado"
                }));
            return;
        }

        // 4. Create session JWT from the validated principal and set it on the response
        var validatedPrincipal = validationResult.Data.Principal!;
        var jwt = sessionService.CreateToken(validatedPrincipal, tenantConfig);
        context.Response.Headers["X-Session-Token"] = jwt;

        // 5. Store opaque token for endpoints that need to call Auth0 directly
        context.Items["AccessToken"] = opaqueToken;
        context.User = validatedPrincipal;

        await _next(context);
    }
}
