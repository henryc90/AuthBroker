using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthBroker.Api.Endpoints;

/// <summary>
/// Maps the healthcheck endpoint.
/// This endpoint is mapped via <c>app.Map("/health", ...)</c> to create a
/// pipeline branch that bypasses <see cref="Middleware.TenantResolutionMiddleware"/>,
/// so it does NOT require an <c>X-Tenant-ID</c> header.
/// </summary>
public static class HealthEndpoints
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Configures the <c>/health</c> pipeline branch.
    /// Call this via <c>app.Map("/health", HealthEndpoints.MapHealthBranch)</c>
    /// BEFORE <c>app.UseMiddleware&lt;TenantResolutionMiddleware&gt;()</c>.
    /// </summary>
    public static void MapHealthBranch(IApplicationBuilder healthApp)
    {
        healthApp.Run(async ctx =>
        {
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";

            var response = new HealthResponse
            {
                Status = "healthy",
                Timestamp = DateTime.UtcNow,
            };

            await ctx.Response.WriteAsync(JsonSerializer.Serialize(response, JsonOptions));
        });
    }

    private sealed class HealthResponse
    {
        public string Status { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; }
    }
}
