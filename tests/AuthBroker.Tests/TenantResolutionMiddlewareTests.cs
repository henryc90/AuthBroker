using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthBroker.Api.Middleware;
using AuthBroker.Core;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthBroker.Tests;

public class TenantResolutionMiddlewareTests : IDisposable
{
    private const string TenantId = "acme-corp";
    private const string TenantName = "Acme Corp";
    private const string TenantDomain = "acme.com";

    /// <summary>
    /// In-memory configuration matching the structure of appsettings.json.
    /// </summary>
    private static readonly Dictionary<string, string?> BaseConfig = new()
    {
        ["Tenants:acme-corp:TenantId"] = TenantId,
        ["Tenants:acme-corp:TenantName"] = TenantName,
        ["Tenants:acme-corp:TenantDomain"] = TenantDomain,
        ["Tenants:acme-corp:ProviderType"] = "Keycloak",
    };

    [Fact]
    public async Task Valid_header_passes_through_to_next_middleware()
    {
        // Arrange
        using var server = CreateTestServer(BaseConfig);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-ID", TenantId);

        // Act
        var response = await client.GetAsync("/test");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Be("OK");
    }

    [Fact]
    public async Task Missing_header_returns_400()
    {
        // Arrange
        using var server = CreateTestServer(BaseConfig);
        using var client = server.CreateClient();
        // No X-Tenant-ID header

        // Act
        var response = await client.GetAsync("/test");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("error").GetString().Should().Be("X-Tenant-ID header is required");
    }

    [Fact]
    public async Task Missing_header_empty_value_returns_400()
    {
        // Arrange
        using var server = CreateTestServer(BaseConfig);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-ID", "");

        // Act
        var response = await client.GetAsync("/test");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Unknown_tenant_returns_404()
    {
        // Arrange
        using var server = CreateTestServer(BaseConfig);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-ID", "unknown-tenant");

        // Act
        var response = await client.GetAsync("/test");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("error").GetString().Should().Be("Tenant 'unknown-tenant' not found");
    }

    [Fact]
    public async Task TenantConfig_stored_in_HttpContext_Items()
    {
        // Arrange
        var builder = new WebHostBuilder()
            .ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(BaseConfig))
            .ConfigureServices(services => services.AddRouting())
            .Configure(app =>
            {
                app.UseMiddleware<TenantResolutionMiddleware>();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/check-tenant", async ctx =>
                    {
                        var stored = ctx.Items["TenantConfig"] as TenantConfig;
                        if (stored is null)
                        {
                            ctx.Response.StatusCode = 500;
                            await ctx.Response.WriteAsync("NOT_FOUND");
                            return;
                        }
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(
                            JsonSerializer.Serialize(new
                            {
                                stored.TenantId,
                                stored.TenantName,
                                stored.TenantDomain,
                                providerType = stored.ProviderType.ToString()
                            }));
                    });
                });
            });

        using var server = new TestServer(builder);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-ID", TenantId);

        // Act
        var response = await client.GetAsync("/check-tenant");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("TenantId").GetString().Should().Be(TenantId);
        body.GetProperty("TenantName").GetString().Should().Be(TenantName);
        body.GetProperty("TenantDomain").GetString().Should().Be(TenantDomain);
        body.GetProperty("providerType").GetString().Should().Be("Keycloak");
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    /// <summary>
    /// Creates a <see cref="TestServer"/> with the middleware and a simple
    /// downstream endpoint that returns 200 OK.
    /// </summary>
    private static TestServer CreateTestServer(Dictionary<string, string?> config)
    {
        var builder = new WebHostBuilder()
            .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(config))
            .Configure(app =>
            {
                app.UseMiddleware<TenantResolutionMiddleware>();
                app.Run(async ctx =>
                {
                    ctx.Response.StatusCode = 200;
                    await ctx.Response.WriteAsync("OK");
                });
            });

        return new TestServer(builder);
    }

    public void Dispose()
    {
        // TestServers are disposed via the using pattern in each test
    }
}
