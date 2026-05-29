using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthBroker.Api.Endpoints;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;

namespace AuthBroker.Tests;

public class HealthEndpointTests
{
    /// <summary>
    /// Verifies that <c>GET /health</c> returns <c>200 OK</c> with
    /// <c>{"status":"healthy",...}</c> WITHOUT requiring an <c>X-Tenant-ID</c> header.
    /// </summary>
    [Fact]
    public async Task Health_returns_200_without_tenant_header()
    {
        // Arrange
        using var server = CreateHealthServer();
        using var client = server.CreateClient();
        // No X-Tenant-ID header

        // Act
        var response = await client.GetAsync("/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
    }

    /// <summary>
    /// Verifies the response body contains <c>status: "healthy"</c> and a valid <c>timestamp</c>.
    /// </summary>
    [Fact]
    public async Task Health_returns_healthy_status_and_timestamp()
    {
        // Arrange
        using var server = CreateHealthServer();
        using var client = server.CreateClient();

        // Act
        var response = await client.GetAsync("/health");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Assert
        body.GetProperty("status").GetString().Should().Be("healthy");

        var timestamp = body.GetProperty("timestamp").GetString();
        timestamp.Should().NotBeNullOrWhiteSpace();
        DateTime.TryParse(timestamp, out _).Should().BeTrue("timestamp should be a valid ISO 8601 date");
    }

    /// <summary>
    /// Verifies that <c>GET /health</c> still works even when the <c>X-Tenant-ID</c>
    /// header is present with a valid-looking value (it should be ignored).
    /// </summary>
    [Fact]
    public async Task Health_works_even_with_tenant_header()
    {
        // Arrange
        using var server = CreateHealthServer();
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-ID", "some-tenant");

        // Act
        var response = await client.GetAsync("/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    /// <summary>
    /// Creates a <see cref="TestServer"/> that only has the health endpoint branch,
    /// without any tenant resolution middleware.
    /// </summary>
    private static TestServer CreateHealthServer()
    {
        var builder = new WebHostBuilder()
            .Configure(app =>
            {
                app.Map("/health", HealthEndpoints.MapHealthBranch);
                app.Run(async ctx =>
                {
                    ctx.Response.StatusCode = 404;
                    await ctx.Response.WriteAsync("Not Found");
                });
            });

        return new TestServer(builder);
    }
}
