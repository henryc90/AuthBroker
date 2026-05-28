using System.Net;

namespace AuthBroker.Tests;

/// <summary>
/// An <see cref="HttpMessageHandler"/> that delegates response creation to
/// a user-supplied function, enabling flexible mocking of HTTP interactions.
/// </summary>
public class TestHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

    public TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
    {
        _handler = handler;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(_handler(request));
    }
}

/// <summary>
/// Helper to create JSON <see cref="HttpResponseMessage"/> values.
/// </summary>
internal static class ResponseHelper
{
    public static HttpResponseMessage Json(HttpStatusCode status, string json)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
    }

    public static HttpResponseMessage Ok(string json) => Json(HttpStatusCode.OK, json);
}
