namespace AuthBroker.Core.Models;

/// <summary>
/// Authentication request payload sent by the client.
/// </summary>
public record RegisterRequest(
    string email,
    string Password
);
