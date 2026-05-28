namespace AuthBroker.Core.Models;

/// <summary>
/// Authentication request payload sent by the client.
/// </summary>
public record AuthRequest(
    string Username,
    string Password,
    string TenantId
);
