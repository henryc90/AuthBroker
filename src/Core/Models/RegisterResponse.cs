namespace AuthBroker.Core.Models;

/// <summary>
/// Authentication response payload sent by the provider.
/// </summary>
public record RegisterResponse(
    string email
);
