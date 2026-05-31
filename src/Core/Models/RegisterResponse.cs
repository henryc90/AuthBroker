namespace AuthBroker.Core.Models;

/// <summary>
/// Response returned after successful user registration.
/// Contains the user identifier and email created by the provider.
/// </summary>
public class RegisterResponse
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}
