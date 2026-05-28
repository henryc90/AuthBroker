namespace AuthBroker.Core.Models;

/// <summary>
/// User profile returned from the authentication provider.
/// </summary>
public class UserProfile
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public List<string> Roles { get; set; } = new();
    public string TenantId { get; set; } = string.Empty;
}
