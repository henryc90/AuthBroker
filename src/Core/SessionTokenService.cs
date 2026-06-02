using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthBroker.Core;

/// <summary>
/// Creates and validates signed session JWTs that replace opaque Auth0 tokens
/// after initial validation. This avoids calling Auth0 on every request.
///
/// Tokens are signed with HS256 using the tenant's ClientSecret as the key.
/// Each tenant gets its own keys so tokens are tenant-scoped.
/// </summary>
public class SessionTokenService
{
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(15);
    private const string Issuer = "auth-broker";

    /// <summary>
    /// Creates a signed session JWT from an already-validated principal.
    /// </summary>
    public string CreateToken(ClaimsPrincipal principal, Auth0TenantConfig tenant)
    {
        var key = DeriveKey(tenant.ClientSecret);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, principal.FindFirst("sub")?.Value ?? ""),
            new(JwtRegisteredClaimNames.Email, principal.FindFirst("email")?.Value ?? ""),
            new("tenant_id", tenant.TenantId),
        };

        // Preserve roles if present (Auth0 namespace)
        foreach (var role in principal.FindAll("https://schemas.auth0.com/roles"))
        {
            claims.Add(role);
        }

        // Preserve nickname/name if present
        var name = principal.FindFirst("nickname") ?? principal.FindFirst("name");
        if (name is not null)
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, name.Value));

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: tenant.Audience ?? tenant.ClientId,
            claims: claims,
            expires: DateTime.UtcNow.Add(TokenLifetime),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Validates a session JWT and returns the ClaimsPrincipal, or null if invalid/expired.
    /// </summary>
    public ClaimsPrincipal? ValidateToken(string token, Auth0TenantConfig tenant)
    {
        try
        {
            var key = DeriveKey(tenant.ClientSecret);

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = false,
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.FromMinutes(1),
            };

            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(token, parameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Derives a 32-byte key from the client secret for HS256.
    /// Uses first 32 bytes if longer, pads with zeros if shorter.
    /// </summary>
    private static byte[] DeriveKey(string clientSecret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(clientSecret);

        if (keyBytes.Length >= 32)
            return keyBytes[..32];

        // Pad short secrets to 32 bytes (HS256 minimum key length)
        var padded = new byte[32];
        keyBytes.CopyTo(padded, 0);
        return padded;
    }
}
