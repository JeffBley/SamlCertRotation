namespace SamlCertRotation.Models;

/// <summary>
/// Information about a client secret (without exposing the actual secret value)
/// </summary>
public class ClientSecretInfo
{
    /// <summary>
    /// A hint showing the first few characters of the secret
    /// </summary>
    public string Hint { get; set; } = string.Empty;

    /// <summary>
    /// When the secret expires
    /// </summary>
    public DateTime EndDateTime { get; set; }

    /// <summary>
    /// The full secret value (only populated immediately after creation)
    /// </summary>
    public string? SecretValue { get; set; }
}
