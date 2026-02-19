namespace SamlCertRotation.Models;

/// <summary>
/// Represents a SAML Enterprise Application with certificate information
/// </summary>
public class SamlApplication
{
    /// <summary>
    /// The object ID of the service principal
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// The application ID (client ID)
    /// </summary>
    public string AppId { get; set; } = string.Empty;

    /// <summary>
    /// Display name of the application
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Custom security attribute value for auto-rotation (on, off, or null)
    /// </summary>
    public string? AutoRotateStatus { get; set; }

    /// <summary>
    /// Sponsor email extracted from service principal tag AppSponsor=&lt;email&gt;
    /// </summary>
    public string? Sponsor { get; set; }

    /// <summary>
    /// List of SAML signing certificates
    /// </summary>
    public List<SamlCertificate> Certificates { get; set; } = new();

    /// <summary>
    /// Notification email addresses for this application
    /// </summary>
    public List<string> NotificationEmails { get; set; } = new();

    /// <summary>
    /// The active certificate thumbprint
    /// </summary>
    public string? ActiveCertificateThumbprint { get; set; }
}

/// <summary>
/// Represents a SAML signing certificate
/// </summary>
public class SamlCertificate
{
    /// <summary>
    /// Unique identifier for the certificate
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Certificate thumbprint
    /// </summary>
    public string Thumbprint { get; set; } = string.Empty;

    /// <summary>
    /// Certificate start date
    /// </summary>
    public DateTime StartDateTime { get; set; }

    /// <summary>
    /// Certificate expiration date
    /// </summary>
    public DateTime EndDateTime { get; set; }

    /// <summary>
    /// Type of credential (e.g., AsymmetricX509Cert)
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Usage of the key (Sign, Verify, etc.)
    /// </summary>
    public string Usage { get; set; } = string.Empty;

    /// <summary>
    /// Whether this is the active certificate
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Days until certificate expires
    /// </summary>
    public int DaysUntilExpiry => (int)(EndDateTime - DateTime.UtcNow).TotalDays;
}
