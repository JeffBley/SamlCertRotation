namespace SamlCertRotation.Models;

/// <summary>
/// Captures details of a certificate action that should be included in a
/// consolidated sponsor notification email.
/// </summary>
public class SponsorNotificationItem
{
    /// <summary>
    /// The application that was processed.
    /// </summary>
    public SamlApplication App { get; set; } = null!;

    /// <summary>
    /// Human-readable category for grouping, e.g. "Certificate Created", "Certificate Activated".
    /// </summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>
    /// The certificate that was created or activated (may be null for error items).
    /// </summary>
    public SamlCertificate? Certificate { get; set; }
}
