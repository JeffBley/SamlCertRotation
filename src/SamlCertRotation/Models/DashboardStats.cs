namespace SamlCertRotation.Models;

/// <summary>
/// Dashboard statistics for SAML applications
/// </summary>
public class DashboardStats
{
    /// <summary>
    /// Total number of SAML enterprise applications
    /// </summary>
    public int TotalSamlApps { get; set; }

    /// <summary>
    /// Apps with AutoRotate = "on"
    /// </summary>
    public int AppsWithAutoRotateOn { get; set; }

    /// <summary>
    /// Apps with AutoRotate = "off"
    /// </summary>
    public int AppsWithAutoRotateOff { get; set; }

    /// <summary>
    /// Apps with AutoRotate = null (not configured)
    /// </summary>
    public int AppsWithAutoRotateNull { get; set; }

    /// <summary>
    /// Apps with certificates expiring within 30 days
    /// </summary>
    public int AppsExpiringIn30Days { get; set; }

    /// <summary>
    /// Apps with certificates expiring within 60 days
    /// </summary>
    public int AppsExpiringIn60Days { get; set; }

    /// <summary>
    /// Apps with certificates expiring within 90 days
    /// </summary>
    public int AppsExpiringIn90Days { get; set; }

    /// <summary>
    /// Apps with expired certificates
    /// </summary>
    public int AppsWithExpiredCerts { get; set; }

    /// <summary>
    /// Timestamp when stats were generated
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// List of apps for detailed view
    /// </summary>
    public List<SamlAppSummary> Apps { get; set; } = new();
}

/// <summary>
/// Summary view of a SAML application for the dashboard
/// </summary>
public class SamlAppSummary
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? AutoRotateStatus { get; set; }
    public DateTime? CertExpiryDate { get; set; }
    public int? DaysUntilExpiry { get; set; }
    public string ExpiryCategory { get; set; } = string.Empty; // "Expired", "Critical", "Warning", "OK"
}

/// <summary>
/// Result of a certificate rotation operation
/// </summary>
public class RotationResult
{
    public string ServicePrincipalId { get; set; } = string.Empty;
    public string AppDisplayName { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Action { get; set; } = string.Empty; // "Created", "Activated", "None"
    public string? NewCertificateThumbprint { get; set; }
    public string? ErrorMessage { get; set; }
}
