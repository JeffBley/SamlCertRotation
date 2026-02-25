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
    /// Apps with AutoRotate = "notify" (notify only, no auto-rotation)
    /// </summary>
    public int AppsWithAutoRotateNotify { get; set; }

    /// <summary>
    /// Apps with certificates expiring within the configured create threshold
    /// </summary>
    public int AppsExpiringSoon { get; set; }

    /// <summary>
    /// Current create-threshold (days) used to calculate AppsExpiringSoon
    /// </summary>
    public int ExpiringSoonThresholdDays { get; set; } = 30;

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
    public string AppId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Sponsor { get; set; }
    public string? AutoRotateStatus { get; set; }
    public DateTime? CertExpiryDate { get; set; }
    public int? DaysUntilExpiry { get; set; }
    public string ExpiryCategory { get; set; } = string.Empty; // "Expired", "Critical", "Warning", "OK"

    /// <summary>
    /// Whether an app-specific policy override exists ("Global" or "App-Specific")
    /// </summary>
    public string PolicyType { get; set; } = "Global";

    /// <summary>
    /// Effective days before expiry to create a new certificate
    /// </summary>
    public int CreateCertDaysBeforeExpiry { get; set; }

    /// <summary>
    /// Effective days before expiry to activate the new certificate
    /// </summary>
    public int ActivateCertDaysBeforeExpiry { get; set; }
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

    /// <summary>
    /// Returns true when this result represents a meaningful action (not a skipped/no-op app).
    /// Used to filter report detail listings to only show apps requiring attention.
    /// </summary>
    public bool IsActionable =>
        !string.IsNullOrEmpty(Action) &&
        !string.Equals(Action, "None", StringComparison.OrdinalIgnoreCase) &&
        !Action.StartsWith("None ", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Computes successful/skipped/failed totals for rotation run summaries.
    /// </summary>
    public static (int successful, int skipped, int failed) GetOutcomeCounts(List<RotationResult> results)
    {
        var successful = results.Count(r =>
            r.Success && (
                string.Equals(r.Action, "Created", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Activated", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Notified", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Notify", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Created (Notify)", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Create (Notify)", StringComparison.OrdinalIgnoreCase)));

        var failed = results.Count(r => !r.Success);
        var skipped = Math.Max(0, results.Count - successful - failed);
        return (successful, skipped, failed);
    }
}
