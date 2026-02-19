namespace SamlCertRotation.Models;

/// <summary>
/// Request model for updating settings
/// </summary>
public class SettingsUpdateRequest
{
    /// <summary>
    /// Comma-separated list of notification email addresses
    /// </summary>
    public string? NotificationEmails { get; set; }

    /// <summary>
    /// Whether report-only mode is enabled
    /// </summary>
    public bool? ReportOnlyModeEnabled { get; set; }

    /// <summary>
    /// Retention policy in days
    /// </summary>
    public int? RetentionPolicyDays { get; set; }

    /// <summary>
    /// Whether app sponsors should receive notifications
    /// </summary>
    public bool? SponsorsReceiveNotifications { get; set; }

    /// <summary>
    /// Days before expiry for sponsor 1st reminder
    /// </summary>
    public int? SponsorFirstReminderDays { get; set; }

    /// <summary>
    /// Days before expiry for sponsor 2nd reminder
    /// </summary>
    public int? SponsorSecondReminderDays { get; set; }

    /// <summary>
    /// Days before expiry for sponsor 3rd reminder
    /// </summary>
    public int? SponsorThirdReminderDays { get; set; }
}
