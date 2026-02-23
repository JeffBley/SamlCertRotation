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
    /// Whether sponsors should be automatically notified when certificates are expired/critical/warning
    /// </summary>
    public bool? NotifySponsorsOnExpiration { get; set; }

    /// <summary>
    /// Whether sponsor reminders for notify apps are enabled
    /// </summary>
    public bool? SponsorRemindersEnabled { get; set; }

    /// <summary>
    /// Number of sponsor reminders to send (1-3)
    /// </summary>
    public int? SponsorReminderCount { get; set; }

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

    /// <summary>
    /// Session timeout in minutes (0 = disabled)
    /// </summary>
    public int? SessionTimeoutMinutes { get; set; }

    /// <summary>
    /// Whether to automatically create (but not activate) new certificates for notify-only apps
    /// </summary>
    public bool? CreateCertsForNotifyApps { get; set; }
}
