using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Interface for sending notifications
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// Send notification when a new certificate is created
    /// </summary>
    Task<bool> SendCertificateCreatedNotificationAsync(SamlApplication app, SamlCertificate newCert);

    /// <summary>
    /// Send notification when a certificate is activated
    /// </summary>
    Task<bool> SendCertificateActivatedNotificationAsync(SamlApplication app, SamlCertificate activatedCert);

    /// <summary>
    /// Send notification when an error occurs
    /// </summary>
    Task<bool> SendErrorNotificationAsync(SamlApplication app, string errorMessage, string operation);

    /// <summary>
    /// Send daily summary report
    /// </summary>
    Task<bool> SendDailySummaryAsync(DashboardStats stats, List<RotationResult> results);

    /// <summary>
    /// Send notify-only reminder to app sponsor when certificate is approaching expiry
    /// </summary>
    Task<bool> SendNotifyOnlyReminderAsync(SamlApplication app, SamlCertificate expiringCert, int daysUntilExpiry, string appPortalUrl, string milestoneLabel);

    /// <summary>
    /// Send sponsor expiration email for Expired/Critical/Warning status
    /// </summary>
    Task<bool> SendSponsorExpirationStatusNotificationAsync(SamlApplication app, SamlCertificate cert, int daysUntilExpiry, string appPortalUrl, string status, bool manualSend);

    /// <summary>
    /// Send a single consolidated email to each sponsor summarising all certificate
    /// actions that affected their sponsored applications during a rotation run.
    /// Items are grouped by action category (e.g. "Certificate Created", "Certificate Activated").
    /// </summary>
    Task SendConsolidatedSponsorNotificationsAsync(List<SponsorNotificationItem> pendingNotifications);

    /// <summary>
    /// Send a test email using a named template with sample data
    /// </summary>
    Task<bool> SendTestEmailAsync(string templateName, string toEmail);
}
