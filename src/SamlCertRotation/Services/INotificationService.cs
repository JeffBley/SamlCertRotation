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
    /// Send notification when certificate is expiring soon (warning)
    /// </summary>
    Task<bool> SendExpirationWarningNotificationAsync(SamlApplication app, SamlCertificate expiringCert, int daysUntilExpiry);

    /// <summary>
    /// Send notification when an error occurs
    /// </summary>
    Task<bool> SendErrorNotificationAsync(SamlApplication app, string errorMessage, string operation);

    /// <summary>
    /// Send daily summary report
    /// </summary>
    Task<bool> SendDailySummaryAsync(DashboardStats stats, List<RotationResult> results);
}
