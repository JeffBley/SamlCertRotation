using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of notification service using Microsoft Graph
/// </summary>
public class NotificationService : INotificationService
{
    private readonly IGraphService _graphService;
    private readonly ILogger<NotificationService> _logger;
    private readonly string _senderEmail;
    private readonly string _adminEmails;

    public NotificationService(
        IGraphService graphService,
        ILogger<NotificationService> logger,
        IConfiguration configuration)
    {
        _graphService = graphService;
        _logger = logger;
        _senderEmail = configuration["NotificationSenderEmail"] ?? "noreply@yourdomain.com";
        _adminEmails = configuration["AdminNotificationEmails"] ?? "";
    }

    /// <inheritdoc />
    public async Task<bool> SendCertificateCreatedNotificationAsync(SamlApplication app, SamlCertificate newCert)
    {
        var recipients = await GetRecipientsAsync(app);
        if (!recipients.Any())
        {
            _logger.LogWarning("No recipients found for app {AppName}", app.DisplayName);
            return false;
        }

        var subject = $"[SAML Cert Rotation] New Certificate Created - {app.DisplayName}";
        var body = GenerateCertificateCreatedEmail(app, newCert);

        return await _graphService.SendEmailAsync(_senderEmail, recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendCertificateActivatedNotificationAsync(SamlApplication app, SamlCertificate activatedCert)
    {
        var recipients = await GetRecipientsAsync(app);
        if (!recipients.Any())
        {
            _logger.LogWarning("No recipients found for app {AppName}", app.DisplayName);
            return false;
        }

        var subject = $"[SAML Cert Rotation] Certificate Activated - {app.DisplayName}";
        var body = GenerateCertificateActivatedEmail(app, activatedCert);

        return await _graphService.SendEmailAsync(_senderEmail, recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendExpirationWarningNotificationAsync(SamlApplication app, SamlCertificate expiringCert, int daysUntilExpiry)
    {
        var recipients = await GetRecipientsAsync(app);
        if (!recipients.Any()) return false;

        var urgency = daysUntilExpiry <= 7 ? "URGENT" : "Warning";
        var subject = $"[SAML Cert Rotation] [{urgency}] Certificate Expiring in {daysUntilExpiry} days - {app.DisplayName}";
        var body = GenerateExpirationWarningEmail(app, expiringCert, daysUntilExpiry);

        return await _graphService.SendEmailAsync(_senderEmail, recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendErrorNotificationAsync(SamlApplication app, string errorMessage, string operation)
    {
        var recipients = await GetRecipientsAsync(app);
        if (!recipients.Any()) return false;

        var subject = $"[SAML Cert Rotation] ERROR - {operation} Failed - {app.DisplayName}";
        var body = GenerateErrorEmail(app, errorMessage, operation);

        return await _graphService.SendEmailAsync(_senderEmail, recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendDailySummaryAsync(DashboardStats stats, List<RotationResult> results)
    {
        var adminRecipients = GetAdminRecipients();
        if (!adminRecipients.Any())
        {
            _logger.LogWarning("No admin recipients configured for daily summary");
            return false;
        }

        var subject = $"[SAML Cert Rotation] Daily Summary - {DateTime.UtcNow:yyyy-MM-dd}";
        var body = GenerateDailySummaryEmail(stats, results);

        return await _graphService.SendEmailAsync(_senderEmail, adminRecipients, subject, body);
    }

    private async Task<List<string>> GetRecipientsAsync(SamlApplication app)
    {
        var recipients = new List<string>();
        
        // Add app notification emails
        if (app.NotificationEmails.Any())
        {
            recipients.AddRange(app.NotificationEmails);
        }

        // Get app owners
        var owners = await _graphService.GetAppOwnersEmailsAsync(app.Id);
        recipients.AddRange(owners);

        // Add admin emails
        recipients.AddRange(GetAdminRecipients());

        return recipients.Distinct().ToList();
    }

    private List<string> GetAdminRecipients()
    {
        if (string.IsNullOrEmpty(_adminEmails))
            return new List<string>();

        return _adminEmails.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(e => e.Trim())
            .ToList();
    }

    private string GenerateCertificateCreatedEmail(SamlApplication app, SamlCertificate newCert)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #0078d4; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .success {{ background: #dff6dd; border-left: 4px solid #107c10; padding: 15px; margin: 15px 0; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>🔐 New SAML Certificate Created</h2>
        </div>
        <div class='content'>
            <div class='success'>
                <strong>A new SAML signing certificate has been created for your application.</strong>
            </div>
            <div class='details'>
                <p><span class='label'>Application:</span> {app.DisplayName}</p>
                <p><span class='label'>App ID:</span> {app.AppId}</p>
                <p><span class='label'>New Certificate Thumbprint:</span> {newCert.Thumbprint}</p>
                <p><span class='label'>Valid From:</span> {newCert.StartDateTime:yyyy-MM-dd HH:mm} UTC</p>
                <p><span class='label'>Valid Until:</span> {newCert.EndDateTime:yyyy-MM-dd HH:mm} UTC</p>
            </div>
            <p style='margin-top: 20px;'>
                <strong>Note:</strong> This certificate is NOT yet active. It will be automatically activated 
                closer to the expiration of the current certificate according to your policy settings.
            </p>
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    private string GenerateCertificateActivatedEmail(SamlApplication app, SamlCertificate activatedCert)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #107c10; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .activated {{ background: #dff6dd; border-left: 4px solid #107c10; padding: 15px; margin: 15px 0; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .action-required {{ background: #fff4ce; border-left: 4px solid #ffb900; padding: 15px; margin: 15px 0; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>✅ SAML Certificate Activated</h2>
        </div>
        <div class='content'>
            <div class='activated'>
                <strong>A new SAML signing certificate has been activated for your application.</strong>
            </div>
            <div class='details'>
                <p><span class='label'>Application:</span> {app.DisplayName}</p>
                <p><span class='label'>App ID:</span> {app.AppId}</p>
                <p><span class='label'>Activated Certificate Thumbprint:</span> {activatedCert.Thumbprint}</p>
                <p><span class='label'>Valid Until:</span> {activatedCert.EndDateTime:yyyy-MM-dd HH:mm} UTC</p>
            </div>
            <div class='action-required'>
                <strong>⚠️ Action May Be Required:</strong><br/>
                If your SAML Service Provider does not automatically fetch metadata updates, you may need 
                to manually update the SP with the new certificate. Otherwise, SAML authentication may fail.
            </div>
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    private string GenerateExpirationWarningEmail(SamlApplication app, SamlCertificate cert, int daysUntilExpiry)
    {
        var urgencyColor = daysUntilExpiry <= 7 ? "#d13438" : "#ffb900";
        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {urgencyColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .warning {{ background: #fff4ce; border-left: 4px solid {urgencyColor}; padding: 15px; margin: 15px 0; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>⚠️ Certificate Expiring in {daysUntilExpiry} Days</h2>
        </div>
        <div class='content'>
            <div class='warning'>
                <strong>The SAML signing certificate for this application is expiring soon.</strong>
            </div>
            <div class='details'>
                <p><span class='label'>Application:</span> {app.DisplayName}</p>
                <p><span class='label'>App ID:</span> {app.AppId}</p>
                <p><span class='label'>Certificate Thumbprint:</span> {cert.Thumbprint}</p>
                <p><span class='label'>Expires On:</span> {cert.EndDateTime:yyyy-MM-dd HH:mm} UTC</p>
                <p><span class='label'>Days Remaining:</span> {daysUntilExpiry}</p>
            </div>
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    private string GenerateErrorEmail(SamlApplication app, string errorMessage, string operation)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #d13438; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .error {{ background: #fde7e9; border-left: 4px solid #d13438; padding: 15px; margin: 15px 0; font-family: monospace; white-space: pre-wrap; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>❌ Certificate Operation Failed</h2>
        </div>
        <div class='content'>
            <div class='details'>
                <p><span class='label'>Application:</span> {app.DisplayName}</p>
                <p><span class='label'>App ID:</span> {app.AppId}</p>
                <p><span class='label'>Operation:</span> {operation}</p>
                <p><span class='label'>Time:</span> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>
            </div>
            <div class='error'>{errorMessage}</div>
            <p>Please investigate this error and take appropriate action.</p>
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    private string GenerateDailySummaryEmail(DashboardStats stats, List<RotationResult> results)
    {
        var successCount = results.Count(r => r.Success);
        var failureCount = results.Count(r => !r.Success);

        var resultsHtml = string.Join("", results.Select(r => $@"
            <tr>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>{r.AppDisplayName}</td>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>{r.Action}</td>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>
                    <span style='color: {(r.Success ? "#107c10" : "#d13438")}'>{(r.Success ? "✓ Success" : "✗ Failed")}</span>
                </td>
            </tr>"));

        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #0078d4; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 28px; font-weight: bold; color: #0078d4; }}
        .stat-label {{ font-size: 12px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th {{ background: #f0f0f0; padding: 10px; text-align: left; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>📊 Daily SAML Certificate Rotation Summary</h2>
            <p style='margin: 5px 0 0 0; opacity: 0.9;'>{DateTime.UtcNow:dddd, MMMM d, yyyy}</p>
        </div>
        <div class='content'>
            <h3>Overview</h3>
            <div class='stats-grid'>
                <div class='stat-card'>
                    <div class='stat-value'>{stats.TotalSamlApps}</div>
                    <div class='stat-label'>Total SAML Apps</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' style='color: #107c10;'>{stats.AppsWithAutoRotateOn}</div>
                    <div class='stat-label'>Auto-Rotate ON</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' style='color: #d13438;'>{stats.AppsWithAutoRotateOff}</div>
                    <div class='stat-label'>Auto-Rotate OFF</div>
                </div>
            </div>
            <div class='stats-grid'>
                <div class='stat-card'>
                    <div class='stat-value' style='color: #797775;'>{stats.AppsWithAutoRotateNull}</div>
                    <div class='stat-label'>Not Configured</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' style='color: #ffb900;'>{stats.AppsExpiringIn30Days}</div>
                    <div class='stat-label'>Expiring in 30 Days</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' style='color: #d13438;'>{stats.AppsWithExpiredCerts}</div>
                    <div class='stat-label'>Expired</div>
                </div>
            </div>

            <h3>Today's Actions ({results.Count} operations)</h3>
            {(results.Any() ? $@"
            <table>
                <tr>
                    <th>Application</th>
                    <th>Action</th>
                    <th>Result</th>
                </tr>
                {resultsHtml}
            </table>" : "<p>No rotation actions were performed today.</p>")}
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }
}
