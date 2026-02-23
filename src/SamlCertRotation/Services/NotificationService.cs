using System.Net;
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
    private readonly IPolicyService _policyService;
    private readonly ILogger<NotificationService> _logger;
    private readonly string _adminEmails;

    public NotificationService(
        IGraphService graphService,
        IPolicyService policyService,
        ILogger<NotificationService> logger,
        IConfiguration configuration)
    {
        _graphService = graphService;
        _policyService = policyService;
        _logger = logger;
        _adminEmails = configuration["AdminNotificationEmails"] ?? "";
    }

    /// <inheritdoc />
    public async Task<bool> SendCertificateCreatedNotificationAsync(SamlApplication app, SamlCertificate newCert)
    {
        var recipients = await GetSponsorRecipientsAsync(app);
        if (!recipients.Any())
        {
            _logger.LogInformation("Sponsor notifications disabled or no sponsor recipient for app {AppName}", app.DisplayName);
            return false;
        }

        var subject = $"[SAML Cert Rotation] New Certificate Created - {app.DisplayName}";
        var body = GenerateCertificateCreatedEmail(app, newCert);

        return await _graphService.SendEmailAsync(recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendCertificateActivatedNotificationAsync(SamlApplication app, SamlCertificate activatedCert)
    {
        var recipients = await GetSponsorRecipientsAsync(app);
        if (!recipients.Any())
        {
            _logger.LogInformation("Sponsor notifications disabled or no sponsor recipient for app {AppName}", app.DisplayName);
            return false;
        }

        var subject = $"[SAML Cert Rotation] Certificate Activated - {app.DisplayName}";
        var body = GenerateCertificateActivatedEmail(app, activatedCert);

        return await _graphService.SendEmailAsync(recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendErrorNotificationAsync(SamlApplication app, string errorMessage, string operation)
    {
        var recipients = await GetRecipientsAsync(app);
        if (!recipients.Any()) return false;

        var subject = $"[SAML Cert Rotation] ERROR - {operation} Failed - {app.DisplayName}";
        var body = GenerateErrorEmail(app, errorMessage, operation);

        return await _graphService.SendEmailAsync(recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendDailySummaryAsync(DashboardStats stats, List<RotationResult> results)
    {
        var adminRecipients = await GetRunSummaryRecipientsAsync();
        if (!adminRecipients.Any())
        {
            _logger.LogWarning("No admin recipients configured for daily summary");
            return false;
        }

        var subject = $"[SAML Cert Rotation] Daily Summary - {DateTime.UtcNow:yyyy-MM-dd}";
        var body = GenerateDailySummaryEmail(stats, results);

        return await _graphService.SendEmailAsync(adminRecipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendNotifyOnlyReminderAsync(SamlApplication app, SamlCertificate expiringCert, int daysUntilExpiry, string appPortalUrl, string milestoneLabel)
    {
        var recipients = await GetSponsorRecipientsAsync(app);
        if (!recipients.Any())
        {
            _logger.LogInformation("Sponsor notifications disabled or no sponsor recipient for app {AppName}", app.DisplayName);
            return false;
        }

        var subject = $"[SAML Cert Rotation] [Notify] Certificate Expiring in {daysUntilExpiry} day(s) - {app.DisplayName}";
        var body = GenerateNotifyOnlyReminderEmail(app, expiringCert, daysUntilExpiry, appPortalUrl, milestoneLabel);
        return await _graphService.SendEmailAsync(recipients, subject, body);
    }

    /// <inheritdoc />
    public async Task<bool> SendSponsorExpirationStatusNotificationAsync(SamlApplication app, SamlCertificate cert, int daysUntilExpiry, string appPortalUrl, string status, bool manualSend)
    {
        var recipients = GetSponsorDirectRecipients(app);
        if (!recipients.Any())
        {
            _logger.LogInformation("No sponsor recipient configured for app {AppName}", app.DisplayName);
            return false;
        }

        var normalizedStatus = (status ?? string.Empty).Trim();
        var sendModeText = manualSend ? "Manual" : "Automatic";

        var subject = string.Equals(normalizedStatus, "Expired", StringComparison.OrdinalIgnoreCase)
            ? $"[SAML Cert Rotation] [{sendModeText}] Application Certificate Expired - {app.DisplayName}"
            : $"[SAML Cert Rotation] [{sendModeText}] {normalizedStatus} Certificate Status - {app.DisplayName}";

        var body = GenerateSponsorExpirationStatusEmail(app, cert, daysUntilExpiry, appPortalUrl, normalizedStatus, manualSend);
        return await _graphService.SendEmailAsync(recipients, subject, body);
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

    private async Task<List<string>> GetSponsorRecipientsAsync(SamlApplication app)
    {
        var enabled = await _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
        if (!enabled)
        {
            return new List<string>();
        }

        if (string.IsNullOrWhiteSpace(app.Sponsor))
        {
            return new List<string>();
        }

        return new List<string> { app.Sponsor.Trim() };
    }

    private List<string> GetSponsorDirectRecipients(SamlApplication app)
    {
        if (string.IsNullOrWhiteSpace(app.Sponsor))
        {
            return new List<string>();
        }

        return new List<string> { app.Sponsor.Trim() };
    }

    private async Task<List<string>> GetRunSummaryRecipientsAsync()
    {
        var recipients = new List<string>();

        var configured = await _policyService.GetNotificationEmailsAsync();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            recipients.AddRange(SplitEmails(configured));
        }

        if (!recipients.Any())
        {
            recipients.AddRange(GetAdminRecipients());
        }

        return recipients
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Select(e => e.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IEnumerable<string> SplitEmails(string emails)
    {
        return emails.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
    }

    private List<string> GetAdminRecipients()
    {
        if (string.IsNullOrEmpty(_adminEmails))
            return new List<string>();

        return _adminEmails.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(e => e.Trim())
            .ToList();
    }

    /// <summary>
    /// HTML-encode a value so it is safe to interpolate into HTML templates.
    /// </summary>
    private static string H(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

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
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>New Certificate Thumbprint:</span> {H(newCert.Thumbprint)}</p>
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
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>Activated Certificate Thumbprint:</span> {H(activatedCert.Thumbprint)}</p>
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
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>Operation:</span> {H(operation)}</p>
                <p><span class='label'>Time:</span> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>
            </div>
            <div class='error'>{H(errorMessage)}</div>
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
        var successCount = results.Count(r =>
            r.Success && (
                string.Equals(r.Action, "Created", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Activated", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase)));
        var failureCount = results.Count(r => !r.Success);
        var skippedCount = Math.Max(0, results.Count - successCount - failureCount);

        var resultsHtml = string.Join("", results.Select(r => $@"
            <tr>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>{H(r.AppDisplayName)}</td>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>{H(r.Action)}</td>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>
                    <span style='color: {(!r.Success ? "#d13438" : (string.Equals(r.Action, "Created", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Action, "Activated", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase) ? "#107c10" : "#797775"))}'>{(!r.Success ? "✗ Failed" : (string.Equals(r.Action, "Created", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Action, "Activated", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase) ? "✓ Success" : "↷ Skipped"))}</span>
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
                    <div class='stat-value' style='color: #0078d4;'>{stats.AppsWithAutoRotateNotify}</div>
                    <div class='stat-label'>Notify</div>
                </div>
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
            <p><strong>Success:</strong> {successCount} &nbsp; <strong>Skipped:</strong> {skippedCount} &nbsp; <strong>Failed:</strong> {failureCount}</p>
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

    private string GenerateNotifyOnlyReminderEmail(SamlApplication app, SamlCertificate cert, int daysUntilExpiry, string appPortalUrl, string milestoneLabel)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #d13438; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .warning {{ background: #fff4ce; border-left: 4px solid #ffb900; padding: 15px; margin: 15px 0; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .button {{ display: inline-block; padding: 10px 14px; background: #0078d4; color: white; text-decoration: none; border-radius: 4px; margin-top: 12px; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>⚠️ SAML Certificate Expiration Reminder</h2>
        </div>
        <div class='content'>
            <div class='warning'>
                <strong>This application is configured as Notify.</strong><br/>
                The current signing certificate expires in <strong>{daysUntilExpiry} day(s)</strong>.
            </div>
            <div class='details'>
                <p><span class='label'>Reminder milestone:</span> {H(milestoneLabel)}</p>
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>Service Principal Object ID:</span> {H(app.Id)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>Certificate Thumbprint:</span> {H(cert.Thumbprint)}</p>
                <p><span class='label'>Expires On:</span> {cert.EndDateTime:yyyy-MM-dd HH:mm} UTC</p>
                <a class='button' href='{H(appPortalUrl)}'>Open Enterprise Application</a>
            </div>
            <p style='margin-top:16px;'>No automatic rotation will occur while Auto-Rotate is set to Notify.</p>
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    private string GenerateSponsorExpirationStatusEmail(SamlApplication app, SamlCertificate cert, int daysUntilExpiry, string appPortalUrl, string status, bool manualSend)
    {
        var isExpired = string.Equals(status, "Expired", StringComparison.OrdinalIgnoreCase);
        var headerColor = isExpired ? "#d13438" : "#ffb900";
        var title = isExpired ? "⚠️ SAML Certificate Has Expired" : "⚠️ SAML Certificate Needs Attention";
        var statusText = isExpired ? "Expired" : status;
        var introText = isExpired
            ? "The signing certificate for this SAML application has expired. Please remediate this as quickly as possible to avoid or resolve sign-in impact."
            : $"The signing certificate for this SAML application is in {statusText} state and requires attention.";

        var dateText = cert.EndDateTime.ToString("yyyy-MM-dd HH:mm") + " UTC";

        var modeText = manualSend ? "Manual resend requested from dashboard." : "Automatically generated notification.";

        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {headerColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .notice {{ background: #fff4ce; border-left: 4px solid {headerColor}; padding: 15px; margin: 15px 0; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .button {{ display: inline-block; padding: 10px 14px; background: #0078d4; color: white; text-decoration: none; border-radius: 4px; margin-top: 12px; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>{title}</h2>
        </div>
        <div class='content'>
            <div class='notice'>
                <strong>{H(introText)}</strong>
            </div>
            <div class='details'>
                <p><span class='label'>Status:</span> {H(statusText)}</p>
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>Service Principal Object ID:</span> {H(app.Id)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>Certificate Thumbprint:</span> {H(cert.Thumbprint)}</p>
                <p><span class='label'>{(isExpired ? "Expired On" : "Expires On")}:</span> {H(dateText)}</p>
                <p><span class='label'>Days Remaining:</span> {daysUntilExpiry}</p>
                <p><span class='label'>Notification:</span> {H(modeText)}</p>
                <a class='button' href='{H(appPortalUrl)}'>Open Enterprise Application</a>
            </div>
            <p style='margin-top:16px;'>Please review and remediate this application promptly.</p>
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    /// <summary>
    /// Available test email template names.
    /// </summary>
    public static readonly string[] TestTemplateNames = new[]
    {
        "CertificateCreated",
        "CertificateActivated",
        "Error",
        "DailySummary",
        "NotifyReminder",
        "SponsorExpirationExpired",
        "SponsorExpirationCritical",
        "SponsorExpirationWarning"
    };

    /// <inheritdoc />
    public async Task<bool> SendTestEmailAsync(string templateName, string toEmail)
    {
        var sampleApp = new SamlApplication
        {
            Id = "00000000-0000-0000-0000-000000000000",
            AppId = "11111111-1111-1111-1111-111111111111",
            DisplayName = "Contoso SAML App (Test)",
            AutoRotateStatus = "on",
            Sponsor = toEmail,
            Certificates = new List<SamlCertificate>
            {
                new SamlCertificate
                {
                    KeyId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    Thumbprint = "AB12CD34EF56789012345678901234567890ABCD",
                    StartDateTime = DateTime.UtcNow.AddYears(-2),
                    EndDateTime = DateTime.UtcNow.AddDays(25),
                    Type = "AsymmetricX509Cert",
                    Usage = "Sign",
                    IsActive = true
                },
                new SamlCertificate
                {
                    KeyId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    Thumbprint = "FF99EE88DD77CC66BB55AA4433221100FFEEDDCC",
                    StartDateTime = DateTime.UtcNow,
                    EndDateTime = DateTime.UtcNow.AddYears(3),
                    Type = "AsymmetricX509Cert",
                    Usage = "Sign",
                    IsActive = false
                }
            }
        };

        var activeCert = sampleApp.Certificates[0];
        var newCert = sampleApp.Certificates[1];
        var appUrl = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/00000000-0000-0000-0000-000000000000/appId/11111111-1111-1111-1111-111111111111";

        string subject;
        string body;

        switch (templateName)
        {
            case "CertificateCreated":
                subject = $"[TEST] [SAML Cert Rotation] New Certificate Created - {sampleApp.DisplayName}";
                body = GenerateCertificateCreatedEmail(sampleApp, newCert);
                break;

            case "CertificateActivated":
                subject = $"[TEST] [SAML Cert Rotation] Certificate Activated - {sampleApp.DisplayName}";
                body = GenerateCertificateActivatedEmail(sampleApp, newCert);
                break;

            case "Error":
                subject = $"[TEST] [SAML Cert Rotation] ERROR - CreateCertificate Failed - {sampleApp.DisplayName}";
                body = GenerateErrorEmail(sampleApp, "System.Exception: This is a sample error message for testing purposes.\n   at SamlCertRotation.Services.GraphService.CreateSamlCertificateAsync(String id)", "CreateCertificate");
                break;

            case "DailySummary":
                var sampleStats = new DashboardStats
                {
                    TotalSamlApps = 42,
                    AppsWithAutoRotateOn = 28,
                    AppsWithAutoRotateOff = 5,
                    AppsWithAutoRotateNotify = 6,
                    AppsWithAutoRotateNull = 3,
                    AppsExpiringIn30Days = 4,
                    AppsWithExpiredCerts = 1
                };
                var sampleResults = new List<RotationResult>
                {
                    new RotationResult { AppDisplayName = "Contoso SAML App A", Success = true, Action = "Created" },
                    new RotationResult { AppDisplayName = "Contoso SAML App B", Success = true, Action = "Activated" },
                    new RotationResult { AppDisplayName = "Contoso SAML App C", Success = true, Action = "None" },
                    new RotationResult { AppDisplayName = "Contoso SAML App D", Success = false, Action = "Create Failed", ErrorMessage = "Insufficient permissions" }
                };
                subject = $"[TEST] [SAML Cert Rotation] Daily Summary - {DateTime.UtcNow:yyyy-MM-dd}";
                body = GenerateDailySummaryEmail(sampleStats, sampleResults);
                break;

            case "NotifyReminder":
                subject = $"[TEST] [SAML Cert Rotation] [Notify] Certificate Expiring in 25 day(s) - {sampleApp.DisplayName}";
                body = GenerateNotifyOnlyReminderEmail(sampleApp, activeCert, 25, appUrl, "30-day reminder");
                break;

            case "SponsorExpirationExpired":
                subject = $"[TEST] [SAML Cert Rotation] [Manual] Application Certificate Expired - {sampleApp.DisplayName}";
                body = GenerateSponsorExpirationStatusEmail(sampleApp, activeCert, -3, appUrl, "Expired", true);
                break;

            case "SponsorExpirationCritical":
                subject = $"[TEST] [SAML Cert Rotation] [Manual] Critical Certificate Status - {sampleApp.DisplayName}";
                body = GenerateSponsorExpirationStatusEmail(sampleApp, activeCert, 5, appUrl, "Critical", true);
                break;

            case "SponsorExpirationWarning":
                subject = $"[TEST] [SAML Cert Rotation] [Manual] Warning Certificate Status - {sampleApp.DisplayName}";
                body = GenerateSponsorExpirationStatusEmail(sampleApp, activeCert, 25, appUrl, "Warning", true);
                break;

            default:
                _logger.LogWarning("Unknown test email template: {Template}", templateName);
                return false;
        }

        return await _graphService.SendEmailAsync(new List<string> { toEmail }, subject, body);
    }
}
