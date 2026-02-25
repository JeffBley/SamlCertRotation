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

    /// <summary>
    /// Actions that count as "successful" in daily summary emails.
    /// Must stay aligned with <see cref="RotationResult.GetOutcomeCounts"/>.
    /// </summary>
    private static readonly HashSet<string> SuccessActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "Created", "Activated", "Would Create", "Would Activate",
        "Notified", "Would Notify", "Created (Notify)", "Would Create (Notify)"
    };

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
        var body = GenerateCertificateActionEmail(app, newCert, isActivation: false);

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
        var body = GenerateCertificateActionEmail(app, activatedCert, isActivation: true);

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
        var recipients = await GetSponsorReminderRecipientsAsync(app);
        if (!recipients.Any())
        {
            _logger.LogInformation("Sponsor notifications disabled or no sponsor recipient for app {AppName}", app.DisplayName);
            return false;
        }

        var subject = $"[SAML Cert Rotation] [Notify] Certificate Expiring in {daysUntilExpiry} day(s) - {app.DisplayName}";
        var body = GenerateSponsorExpirationStatusEmail(app, expiringCert, daysUntilExpiry, appPortalUrl, "Notify", manualSend: false, milestoneLabel: milestoneLabel);
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

        return ParseSponsorEmails(app.Sponsor);
    }

    private async Task<List<string>> GetSponsorReminderRecipientsAsync(SamlApplication app)
    {
        var enabled = await _policyService.GetSponsorRemindersEnabledAsync();
        if (!enabled)
        {
            return new List<string>();
        }

        return ParseSponsorEmails(app.Sponsor);
    }

    private List<string> GetSponsorDirectRecipients(SamlApplication app)
    {
        return ParseSponsorEmails(app.Sponsor);
    }

    /// <summary>
    /// Parses a semicolon-separated sponsor string into a list of trimmed, non-empty email addresses.
    /// </summary>
    private static List<string> ParseSponsorEmails(string? sponsorField)
    {
        if (string.IsNullOrWhiteSpace(sponsorField))
        {
            return new List<string>();
        }

        return sponsorField
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
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

    /// <summary>
    /// Shared email shell that wraps content in the standard HTML structure (DOCTYPE, styles,
    /// header, content area, footer). All generators delegate to this to avoid boilerplate duplication.
    /// </summary>
    private static string EmailShell(string headerColor, string title, string? subtitle, string contentHtml, string extraStyles = "", int maxWidth = 600)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: {maxWidth}px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {headerColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; }}
        .details {{ background: white; padding: 15px; border-radius: 4px; margin-top: 15px; }}
        .label {{ font-weight: 600; color: #666; }}
        .callout-green {{ background: #dff6dd; border-left: 4px solid #107c10; padding: 15px; margin: 15px 0; }}
        .callout-yellow {{ background: #fff4ce; border-left: 4px solid #ffb900; padding: 15px; margin: 15px 0; }}
        .callout-red {{ background: #fde7e9; border-left: 4px solid #d13438; padding: 15px; margin: 15px 0; }}
        .button {{ display: inline-block; padding: 10px 14px; background: #0078d4; color: white; text-decoration: none; border-radius: 4px; margin-top: 12px; }}
        .footer {{ padding: 15px; font-size: 12px; color: #666; text-align: center; }}
        {extraStyles}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2 style='margin:0;'>{title}</h2>
            {(subtitle != null ? $"<p style='margin: 5px 0 0 0; opacity: 0.9;'>{subtitle}</p>" : "")}
        </div>
        <div class='content'>
            {contentHtml}
        </div>
        <div class='footer'>
            This is an automated message from the SAML Certificate Rotation Tool.
        </div>
    </div>
</body>
</html>";
    }

    private string GenerateCertificateActionEmail(SamlApplication app, SamlCertificate cert, bool isActivation)
    {
        var headerColor = isActivation ? "#107c10" : "#0078d4";
        var title = isActivation ? "✅ SAML Certificate Activated" : "🔐 New SAML Certificate Created";
        var headline = isActivation
            ? "A new SAML signing certificate has been activated for your application."
            : "A new SAML signing certificate has been created for your application.";
        var thumbLabel = isActivation ? "Activated Certificate Thumbprint" : "New Certificate Thumbprint";

        var content = $@"
            <div class='callout-green'>
                <strong>{H(headline)}</strong>
            </div>
            <div class='details'>
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>{thumbLabel}:</span> {H(cert.Thumbprint)}</p>
                {(!isActivation ? $"<p><span class='label'>Valid From:</span> {cert.StartDateTime:yyyy-MM-dd HH:mm} UTC</p>" : "")}
                <p><span class='label'>Valid Until:</span> {cert.EndDateTime:yyyy-MM-dd HH:mm} UTC</p>
            </div>
            {(isActivation ? @"
            <div class='callout-yellow'>
                <strong>⚠️ Action May Be Required:</strong><br/>
                If your SAML Service Provider does not automatically fetch metadata updates, you may need 
                to manually update the SP with the new certificate. Otherwise, SAML authentication may fail.
            </div>" : @"
            <p style='margin-top: 20px;'>
                <strong>Note:</strong> This certificate is NOT yet active. It will be automatically activated 
                closer to the expiration of the current certificate according to your policy settings.
            </p>")}";

        return EmailShell(headerColor, title, null, content);
    }

    private string GenerateErrorEmail(SamlApplication app, string errorMessage, string operation)
    {
        var content = $@"
            <div class='details'>
                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>
                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>
                <p><span class='label'>Operation:</span> {H(operation)}</p>
                <p><span class='label'>Time:</span> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>
            </div>
            <div class='callout-red' style='font-family: monospace; white-space: pre-wrap;'>{H(errorMessage)}</div>
            <p>Please investigate this error and take appropriate action.</p>";

        return EmailShell("#d13438", "❌ Certificate Operation Failed", null, content);
    }

    private string GenerateDailySummaryEmail(DashboardStats stats, List<RotationResult> results)
    {
        var successCount = results.Count(r => r.Success && SuccessActions.Contains(r.Action ?? string.Empty));
        var failureCount = results.Count(r => !r.Success);
        var skippedCount = Math.Max(0, results.Count - successCount - failureCount);

        var resultsHtml = string.Join("", results.Select(r =>
        {
            var isSuccess = r.Success && SuccessActions.Contains(r.Action ?? string.Empty);
            var color = !r.Success ? "#d13438" : isSuccess ? "#107c10" : "#797775";
            var label = !r.Success ? "✗ Failed" : isSuccess ? "✓ Success" : "↷ Skipped";
            return $@"
            <tr>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>{H(r.AppDisplayName)}</td>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>{H(r.Action)}</td>
                <td style='padding: 8px; border-bottom: 1px solid #eee;'>
                    <span style='color: {color}'>{label}</span>
                </td>
            </tr>";
        }));

        var extraStyles = @"
            .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }
            .stat-card { background: white; padding: 15px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-value { font-size: 28px; font-weight: bold; color: #0078d4; }
            .stat-label { font-size: 12px; color: #666; }
            table { width: 100%; border-collapse: collapse; background: white; }
            th { background: #f0f0f0; padding: 10px; text-align: left; }";

        var content = $@"
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
                    <div class='stat-value' style='color: #ffb900;'>{stats.AppsExpiringSoon}</div>
                    <div class='stat-label'>Expiring in {stats.ExpiringSoonThresholdDays} Days</div>
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
            </table>" : "<p>No rotation actions were performed today.</p>")}";

        return EmailShell("#0078d4", "📊 Daily SAML Certificate Rotation Summary", $"{DateTime.UtcNow:dddd, MMMM d, yyyy}", content, extraStyles, maxWidth: 700);
    }

    private string GenerateSponsorExpirationStatusEmail(SamlApplication app, SamlCertificate cert, int daysUntilExpiry, string appPortalUrl, string status, bool manualSend, string? milestoneLabel = null)
    {
        var isExpired = string.Equals(status, "Expired", StringComparison.OrdinalIgnoreCase);
        var isNotify = string.Equals(status, "Notify", StringComparison.OrdinalIgnoreCase);

        var headerColor = isExpired || isNotify ? "#d13438" : "#ffb900";
        var title = isExpired ? "⚠️ SAML Certificate Has Expired"
                  : isNotify  ? "⚠️ SAML Certificate Expiration Reminder"
                  : "⚠️ SAML Certificate Needs Attention";

        string introHtml;
        if (isNotify)
        {
            introHtml = $"<strong>This application is configured as Notify.</strong><br/>The current signing certificate expires in <strong>{daysUntilExpiry} day(s)</strong>.";
        }
        else if (isExpired)
        {
            introHtml = $"<strong>{H("The signing certificate for this SAML application has expired. Please remediate this as quickly as possible to avoid or resolve sign-in impact.")}</strong>";
        }
        else
        {
            introHtml = $"<strong>{H($"The signing certificate for this SAML application is in {status} state and requires attention.")}</strong>";
        }

        var dateText = cert.EndDateTime.ToString("yyyy-MM-dd HH:mm") + " UTC";
        var dateLabel = isExpired ? "Expired On" : "Expires On";

        var detailsBuilder = new System.Text.StringBuilder();
        if (isNotify && milestoneLabel != null)
        {
            detailsBuilder.AppendLine($"                <p><span class='label'>Reminder milestone:</span> {H(milestoneLabel)}</p>");
        }
        else if (!isNotify)
        {
            detailsBuilder.AppendLine($"                <p><span class='label'>Status:</span> {H(status)}</p>");
        }
        detailsBuilder.AppendLine($"                <p><span class='label'>Application:</span> {H(app.DisplayName)}</p>");
        detailsBuilder.AppendLine($"                <p><span class='label'>Service Principal Object ID:</span> {H(app.Id)}</p>");
        detailsBuilder.AppendLine($"                <p><span class='label'>App ID:</span> {H(app.AppId)}</p>");
        detailsBuilder.AppendLine($"                <p><span class='label'>Certificate Thumbprint:</span> {H(cert.Thumbprint)}</p>");
        detailsBuilder.AppendLine($"                <p><span class='label'>{dateLabel}:</span> {H(dateText)}</p>");
        if (!isNotify)
        {
            detailsBuilder.AppendLine($"                <p><span class='label'>Days Remaining:</span> {daysUntilExpiry}</p>");
            var modeText = manualSend ? "Manual resend requested from dashboard." : "Automatically generated notification.";
            detailsBuilder.AppendLine($"                <p><span class='label'>Notification:</span> {H(modeText)}</p>");
        }
        detailsBuilder.AppendLine($"                <a class='button' href='{H(appPortalUrl)}'>Open Enterprise Application</a>");

        var footerNote = isNotify
            ? "No automatic rotation will occur while Auto-Rotate is set to Notify."
            : "Please review and remediate this application promptly.";

        var noticeColor = isExpired || isNotify ? "#d13438" : "#ffb900";
        var content = $@"
            <div style='background: #fff4ce; border-left: 4px solid {noticeColor}; padding: 15px; margin: 15px 0;'>
                {introHtml}
            </div>
            <div class='details'>
{detailsBuilder}
            </div>
            <p style='margin-top:16px;'>{footerNote}</p>";

        return EmailShell(headerColor, title, null, content, maxWidth: 700);
    }

    /// <inheritdoc />
    public async Task SendConsolidatedSponsorNotificationsAsync(List<SponsorNotificationItem> pendingNotifications)
    {
        if (pendingNotifications == null || !pendingNotifications.Any())
        {
            return;
        }

        var enabled = await _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
        if (!enabled)
        {
            _logger.LogInformation("Sponsor notifications disabled — skipping consolidated emails");
            return;
        }

        // Build a map: sponsor email → list of notification items
        var sponsorGroups = new Dictionary<string, List<SponsorNotificationItem>>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in pendingNotifications)
        {
            var emails = ParseSponsorEmails(item.App.Sponsor);
            foreach (var email in emails)
            {
                if (!sponsorGroups.TryGetValue(email, out var list))
                {
                    list = new List<SponsorNotificationItem>();
                    sponsorGroups[email] = list;
                }
                list.Add(item);
            }
        }

        foreach (var (sponsorEmail, items) in sponsorGroups)
        {
            try
            {
                var subject = items.Count == 1
                    ? $"[SAML Cert Rotation] Certificate Action - {items[0].App.DisplayName}"
                    : $"[SAML Cert Rotation] Certificate Actions - {items.Count} Application(s)";

                var body = GenerateConsolidatedSponsorEmail(items);
                await _graphService.SendEmailAsync(new List<string> { sponsorEmail }, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send consolidated sponsor email to {Email}", sponsorEmail);
            }
        }
    }

    private string GenerateConsolidatedSponsorEmail(List<SponsorNotificationItem> items)
    {
        // Group items by category
        var groups = items
            .GroupBy(i => i.Category, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => GetCategorySortOrder(g.Key));

        var sectionsHtml = new System.Text.StringBuilder();

        foreach (var group in groups)
        {
            var (icon, headerColor, description) = GetCategoryMeta(group.Key);

            sectionsHtml.AppendLine($@"
            <div style='margin-bottom: 24px;'>
                <div style='background: {headerColor}; color: white; padding: 10px 15px; border-radius: 6px 6px 0 0;'>
                    <h3 style='margin:0;'>{icon} {H(group.Key)} ({group.Count()} app{(group.Count() != 1 ? "s" : "")})</h3>
                </div>
                <div style='background: white; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 6px 6px; padding: 0;'>
                    {(string.IsNullOrEmpty(description) ? "" : $"<p style='padding: 12px 15px 0 15px; margin: 0; color: #666;'>{H(description)}</p>")}
                    <table style='width: 100%; border-collapse: collapse;'>
                        <tr style='background: #f5f5f5;'>
                            <th style='text-align:left; padding: 10px 15px; font-size: 13px; color: #555;'>Application</th>
                            <th style='text-align:left; padding: 10px 15px; font-size: 13px; color: #555;'>Thumbprint</th>
                            <th style='text-align:left; padding: 10px 15px; font-size: 13px; color: #555;'>Valid Until</th>
                            <th style='text-align:left; padding: 10px 15px; font-size: 13px; color: #555;'>View in Entra ID</th>
                        </tr>");

            foreach (var item in group.OrderBy(i => i.App.DisplayName, StringComparer.OrdinalIgnoreCase))
            {
                var thumbprint = item.Certificate?.Thumbprint ?? "—";
                var validUntil = item.Certificate?.EndDateTime.ToString("yyyy-MM-dd") ?? "—";
                var entraUrl = Helpers.UrlHelper.BuildEntraManagedAppUrl(item.App.Id, item.App.AppId);

                sectionsHtml.AppendLine($@"
                        <tr>
                            <td style='padding: 10px 15px; border-top: 1px solid #eee;'>{H(item.App.DisplayName)}</td>
                            <td style='padding: 10px 15px; border-top: 1px solid #eee; font-family: monospace; font-size: 12px;'>{H(thumbprint)}</td>
                            <td style='padding: 10px 15px; border-top: 1px solid #eee;'>{H(validUntil)}</td>
                            <td style='padding: 10px 15px; border-top: 1px solid #eee;'><a href='{H(entraUrl)}' style='color: #0078d4;'>Open</a></td>
                        </tr>");
            }

            sectionsHtml.AppendLine(@"
                    </table>
                </div>
            </div>");
        }

        var content = $@"
            <p>The following certificate operations were performed on applications you sponsor:</p>
            {sectionsHtml}";

        return EmailShell("#0078d4", "🔐 SAML Certificate Rotation Summary", $"{DateTime.UtcNow:dddd, MMMM d, yyyy}", content, maxWidth: 750);
    }

    private static int GetCategorySortOrder(string category)
    {
        return category switch
        {
            "Certificate Created" => 1,
            "Certificate Created (Notify-App)" => 2,
            "Certificate Activated" => 3,
            _ => 99
        };
    }

    private static (string icon, string headerColor, string description) GetCategoryMeta(string category)
    {
        return category switch
        {
            "Certificate Created" => ("🆕", "#0078d4",
                "A new signing certificate has been created. It is not yet active and will be activated automatically closer to expiration."),
            "Certificate Created (Notify-App)" => ("🆕", "#0078d4",
                "A new signing certificate has been created for a notify-app. It will NOT be auto-activated."),
            "Certificate Activated" => ("✅", "#107c10",
                "A new signing certificate has been activated. If your SAML SP does not auto-fetch metadata, you may need to update it manually."),
            _ => ("ℹ️", "#797775", "")
        };
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
        "SponsorExpirationWarning",
        "ConsolidatedSponsor"
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
                body = GenerateCertificateActionEmail(sampleApp, newCert, isActivation: false);
                break;

            case "CertificateActivated":
                subject = $"[TEST] [SAML Cert Rotation] Certificate Activated - {sampleApp.DisplayName}";
                body = GenerateCertificateActionEmail(sampleApp, newCert, isActivation: true);
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
                    AppsExpiringSoon = 4,
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
                body = GenerateSponsorExpirationStatusEmail(sampleApp, activeCert, 25, appUrl, "Notify", manualSend: false, milestoneLabel: "30-day reminder");
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

            case "ConsolidatedSponsor":
                var sampleApp2 = new SamlApplication
                {
                    Id = "22222222-2222-2222-2222-222222222222",
                    AppId = "33333333-3333-3333-3333-333333333333",
                    DisplayName = "Fabrikam SAML App (Test)",
                    AutoRotateStatus = "on",
                    Sponsor = toEmail
                };
                var sampleApp3 = new SamlApplication
                {
                    Id = "44444444-4444-4444-4444-444444444444",
                    AppId = "55555555-5555-5555-5555-555555555555",
                    DisplayName = "Northwind SAML App (Test)",
                    AutoRotateStatus = "notify",
                    Sponsor = toEmail
                };
                var sampleItems = new List<SponsorNotificationItem>
                {
                    new SponsorNotificationItem { App = sampleApp, Category = "Certificate Created", Certificate = newCert },
                    new SponsorNotificationItem { App = sampleApp2, Category = "Certificate Created", Certificate = new SamlCertificate
                    {
                        Thumbprint = "AA11BB22CC33DD44EE55FF6677889900AABBCCDD",
                        StartDateTime = DateTime.UtcNow,
                        EndDateTime = DateTime.UtcNow.AddYears(3)
                    }},
                    new SponsorNotificationItem { App = sampleApp3, Category = "Certificate Created (Notify-App)", Certificate = new SamlCertificate
                    {
                        Thumbprint = "1122334455667788990011223344556677889900",
                        StartDateTime = DateTime.UtcNow,
                        EndDateTime = DateTime.UtcNow.AddYears(3)
                    }},
                    new SponsorNotificationItem { App = sampleApp, Category = "Certificate Activated", Certificate = newCert }
                };
                subject = $"[TEST] [SAML Cert Rotation] Certificate Actions - {sampleItems.Count} Application(s)";
                body = GenerateConsolidatedSponsorEmail(sampleItems);
                break;

            default:
                _logger.LogWarning("Unknown test email template: {Template}", templateName);
                return false;
        }

        return await _graphService.SendEmailAsync(new List<string> { toEmail }, subject, body);
    }
}
