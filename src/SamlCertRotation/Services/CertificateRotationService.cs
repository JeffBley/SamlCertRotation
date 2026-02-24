using Microsoft.Extensions.Logging;
using SamlCertRotation.Helpers;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Main orchestration service for certificate rotation
/// </summary>
public class CertificateRotationService : ICertificateRotationService
{
    private const string AutoRotateOn = "on";
    private const string AutoRotateNotify = "notify";

    private readonly IGraphService _graphService;
    private readonly IPolicyService _policyService;
    private readonly INotificationService _notificationService;
    private readonly IAuditService _auditService;
    private readonly ILogger<CertificateRotationService> _logger;

    public CertificateRotationService(
        IGraphService graphService,
        IPolicyService policyService,
        INotificationService notificationService,
        IAuditService auditService,
        ILogger<CertificateRotationService> logger)
    {
        _graphService = graphService;
        _policyService = policyService;
        _notificationService = notificationService;
        _auditService = auditService;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<List<RotationResult>> RunRotationAsync(bool? forceReportOnlyMode = null, string? performedBy = null)
    {
        var results = new List<RotationResult>();

        try
        {
            _logger.LogInformation("Starting certificate rotation run at {Time}", DateTime.UtcNow);
            var reportOnlyMode = forceReportOnlyMode ?? await _policyService.GetReportOnlyModeEnabledAsync();
            _logger.LogInformation("Rotation run mode: {Mode}", reportOnlyMode ? "ReportOnly" : "Production");

            // Get all SAML applications
            var apps = await _graphService.GetSamlApplicationsAsync();
            _logger.LogInformation("Found {Count} SAML applications", apps.Count);

            // Filter to apps with AutoRotate = "on" or "notify"
            var appsToProcess = apps.Where(a =>
            {
                var mode = a.AutoRotateStatus?.Trim().ToLowerInvariant();
                return mode == AutoRotateOn || mode == AutoRotateNotify;
            })
                .ToList();

            _logger.LogInformation("Processing {Count} applications with AutoRotate=on", appsToProcess.Count);

            // Pre-fetch audit entries for all apps that will need milestone checks.
            // This replaces N individual audit queries with a single bulk query.
            var appIdsNeedingAudit = apps
                .Where(a =>
                {
                    var mode = a.AutoRotateStatus?.Trim().ToLowerInvariant();
                    return mode == AutoRotateOn || mode == AutoRotateNotify || mode == "off" || mode == null;
                })
                .Select(a => a.Id)
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .ToList();
            var auditCache = await _auditService.GetRecentEntriesForAppsAsync(appIdsNeedingAudit);

            foreach (var app in appsToProcess)
            {
                try
                {
                    var result = await ProcessApplicationAsync(app, reportOnlyMode, auditCache, performedBy);
                    results.Add(result);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing app {AppName}", app.DisplayName);
                    results.Add(new RotationResult
                    {
                        ServicePrincipalId = app.Id,
                        AppDisplayName = app.DisplayName,
                        Success = false,
                        Action = "Error",
                        ErrorMessage = ex.Message
                    });
                }
            }

            if (!reportOnlyMode)
            {
                await SendAutomaticExpirationNotificationsAsync(apps, auditCache);
            }

            // Log completion
            var reportOnlyCreateCount = results.Count(r => 
                string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Create (Notify)", StringComparison.OrdinalIgnoreCase));
            var reportOnlyActivateCount = results.Count(r => string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase));
            var successCount = results.Count(r =>
                r.Success && (
                    string.Equals(r.Action, "Created", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Created (Notify)", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Activated", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Notified", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Would Create (Notify)", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Action, "Would Notify", StringComparison.OrdinalIgnoreCase)));
            var failedCount = results.Count(r => !r.Success);
            var skippedCount = Math.Max(0, results.Count - successCount - failedCount);

            var completionDescription = reportOnlyMode
                ? $"Report-only run completed. {appsToProcess.Count} apps evaluated. {reportOnlyCreateCount} apps would generate new cert. {reportOnlyActivateCount} apps would activate new cert. Success: {successCount}, Skipped: {skippedCount}, Failed: {failedCount}"
                : $"Completed production rotation run. Processed {appsToProcess.Count} apps. Success: {successCount}, Skipped: {skippedCount}, Failed: {failedCount}";

            await _auditService.LogSuccessAsync(
                "SYSTEM",
                "System",
                reportOnlyMode ? AuditActionType.ScanCompletedReportOnly : AuditActionType.ScanCompleted,
                completionDescription,
                performedBy: performedBy);

            // Send daily summary — reuse the apps list we already fetched to avoid another Graph round-trip
            var stats = await GetDashboardStatsAsync(apps);
            await _notificationService.SendDailySummaryAsync(stats, results);

            _logger.LogInformation("Certificate rotation run completed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during certificate rotation run");
            throw;
        }

        return results;
    }

    /// <inheritdoc />
    public async Task<RotationResult> ProcessApplicationAsync(SamlApplication app, bool reportOnlyMode = false)
    {
        return await ProcessApplicationAsync(app, reportOnlyMode, null);
    }

    private async Task<RotationResult> ProcessApplicationAsync(SamlApplication app, bool reportOnlyMode, Dictionary<string, List<AuditEntry>>? auditCache, string? performedBy = null)
    {
        var result = new RotationResult
        {
            ServicePrincipalId = app.Id,
            AppDisplayName = app.DisplayName,
            Success = true,
            Action = "None"
        };

        try
        {
            var autoRotateMode = app.AutoRotateStatus?.Trim().ToLowerInvariant();

            // Get effective policy for this app
            var policy = await _policyService.GetEffectivePolicyAsync(app.Id);

            // Find the active certificate
            var activeCert = app.Certificates.FirstOrDefault(c => c.IsActive);
            if (activeCert == null)
            {
                _logger.LogWarning("No active certificate found for {AppName}", app.DisplayName);
                result.Action = "None - No active certificate";
                return result;
            }

            var daysUntilExpiry = activeCert.DaysUntilExpiry;
            _logger.LogInformation("App {AppName}: Active cert expires in {Days} days", 
                app.DisplayName, daysUntilExpiry);

            if (autoRotateMode == AutoRotateNotify)
            {
                var sponsorReminderDays = await _policyService.GetSponsorReminderDaysAsync();
                var sponsorReminderCount = await _policyService.GetSponsorReminderCountAsync();
                var notifyMilestone = GetNotifyMilestoneToSend(app, activeCert, daysUntilExpiry, sponsorReminderDays, sponsorReminderCount, auditCache);
                if (notifyMilestone != null)
                {
                    var appUrl = UrlHelper.BuildEntraManagedAppUrl(app.Id, app.AppId);

                    if (reportOnlyMode)
                    {
                        result.Action = "Would Notify";
                        await _auditService.LogSuccessAsync(
                            app.Id,
                            app.DisplayName,
                            AuditActionType.CertificateExpiringSoon,
                            $"Report-only mode: would send notify reminder. Milestone: {notifyMilestone}. Days remaining: {daysUntilExpiry}. Link: {appUrl}",
                            activeCert.Thumbprint,
                            performedBy: performedBy);
                    }
                    else
                    {
                        var sent = await _notificationService.SendNotifyOnlyReminderAsync(app, activeCert, daysUntilExpiry, appUrl, notifyMilestone);

                        if (sent)
                        {
                            result.Action = "Notified";
                            await _auditService.LogSuccessAsync(
                                app.Id,
                                app.DisplayName,
                                AuditActionType.CertificateExpiringSoon,
                                $"Notify reminder sent. Milestone: {notifyMilestone}. Days remaining: {daysUntilExpiry}. Link: {appUrl}",
                                activeCert.Thumbprint,
                                performedBy: performedBy);
                        }
                    }
                }

                // Optionally auto-create (but never activate) certs for notify-only apps
                var createCertsForNotify = await ResolveCreateCertsForNotifyAsync(app.Id);
                if (createCertsForNotify && daysUntilExpiry <= policy.CreateCertDaysBeforeExpiry)
                {
                    var newerInactiveCert = app.Certificates
                        .Where(c => !c.IsActive && c.EndDateTime > activeCert.EndDateTime)
                        .OrderByDescending(c => c.EndDateTime)
                        .FirstOrDefault();

                    if (newerInactiveCert == null)
                    {
                        if (reportOnlyMode)
                        {
                            result.Action = "Would Create (Notify)";
                            await _auditService.LogSuccessAsync(
                                app.Id,
                                app.DisplayName,
                                AuditActionType.CertificateCreatedReportOnly,
                                $"Report-only mode: would create a new certificate for notify-only app. Active cert expires in {daysUntilExpiry} day(s).",
                                activeCert.Thumbprint,
                                performedBy: performedBy);
                        }
                        else
                        {
                            _logger.LogInformation("Creating new certificate for notify-only app {AppName}", app.DisplayName);
                            var newCert = await _graphService.CreateSamlCertificateAsync(app.Id);
                            if (newCert != null)
                            {
                                result.Action = "Created (Notify)";
                                result.NewCertificateThumbprint = newCert.Thumbprint;
                                await _auditService.LogSuccessAsync(
                                    app.Id,
                                    app.DisplayName,
                                    AuditActionType.CertificateCreated,
                                    $"Created new certificate for notify-only app, expiring {newCert.EndDateTime:yyyy-MM-dd}. Certificate will NOT be auto-activated.",
                                    activeCert.Thumbprint,
                                    newCert.Thumbprint,
                                    performedBy);
                                await _notificationService.SendCertificateCreatedNotificationAsync(app, newCert);
                            }
                            else
                            {
                                result.Success = false;
                                result.Action = "Create Failed";
                                result.ErrorMessage = "Certificate creation returned null";
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(result.Action)) result.Action = "None";
                return result;
            }

            if (autoRotateMode != AutoRotateOn)
            {
                result.Action = "None";
                return result;
            }

            // Check if we need to CREATE a new certificate
            if (daysUntilExpiry <= policy.CreateCertDaysBeforeExpiry)
            {
                // Check if there's already an inactive cert that's newer
                var newerInactiveCert = app.Certificates
                    .Where(c => !c.IsActive && c.EndDateTime > activeCert.EndDateTime)
                    .OrderByDescending(c => c.EndDateTime)
                    .FirstOrDefault();

                if (newerInactiveCert == null)
                {
                    if (reportOnlyMode)
                    {
                        result.Action = "Would Create";
                        await _auditService.LogSuccessAsync(
                            app.Id, 
                            app.DisplayName, 
                            AuditActionType.CertificateCreatedReportOnly,
                            $"Report-only mode: would create a new certificate. Active cert expires in {daysUntilExpiry} day(s).",
                            activeCert.Thumbprint,
                            performedBy: performedBy);
                    }
                    else
                    {
                        _logger.LogInformation("Creating new certificate for {AppName}", app.DisplayName);
                        
                        var newCert = await _graphService.CreateSamlCertificateAsync(app.Id);
                        
                        if (newCert != null)
                        {
                            result.Action = "Created";
                            result.NewCertificateThumbprint = newCert.Thumbprint;

                            await _auditService.LogSuccessAsync(
                                app.Id, 
                                app.DisplayName, 
                                AuditActionType.CertificateCreated,
                                $"Created new certificate expiring {newCert.EndDateTime:yyyy-MM-dd}",
                                activeCert.Thumbprint,
                                newCert.Thumbprint,
                                performedBy);

                            await _notificationService.SendCertificateCreatedNotificationAsync(app, newCert);
                        }
                        else
                        {
                            result.Success = false;
                            result.Action = "Create Failed";
                            result.ErrorMessage = "Certificate creation returned null";
                        }
                    }
                }
                else
                {
                    _logger.LogInformation("App {AppName} already has a pending certificate", app.DisplayName);
                    
                    // Check if we should ACTIVATE the pending cert
                    if (daysUntilExpiry <= policy.ActivateCertDaysBeforeExpiry)
                    {
                        if (reportOnlyMode)
                        {
                            result.Action = "Would Activate";

                            await _auditService.LogSuccessAsync(
                                app.Id,
                                app.DisplayName,
                                AuditActionType.CertificateActivatedReportOnly,
                                $"Report-only mode: would activate pending certificate {newerInactiveCert.Thumbprint} (expires {newerInactiveCert.EndDateTime:yyyy-MM-dd}).",
                                activeCert.Thumbprint,
                                newerInactiveCert.Thumbprint,
                                performedBy);
                        }
                        else
                        {
                            _logger.LogInformation("Activating certificate for {AppName}", app.DisplayName);
                            
                            var activated = await _graphService.ActivateCertificateAsync(app.Id, newerInactiveCert.Thumbprint);
                            
                            if (activated)
                            {
                                result.Action = "Activated";
                                result.NewCertificateThumbprint = newerInactiveCert.Thumbprint;

                                await _auditService.LogSuccessAsync(
                                    app.Id,
                                    app.DisplayName,
                                    AuditActionType.CertificateActivated,
                                    $"Activated certificate {newerInactiveCert.Thumbprint} (expires {newerInactiveCert.EndDateTime:yyyy-MM-dd})",
                                    activeCert.Thumbprint,
                                    newerInactiveCert.Thumbprint,
                                    performedBy);

                                await _notificationService.SendCertificateActivatedNotificationAsync(app, newerInactiveCert);
                            }
                            else
                            {
                                result.Success = false;
                                result.Action = "Activate Failed";
                                result.ErrorMessage = "Certificate activation failed";

                                await _notificationService.SendErrorNotificationAsync(app, "Certificate activation failed", "Activate");
                            }
                        }
                    }
                }
            }
            // Check if we should activate (in case create threshold wasn't reached but activate is)
            else if (daysUntilExpiry <= policy.ActivateCertDaysBeforeExpiry)
            {
                var pendingCert = app.Certificates
                    .Where(c => !c.IsActive && c.EndDateTime > activeCert.EndDateTime)
                    .OrderByDescending(c => c.EndDateTime)
                    .FirstOrDefault();

                if (pendingCert != null)
                {
                    if (reportOnlyMode)
                    {
                        result.Action = "Would Activate";

                        await _auditService.LogSuccessAsync(
                            app.Id,
                            app.DisplayName,
                            AuditActionType.CertificateActivatedReportOnly,
                            $"Report-only mode: would activate pending certificate {pendingCert.Thumbprint} (expires {pendingCert.EndDateTime:yyyy-MM-dd}).",
                            activeCert.Thumbprint,
                            pendingCert.Thumbprint,
                            performedBy);
                    }
                    else
                    {
                        _logger.LogInformation("Activating pending certificate for {AppName}", app.DisplayName);
                        
                        var activated = await _graphService.ActivateCertificateAsync(app.Id, pendingCert.Thumbprint);
                        
                        if (activated)
                        {
                            result.Action = "Activated";
                            result.NewCertificateThumbprint = pendingCert.Thumbprint;

                            await _auditService.LogSuccessAsync(
                                app.Id,
                                app.DisplayName,
                                AuditActionType.CertificateActivated,
                                $"Activated certificate {pendingCert.Thumbprint} (expires {pendingCert.EndDateTime:yyyy-MM-dd})",
                                activeCert.Thumbprint,
                                pendingCert.Thumbprint,
                                performedBy);

                            await _notificationService.SendCertificateActivatedNotificationAsync(app, pendingCert);
                        }
                        else
                        {
                            result.Success = false;
                            result.Action = "Activate Failed";
                            result.ErrorMessage = "Certificate activation failed";
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing {AppName}", app.DisplayName);
            result.Success = false;
            result.Action = "Error";
            result.ErrorMessage = ex.Message;

            await _auditService.LogFailureAsync(
                app.Id,
                app.DisplayName,
                AuditActionType.Error,
                "Error during certificate rotation",
                ex.Message,
                performedBy);

            if (!reportOnlyMode)
            {
                await _notificationService.SendErrorNotificationAsync(app, ex.Message, "Rotation");
            }
        }

        return result;
    }

    private async Task SendAutomaticExpirationNotificationsAsync(List<SamlApplication> apps, Dictionary<string, List<AuditEntry>>? auditCache)
    {
        var notifyOnExpirationEnabled = await _policyService.GetNotifySponsorsOnExpirationEnabledAsync();
        if (!notifyOnExpirationEnabled)
        {
            return;
        }

        // Only process apps with AutoRotate = "on" or "notify"
        var eligibleApps = apps.Where(a =>
        {
            var mode = a.AutoRotateStatus?.Trim().ToLowerInvariant();
            return mode == AutoRotateOn || mode == AutoRotateNotify;
        }).ToList();

        foreach (var app in eligibleApps)
        {
            try
            {
                var activeCert = app.Certificates.FirstOrDefault(c => c.IsActive);
                if (activeCert == null)
                {
                    continue;
                }

                // Only notify when the certificate has actually expired
                if (activeCert.DaysUntilExpiry >= 0)
                {
                    continue;
                }

                var status = "Expired";
                var milestoneLabel = $"Expiration-{status}";
                var alreadySent = HasExpirationMilestoneBeenSent(GetCachedEntries(app.Id, auditCache), activeCert.Thumbprint, milestoneLabel);
                if (alreadySent)
                {
                    continue;
                }

                var appUrl = UrlHelper.BuildEntraManagedAppUrl(app.Id, app.AppId);
                var sent = await _notificationService.SendSponsorExpirationStatusNotificationAsync(
                    app,
                    activeCert,
                    activeCert.DaysUntilExpiry,
                    appUrl,
                    status,
                    false);

                if (!sent)
                {
                    continue;
                }

                await _auditService.LogSuccessAsync(
                    app.Id,
                    app.DisplayName,
                    AuditActionType.SponsorExpirationReminderSent,
                    $"Automatic expiration reminder sent. Milestone: {milestoneLabel}. Status: {status}. Days remaining: {activeCert.DaysUntilExpiry}. Link: {appUrl}",
                    activeCert.Thumbprint);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error sending automatic expiration reminder for app {AppName}", app.DisplayName);
            }
        }
    }

    /// <inheritdoc />
    public async Task<DashboardStats> GetDashboardStatsAsync()
    {
        var apps = await _graphService.GetSamlApplicationsAsync();
        return await GetDashboardStatsAsync(apps);
    }

    /// <inheritdoc />
    public async Task<DashboardStats> GetDashboardStatsAsync(List<SamlApplication> apps)
    {
        var stats = new DashboardStats();

        try
        {
            var globalPolicy = await _policyService.GetGlobalPolicyAsync();
            var expiringSoonThresholdDays = Math.Max(1, globalPolicy.CreateCertDaysBeforeExpiry);
            stats.ExpiringSoonThresholdDays = expiringSoonThresholdDays;

            // Fetch all app-specific policies in one call
            var appPolicies = await _policyService.ListAppPoliciesAsync();
            var appPolicyLookup = appPolicies.ToDictionary(p => p.RowKey, p => p, StringComparer.OrdinalIgnoreCase);

            stats.TotalSamlApps = apps.Count;

            foreach (var app in apps)
            {
                // Count by auto-rotate status
                switch (app.AutoRotateStatus?.ToLowerInvariant())
                {
                    case "on":
                        stats.AppsWithAutoRotateOn++;
                        break;
                    case "off":
                        stats.AppsWithAutoRotateOff++;
                        break;
                    case "notify":
                        stats.AppsWithAutoRotateNotify++;
                        break;
                    default:
                        stats.AppsWithAutoRotateNull++;
                        break;
                }

                // Find active certificate for expiry stats
                var activeCert = app.Certificates.FirstOrDefault(c => c.IsActive);
                if (activeCert != null)
                {
                    var daysUntilExpiry = activeCert.DaysUntilExpiry;

                    if (daysUntilExpiry < 0)
                        stats.AppsWithExpiredCerts++;
                    else if (daysUntilExpiry <= expiringSoonThresholdDays)
                        stats.AppsExpiringIn30Days++;
                    else if (daysUntilExpiry <= 60)
                        stats.AppsExpiringIn60Days++;
                    else if (daysUntilExpiry <= 90)
                        stats.AppsExpiringIn90Days++;

                    // Add to summary list
                    var hasAppPolicy1 = appPolicyLookup.TryGetValue(app.Id, out var appPolicy1);
                    stats.Apps.Add(new SamlAppSummary
                    {
                        Id = app.Id,
                        AppId = app.AppId,
                        DisplayName = app.DisplayName,
                        Sponsor = app.Sponsor,
                        AutoRotateStatus = app.AutoRotateStatus,
                        CertExpiryDate = activeCert.EndDateTime,
                        DaysUntilExpiry = daysUntilExpiry,
                        ExpiryCategory = GetExpiryCategory(daysUntilExpiry),
                        PolicyType = hasAppPolicy1 ? "App-Specific" : "Global",
                        CreateCertDaysBeforeExpiry = (hasAppPolicy1 ? appPolicy1!.CreateCertDaysBeforeExpiry : null) ?? globalPolicy.CreateCertDaysBeforeExpiry,
                        ActivateCertDaysBeforeExpiry = (hasAppPolicy1 ? appPolicy1!.ActivateCertDaysBeforeExpiry : null) ?? globalPolicy.ActivateCertDaysBeforeExpiry
                    });
                }
                else
                {
                    var hasAppPolicy2 = appPolicyLookup.TryGetValue(app.Id, out var appPolicy2);
                    stats.Apps.Add(new SamlAppSummary
                    {
                        Id = app.Id,
                        AppId = app.AppId,
                        DisplayName = app.DisplayName,
                        Sponsor = app.Sponsor,
                        AutoRotateStatus = app.AutoRotateStatus,
                        ExpiryCategory = "Unknown",
                        PolicyType = hasAppPolicy2 ? "App-Specific" : "Global",
                        CreateCertDaysBeforeExpiry = (hasAppPolicy2 ? appPolicy2!.CreateCertDaysBeforeExpiry : null) ?? globalPolicy.CreateCertDaysBeforeExpiry,
                        ActivateCertDaysBeforeExpiry = (hasAppPolicy2 ? appPolicy2!.ActivateCertDaysBeforeExpiry : null) ?? globalPolicy.ActivateCertDaysBeforeExpiry
                    });
                }
            }

            stats.Apps = stats.Apps.OrderBy(a => a.DaysUntilExpiry ?? int.MaxValue).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting dashboard stats");
        }

        return stats;
    }

    private static string GetExpiryCategory(int daysUntilExpiry)
    {
        if (daysUntilExpiry < 0) return "Expired";
        if (daysUntilExpiry <= 30) return "Critical";
        if (daysUntilExpiry <= 60) return "Warning";
        if (daysUntilExpiry <= 90) return "Attention";
        return "OK";
    }

    private static string? GetNotifyMilestoneToSend(
        SamlApplication app,
        SamlCertificate activeCert,
        int daysUntilExpiry,
        (int firstReminderDays, int secondReminderDays, int thirdReminderDays) sponsorReminderDays,
        int sponsorReminderCount,
        Dictionary<string, List<AuditEntry>>? auditCache)
    {
        if (daysUntilExpiry < 0)
        {
            return null;
        }

        var milestones = new List<(string Label, int TriggerDays)>
        {
            ($"1st-{sponsorReminderDays.firstReminderDays}", sponsorReminderDays.firstReminderDays),
            ($"2nd-{sponsorReminderDays.secondReminderDays}", sponsorReminderDays.secondReminderDays),
            ($"3rd-{sponsorReminderDays.thirdReminderDays}", sponsorReminderDays.thirdReminderDays)
        };

        // Limit milestones based on the configured reminder count
        milestones = milestones.Take(sponsorReminderCount).ToList();

        var entries = GetCachedEntries(app.Id, auditCache);

        foreach (var milestone in milestones.OrderBy(m => m.TriggerDays))
        {
            if (daysUntilExpiry > milestone.TriggerDays)
            {
                continue;
            }

            var alreadySent = HasNotifyMilestoneBeenSent(entries, activeCert.Thumbprint, milestone.Label);
            if (!alreadySent)
            {
                return milestone.Label;
            }
        }

        return null;
    }

    /// <summary>
    /// Returns cached audit entries synchronously — returns empty list if not found in cache.
    /// Used by methods that already have a cache and don't need individual query fallback.
    /// </summary>
    private static List<AuditEntry> GetCachedEntries(string servicePrincipalId, Dictionary<string, List<AuditEntry>>? auditCache)
    {
        if (auditCache != null && auditCache.TryGetValue(servicePrincipalId, out var cached))
        {
            return cached;
        }
        return new List<AuditEntry>();
    }

    private static bool HasNotifyMilestoneBeenSent(List<AuditEntry> entries, string activeThumbprint, string milestoneLabel)
    {
        return entries.Any(entry =>
            entry.IsSuccess &&
            string.Equals(entry.ActionType, AuditActionType.CertificateExpiringSoon, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(entry.CertificateThumbprint, activeThumbprint, StringComparison.OrdinalIgnoreCase) &&
            (entry.Description?.Contains($"Milestone: {milestoneLabel}", StringComparison.OrdinalIgnoreCase) ?? false));
    }

    private static bool HasExpirationMilestoneBeenSent(List<AuditEntry> entries, string activeThumbprint, string milestoneLabel)
    {
        return entries.Any(entry =>
            entry.IsSuccess &&
            string.Equals(entry.ActionType, AuditActionType.SponsorExpirationReminderSent, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(entry.CertificateThumbprint, activeThumbprint, StringComparison.OrdinalIgnoreCase) &&
            (entry.Description?.Contains($"Milestone: {milestoneLabel}", StringComparison.OrdinalIgnoreCase) ?? false));
    }

    /// <summary>
    /// Resolve whether cert creation is enabled for a notify-only app,
    /// considering the app-specific override and the global setting.
    /// </summary>
    private async Task<bool> ResolveCreateCertsForNotifyAsync(string servicePrincipalId)
    {
        var appPolicy = await _policyService.GetAppPolicyAsync(servicePrincipalId);
        if (appPolicy?.CreateCertsForNotifyOverride != null)
        {
            return appPolicy.CreateCertsForNotifyOverride.Value;
        }
        return await _policyService.GetCreateCertsForNotifyAppsEnabledAsync();
    }

}
