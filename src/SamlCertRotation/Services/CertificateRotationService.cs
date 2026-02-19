using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Main orchestration service for certificate rotation
/// </summary>
public class CertificateRotationService : ICertificateRotationService
{
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
    public async Task<List<RotationResult>> RunRotationAsync(bool? forceReportOnlyMode = null)
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

            // Filter to apps with AutoRotate = "on"
            var appsToProcess = apps.Where(a => 
                string.Equals(a.AutoRotateStatus, "on", StringComparison.OrdinalIgnoreCase))
                .ToList();

            _logger.LogInformation("Processing {Count} applications with AutoRotate=on", appsToProcess.Count);

            foreach (var app in appsToProcess)
            {
                try
                {
                    var result = await ProcessApplicationAsync(app, reportOnlyMode);
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

            // Log completion
            var reportOnlyCreateCount = results.Count(r => string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase));
            var reportOnlyActivateCount = results.Count(r => string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase));

            var completionDescription = reportOnlyMode
                ? $"Report-only run completed. {appsToProcess.Count} apps evaluated. {reportOnlyCreateCount} apps would generate new cert. {reportOnlyActivateCount} apps would activate new cert. Success: {results.Count(r => r.Success)}, Failed: {results.Count(r => !r.Success)}"
                : $"Completed production rotation run. Processed {appsToProcess.Count} apps. Success: {results.Count(r => r.Success)}, Failed: {results.Count(r => !r.Success)}";

            await _auditService.LogSuccessAsync(
                "SYSTEM",
                "System",
                reportOnlyMode ? AuditActionType.ScanCompletedReportOnly : AuditActionType.ScanCompleted,
                completionDescription);

            // Send daily summary
            var stats = await GetDashboardStatsAsync();
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
        var result = new RotationResult
        {
            ServicePrincipalId = app.Id,
            AppDisplayName = app.DisplayName,
            Success = true,
            Action = "None"
        };

        try
        {
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
                            activeCert.Thumbprint);
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
                                newCert.Thumbprint);

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
                                $"Report-only mode: would activate pending certificate {newerInactiveCert.Thumbprint}.",
                                activeCert.Thumbprint,
                                newerInactiveCert.Thumbprint);
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
                                    $"Activated certificate {newerInactiveCert.Thumbprint}",
                                    activeCert.Thumbprint,
                                    newerInactiveCert.Thumbprint);

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
                            $"Report-only mode: would activate pending certificate {pendingCert.Thumbprint}.",
                            activeCert.Thumbprint,
                            pendingCert.Thumbprint);
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
                                $"Activated certificate {pendingCert.Thumbprint}",
                                activeCert.Thumbprint,
                                pendingCert.Thumbprint);

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
                ex.Message);

            await _notificationService.SendErrorNotificationAsync(app, ex.Message, "Rotation");
        }

        return result;
    }

    /// <inheritdoc />
    public async Task<DashboardStats> GetDashboardStatsAsync()
    {
        var stats = new DashboardStats();

        try
        {
            var apps = await _graphService.GetSamlApplicationsAsync();
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
                    else if (daysUntilExpiry <= 30)
                        stats.AppsExpiringIn30Days++;
                    else if (daysUntilExpiry <= 60)
                        stats.AppsExpiringIn60Days++;
                    else if (daysUntilExpiry <= 90)
                        stats.AppsExpiringIn90Days++;

                    // Add to summary list
                    stats.Apps.Add(new SamlAppSummary
                    {
                        Id = app.Id,
                        DisplayName = app.DisplayName,
                        AutoRotateStatus = app.AutoRotateStatus,
                        CertExpiryDate = activeCert.EndDateTime,
                        DaysUntilExpiry = daysUntilExpiry,
                        ExpiryCategory = GetExpiryCategory(daysUntilExpiry)
                    });
                }
                else
                {
                    stats.Apps.Add(new SamlAppSummary
                    {
                        Id = app.Id,
                        DisplayName = app.DisplayName,
                        AutoRotateStatus = app.AutoRotateStatus,
                        ExpiryCategory = "Unknown"
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
}
