using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using HttpRequestData = Microsoft.Azure.Functions.Worker.Http.HttpRequestData;
using HttpResponseData = Microsoft.Azure.Functions.Worker.Http.HttpResponseData;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// HTTP-triggered functions for the dashboard API
/// </summary>
public class DashboardFunctions
{
    private readonly ICertificateRotationService _rotationService;
    private readonly IGraphService _graphService;
    private readonly IPolicyService _policyService;
    private readonly IAuditService _auditService;
    private readonly INotificationService _notificationService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DashboardFunctions> _logger;
    private readonly string? _tenantId;
    private readonly HashSet<string> _allowedAudiences;
    private readonly HashSet<string> _trustedSwaIssuers;
    private readonly IConfigurationManager<OpenIdConnectConfiguration>? _oidcConfigurationManager;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public DashboardFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IConfiguration configuration,
        ILogger<DashboardFunctions> logger)
    {
        _rotationService = rotationService;
        _graphService = graphService;
        _policyService = policyService;
        _auditService = auditService;
        _notificationService = notificationService;
        _configuration = configuration;
        _logger = logger;

        _tenantId = _configuration["TenantId"];
        _allowedAudiences = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddAudienceIfPresent(_allowedAudiences, _configuration["SWA_AAD_CLIENT_ID"]);
        AddAudienceIfPresent(_allowedAudiences, _configuration["AAD_CLIENT_ID"]);

        var configuredAudiences = _configuration["SWA_ALLOWED_AUDIENCES"];
        if (!string.IsNullOrWhiteSpace(configuredAudiences))
        {
            foreach (var audience in configuredAudiences.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                AddAudienceIfPresent(_allowedAudiences, audience);
            }
        }

        // Build set of trusted SWA issuers for SWA-issued token path
        _trustedSwaIssuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var swaHostname = _configuration["SWA_HOSTNAME"];
        if (!string.IsNullOrWhiteSpace(swaHostname))
        {
            _trustedSwaIssuers.Add($"https://{swaHostname.TrimEnd('/')}/.auth");
        }
        // Also auto-trust the default SWA domain pattern
        var swaDefaultHostname = _configuration["SWA_DEFAULT_HOSTNAME"];
        if (!string.IsNullOrWhiteSpace(swaDefaultHostname))
        {
            _trustedSwaIssuers.Add($"https://{swaDefaultHostname.TrimEnd('/')}/.auth");
        }

        if (!string.IsNullOrWhiteSpace(_tenantId))
        {
            var metadataAddress = $"https://login.microsoftonline.com/{_tenantId}/v2.0/.well-known/openid-configuration";
            _oidcConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
        }
    }

    /// <summary>
    /// Get dashboard statistics.
    /// Supports optional server-side pagination via ?page=1&amp;pageSize=50 query parameters.
    /// When omitted, all apps are returned (backward compatible).
    /// </summary>
    [Function("GetDashboardStats")]
    public async Task<HttpResponseData> GetDashboardStats(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "dashboard/stats")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting dashboard stats");

        try
        {
            var stats = await _rotationService.GetDashboardStatsAsync();

            // Support optional server-side pagination for the apps list
            var queryParams = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
            if (int.TryParse(queryParams["page"], out var page) && int.TryParse(queryParams["pageSize"], out var pageSize))
            {
                page = Math.Max(1, page);
                pageSize = Math.Clamp(pageSize, 1, 500);
                var totalApps = stats.Apps.Count;
                var totalPages = (int)Math.Ceiling((double)totalApps / pageSize);

                stats.Apps = stats.Apps
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToList();

                return await CreateJsonResponse(req, new
                {
                    stats.TotalSamlApps,
                    stats.AppsWithAutoRotateOn,
                    stats.AppsWithAutoRotateOff,
                    stats.AppsWithAutoRotateNull,
                    stats.AppsExpiringIn30Days,
                    stats.ExpiringSoonThresholdDays,
                    stats.AppsExpiringIn60Days,
                    stats.AppsExpiringIn90Days,
                    stats.AppsWithExpiredCerts,
                    stats.GeneratedAt,
                    apps = stats.Apps,
                    pagination = new { page, pageSize, totalApps, totalPages }
                });
            }

            return await CreateJsonResponse(req, stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting dashboard stats");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get all SAML applications
    /// </summary>
    [Function("GetApplications")]
    public async Task<HttpResponseData> GetApplications(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "applications")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting all SAML applications");

        try
        {
            var apps = await _graphService.GetSamlApplicationsAsync();
            return await CreateJsonResponse(req, apps);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting applications");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get a specific application
    /// </summary>
    [Function("GetApplication")]
    public async Task<HttpResponseData> GetApplication(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "applications/{id}")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting application {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                var notFound = req.CreateResponse(HttpStatusCode.NotFound);
                return notFound;
            }
            return await CreateJsonResponse(req, app);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting application {Id}", id);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get global policy
    /// </summary>
    [Function("GetGlobalPolicy")]
    public async Task<HttpResponseData> GetGlobalPolicy(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting global policy");

        try
        {
            var policy = await _policyService.GetGlobalPolicyAsync();
            return await CreateJsonResponse(req, policy);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting global policy");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Update global policy
    /// </summary>
    [Function("UpdateGlobalPolicy")]
    public async Task<HttpResponseData> UpdateGlobalPolicy(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "policy")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Updating global policy");

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrEmpty(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var policy = JsonSerializer.Deserialize<RotationPolicy>(body, JsonOptions);
            if (policy == null)
            {
                return await CreateErrorResponse(req, "Invalid policy format", HttpStatusCode.BadRequest);
            }

            var success = await _policyService.UpdateGlobalPolicyAsync(policy);
            if (success)
            {
                return await CreateJsonResponse(req, new { message = "Policy updated successfully" });
            }
            else
            {
                return await CreateErrorResponse(req, "Failed to update policy");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating global policy");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get app-specific policy
    /// </summary>
    [Function("GetAppPolicy")]
    public async Task<HttpResponseData> GetAppPolicy(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy/app/{id}")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting app policy for {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var policy = await _policyService.GetAppPolicyAsync(id);
            if (policy == null)
            {
                // Return global policy as effective policy
                var globalPolicy = await _policyService.GetGlobalPolicyAsync();
                return await CreateJsonResponse(req, new
                {
                    isAppSpecific = false,
                    policy = globalPolicy
                });
            }
            return await CreateJsonResponse(req, new
            {
                isAppSpecific = true,
                policy = policy
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting app policy");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Update app-specific policy
    /// </summary>
    [Function("UpdateAppPolicy")]
    public async Task<HttpResponseData> UpdateAppPolicy(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "policy/app/{id}")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Updating app policy for {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrEmpty(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var policy = JsonSerializer.Deserialize<AppPolicy>(body, JsonOptions);
            if (policy == null)
            {
                return await CreateErrorResponse(req, "Invalid policy format", HttpStatusCode.BadRequest);
            }

            policy.RowKey = id;
            var success = await _policyService.UpsertAppPolicyAsync(policy);
            
            if (success)
            {
                return await CreateJsonResponse(req, new { message = "App policy updated successfully" });
            }
            else
            {
                return await CreateErrorResponse(req, "Failed to update app policy");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating app policy");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get audit logs
    /// </summary>
    [Function("GetAuditLogs")]
    public async Task<HttpResponseData> GetAuditLogs(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "audit")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting audit logs");

        try
        {
            var fromParam = req.Query["from"];
            var toParam = req.Query["to"];

            DateTime startDate;
            DateTime endDate;

            if (!string.IsNullOrWhiteSpace(fromParam) && !string.IsNullOrWhiteSpace(toParam))
            {
                if (!DateTime.TryParse(fromParam, out var fromDate) || !DateTime.TryParse(toParam, out var toDate))
                {
                    return await CreateErrorResponse(req, "Invalid from/to date format", HttpStatusCode.BadRequest);
                }

                startDate = fromDate.Date;
                endDate = toDate.Date.AddDays(1).AddTicks(-1);

                if (startDate > endDate)
                {
                    return await CreateErrorResponse(req, "From date must be before or equal to To date", HttpStatusCode.BadRequest);
                }
            }
            else
            {
                var daysParam = req.Query["days"];
                var days = int.TryParse(daysParam, out var d) ? d : 30;
                days = Math.Max(1, days);
                startDate = DateTime.UtcNow.AddDays(-days);
                endDate = DateTime.UtcNow;
            }

            var entries = await _auditService.GetEntriesAsync(startDate, endDate);

            return await CreateJsonResponse(req, entries);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting audit logs");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get audit logs for a specific application
    /// </summary>
    [Function("GetAppAuditLogs")]
    public async Task<HttpResponseData> GetAppAuditLogs(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "audit/app/{id}")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting audit logs for app {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var entries = await _auditService.GetEntriesForAppAsync(id);
            return await CreateJsonResponse(req, entries);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting app audit logs");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get application settings
    /// </summary>
    [Function("GetSettings")]
    public async Task<HttpResponseData> GetSettings(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "settings")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Getting settings");

        try
        {
            var notificationEmails = await _policyService.GetNotificationEmailsAsync();
            if (string.IsNullOrWhiteSpace(notificationEmails))
            {
                notificationEmails = _configuration["AdminNotificationEmails"] ?? "";
            }

            var reportOnlyModeEnabled = await _policyService.GetReportOnlyModeEnabledAsync();
            var retentionPolicyDays = await _policyService.GetRetentionPolicyDaysAsync();
            var sponsorsReceiveNotifications = await _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
            var notifySponsorsOnExpiration = await _policyService.GetNotifySponsorsOnExpirationEnabledAsync();
            var sponsorReminderDays = await _policyService.GetSponsorReminderDaysAsync();

            var settings = new
            {
                notificationEmails,
                senderEmail = _configuration["NotificationSenderEmail"] ?? "",
                tenantId = _configuration["TenantId"] ?? "",
                rotationSchedule = _configuration["RotationSchedule"] ?? "0 0 6 * * *",
                reportOnlyModeEnabled,
                retentionPolicyDays,
                sponsorsReceiveNotifications,
                notifySponsorsOnExpiration,
                sponsorFirstReminderDays = sponsorReminderDays.firstReminderDays,
                sponsorSecondReminderDays = sponsorReminderDays.secondReminderDays,
                sponsorThirdReminderDays = sponsorReminderDays.thirdReminderDays
            };
            return await CreateJsonResponse(req, settings);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting settings");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Update notification emails (note: this updates in-memory only, 
    /// permanent changes require updating App Settings in Azure Portal)
    /// </summary>
    [Function("UpdateSettings")]
    public async Task<HttpResponseData> UpdateSettings(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "settings")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Updating settings");

        try
        {
            var body = await req.ReadAsStringAsync();
            var settings = JsonSerializer.Deserialize<SettingsUpdateRequest>(body ?? "{}", new JsonSerializerOptions 
            { 
                PropertyNameCaseInsensitive = true 
            });

            if (settings == null)
            {
                return await CreateErrorResponse(req, "Invalid settings data", HttpStatusCode.BadRequest);
            }

            // Note: We can't actually update Azure App Settings from within the function
            // This would require Azure Management API access. For now, we'll store in Table Storage
            // alongside policies, or return instructions.
            
            // Store settings in policy service (we'll reuse the table)
            await _policyService.UpdateNotificationEmailsAsync(settings.NotificationEmails ?? "");

            if (settings.ReportOnlyModeEnabled.HasValue)
            {
                await _policyService.UpdateReportOnlyModeEnabledAsync(settings.ReportOnlyModeEnabled.Value);
            }

            if (settings.RetentionPolicyDays.HasValue)
            {
                if (settings.RetentionPolicyDays.Value < 1)
                {
                    return await CreateErrorResponse(req, "Retention policy must be at least 1 day", HttpStatusCode.BadRequest);
                }
                await _policyService.UpdateRetentionPolicyDaysAsync(settings.RetentionPolicyDays.Value);
            }

            if (settings.SponsorsReceiveNotifications.HasValue)
            {
                await _policyService.UpdateSponsorsReceiveNotificationsEnabledAsync(settings.SponsorsReceiveNotifications.Value);
            }

            if (settings.NotifySponsorsOnExpiration.HasValue)
            {
                await _policyService.UpdateNotifySponsorsOnExpirationEnabledAsync(settings.NotifySponsorsOnExpiration.Value);
            }

            if (settings.SponsorFirstReminderDays.HasValue || settings.SponsorSecondReminderDays.HasValue || settings.SponsorThirdReminderDays.HasValue)
            {
                var existingReminderDays = await _policyService.GetSponsorReminderDaysAsync();

                var firstReminderDays = settings.SponsorFirstReminderDays ?? existingReminderDays.firstReminderDays;
                var secondReminderDays = settings.SponsorSecondReminderDays ?? existingReminderDays.secondReminderDays;
                var thirdReminderDays = settings.SponsorThirdReminderDays ?? existingReminderDays.thirdReminderDays;

                if (firstReminderDays < 1 || firstReminderDays > 180 || secondReminderDays < 1 || secondReminderDays > 180 || thirdReminderDays < 1 || thirdReminderDays > 180)
                {
                    return await CreateErrorResponse(req, "Sponsor reminder days must be whole numbers between 1 and 180", HttpStatusCode.BadRequest);
                }

                await _policyService.UpdateSponsorReminderDaysAsync(firstReminderDays, secondReminderDays, thirdReminderDays);
            }

            var reportOnlyModeEnabled = await _policyService.GetReportOnlyModeEnabledAsync();
            var retentionPolicyDays = await _policyService.GetRetentionPolicyDaysAsync();
            var sponsorsReceiveNotifications = await _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
            var notifySponsorsOnExpiration = await _policyService.GetNotifySponsorsOnExpirationEnabledAsync();
            var sponsorReminderDays = await _policyService.GetSponsorReminderDaysAsync();

            return await CreateJsonResponse(req, new 
            { 
                message = "Settings updated successfully",
                notificationEmails = settings.NotificationEmails,
                reportOnlyModeEnabled,
                retentionPolicyDays,
                sponsorsReceiveNotifications,
                notifySponsorsOnExpiration,
                sponsorFirstReminderDays = sponsorReminderDays.firstReminderDays,
                sponsorSecondReminderDays = sponsorReminderDays.secondReminderDays,
                sponsorThirdReminderDays = sponsorReminderDays.thirdReminderDays
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating settings");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Manually trigger certificate rotation (admin endpoint)
    /// </summary>
    [Function("TriggerRotation")]
    public async Task<HttpResponseData> TriggerRotation(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "admin/trigger-rotation")] HttpRequestData req)
    {
        return await TriggerRotationProd(req);
    }

    /// <summary>
    /// Manually trigger certificate rotation in report-only mode
    /// </summary>
    [Function("TriggerRotationReportOnly")]
    public async Task<HttpResponseData> TriggerRotationReportOnly(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "admin/trigger-rotation/report-only")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Manual report-only rotation triggered");

        try
        {
            var results = await _rotationService.RunRotationAsync(true);
            var (successful, skipped, failed) = GetRotationOutcomeCounts(results);
            return await CreateJsonResponse(req, new
            {
                message = "Report-only run completed",
                mode = "report-only",
                totalProcessed = results.Count,
                successful,
                skipped,
                failed,
                results = results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during manual report-only rotation");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Manually trigger certificate rotation in report-only mode (non-admin alias route)
    /// </summary>
    [Function("TriggerRotationReportOnlyAlias")]
    public Task<HttpResponseData> TriggerRotationReportOnlyAlias(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "rotation/trigger/report-only")] HttpRequestData req)
    {
        return TriggerRotationReportOnly(req);
    }

    /// <summary>
    /// Manually trigger certificate rotation in production mode
    /// </summary>
    [Function("TriggerRotationProd")]
    public async Task<HttpResponseData> TriggerRotationProd(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "admin/trigger-rotation/prod")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Manual production rotation triggered");

        try
        {
            var results = await _rotationService.RunRotationAsync(false);
            var (successful, skipped, failed) = GetRotationOutcomeCounts(results);
            return await CreateJsonResponse(req, new
            {
                message = "Completed production rotation run",
                mode = "prod",
                totalProcessed = results.Count,
                successful,
                skipped,
                failed,
                results = results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during manual production rotation");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Manually trigger certificate rotation in production mode (non-admin alias route)
    /// </summary>
    [Function("TriggerRotationProdAlias")]
    public Task<HttpResponseData> TriggerRotationProdAlias(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "rotation/trigger/prod")] HttpRequestData req)
    {
        return TriggerRotationProd(req);
    }

    /// <summary>
    /// Create a new SAML certificate for an application
    /// </summary>
    [Function("CreateCertificate")]
    public async Task<HttpResponseData> CreateCertificate(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "applications/{id}/certificate")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Creating new certificate for application {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
            }

            var cert = await _graphService.CreateSamlCertificateAsync(id);
            if (cert == null)
            {
                return await CreateErrorResponse(req, "Failed to create certificate");
            }

            await _auditService.LogSuccessAsync(
                id,
                app.DisplayName,
                AuditActionType.CertificateCreated,
                $"New certificate created via dashboard. KeyId: {cert.KeyId}");

            return await CreateJsonResponse(req, new
            {
                message = "Certificate created successfully",
                certificate = cert
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating certificate for application {Id}", id);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Activate the newest certificate for an application
    /// </summary>
    [Function("ActivateNewestCertificate")]
    public async Task<HttpResponseData> ActivateNewestCertificate(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "applications/{id}/certificate/activate")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Activating newest certificate for application {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
            }

            if (app.Certificates == null || !app.Certificates.Any())
            {
                return await CreateErrorResponse(req, "No certificates found for this application", HttpStatusCode.BadRequest);
            }

            // Find the most recently created certificate (by StartDateTime)
            var newestCert = app.Certificates
                .OrderByDescending(c => c.StartDateTime)
                .First();

            if (newestCert.IsActive)
            {
                return await CreateJsonResponse(req, new
                {
                    message = "The newest certificate is already active",
                    activatedKeyId = newestCert.KeyId
                });
            }

            var success = await _graphService.ActivateCertificateAsync(id, newestCert.Thumbprint);
            if (!success)
            {
                return await CreateErrorResponse(req, "Failed to activate certificate");
            }

            await _auditService.LogSuccessAsync(
                id,
                app.DisplayName,
                AuditActionType.CertificateActivated,
                $"Certificate activated via dashboard. KeyId: {newestCert.KeyId}, Thumbprint: {newestCert.Thumbprint}, Expires: {newestCert.EndDateTime:yyyy-MM-dd}");

            return await CreateJsonResponse(req, new
            {
                message = "Certificate activated successfully",
                activatedKeyId = newestCert.KeyId
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error activating certificate for application {Id}", id);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Manually resend sponsor reminder email for applications in Expired/Critical/Warning status
    /// </summary>
    [Function("ResendReminderEmail")]
    public async Task<HttpResponseData> ResendReminderEmail(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "applications/{id}/resend-reminder")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Manual sponsor reminder email requested for application {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
            }

            var activeCert = app.Certificates.FirstOrDefault(c => c.IsActive);
            if (activeCert == null)
            {
                return await CreateErrorResponse(req, "No active certificate found for this application", HttpStatusCode.BadRequest);
            }

            var globalPolicy = await _policyService.GetGlobalPolicyAsync();
            var status = GetCertificateStatus(activeCert.DaysUntilExpiry, globalPolicy.CreateCertDaysBeforeExpiry, globalPolicy.ActivateCertDaysBeforeExpiry);
            if (string.Equals(status, "OK", StringComparison.OrdinalIgnoreCase))
            {
                return await CreateErrorResponse(req, "Reminder emails can only be resent for Expired, Critical, or Warning applications", HttpStatusCode.BadRequest);
            }

            var appUrl = BuildEntraManagedAppUrl(app.Id, app.AppId);
            var sent = await _notificationService.SendSponsorExpirationStatusNotificationAsync(app, activeCert, activeCert.DaysUntilExpiry, appUrl, status, true);
            if (!sent)
            {
                return await CreateErrorResponse(req, "No sponsor recipient found or email failed to send", HttpStatusCode.BadRequest);
            }

            await _auditService.LogSuccessAsync(
                app.Id,
                app.DisplayName,
                AuditActionType.SponsorExpirationReminderSent,
                $"Manual expiration reminder sent. Status: {status}. Days remaining: {activeCert.DaysUntilExpiry}. Link: {appUrl}",
                activeCert.Thumbprint);

            return await CreateJsonResponse(req, new
            {
                message = "Reminder email sent successfully",
                status,
                daysUntilExpiry = activeCert.DaysUntilExpiry
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resending reminder email for application {Id}", id);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Update sponsor tag for an application service principal
    /// </summary>
    [Function("UpdateApplicationSponsor")]
    public async Task<HttpResponseData> UpdateApplicationSponsor(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "applications/{id}/sponsor")] HttpRequestData req,
        string id)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Updating sponsor for application {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        SamlApplication? app = null;

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var request = JsonSerializer.Deserialize<SponsorUpdateRequest>(body, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            var sponsorEmail = request?.SponsorEmail?.Trim();
            if (string.IsNullOrWhiteSpace(sponsorEmail))
            {
                return await CreateErrorResponse(req, "Sponsor email is required", HttpStatusCode.BadRequest);
            }

            if (!IsValidEmail(sponsorEmail))
            {
                return await CreateErrorResponse(req, "Sponsor email format is invalid", HttpStatusCode.BadRequest);
            }

            app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
            }

            var updated = await _graphService.UpdateAppSponsorTagAsync(id, sponsorEmail);
            if (!updated)
            {
                return await CreateErrorResponse(req, "Failed to update sponsor tag");
            }

            await _auditService.LogSuccessAsync(
                id,
                app.DisplayName,
                AuditActionType.SponsorUpdated,
                $"Sponsor updated to AppSponsor={sponsorEmail}");

            return await CreateJsonResponse(req, new
            {
                message = "Sponsor updated successfully",
                sponsor = sponsorEmail
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating sponsor for application {Id}", id);

            await _auditService.LogFailureAsync(
                id,
                app?.DisplayName ?? "Unknown",
                AuditActionType.SponsorUpdated,
                "Error updating sponsor",
                ex.Message);

            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Serializes a success payload using the shared JSON options and status code.
    /// </summary>
    private async Task<HttpResponseData> CreateJsonResponse<T>(HttpRequestData req, T data, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(data, JsonOptions));
        return response;
    }

    /// <summary>
    /// Returns a sanitized error payload to avoid exposing sensitive implementation details.
    /// </summary>
    private async Task<HttpResponseData> CreateErrorResponse(HttpRequestData req, string message, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
    {
        // Sanitize error messages to avoid exposing internal details
        var sanitizedMessage = SanitizeErrorMessage(message);
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(new { error = sanitizedMessage }, JsonOptions));
        return response;
    }

    /// <summary>
    /// Filters known sensitive patterns from error text before returning it to callers.
    /// </summary>
    private static string SanitizeErrorMessage(string message)
    {
        // Remove potentially sensitive information from error messages
        // Keep it generic for security but specific enough to be useful
        if (string.IsNullOrEmpty(message)) return "An error occurred";
        
        // List of patterns that might leak implementation details
        var sensitivePatterns = new[] { "stack trace", "at System.", "at Microsoft.", "connection string", "password", "secret" };
        var lowerMessage = message.ToLowerInvariant();
        
        foreach (var pattern in sensitivePatterns)
        {
            if (lowerMessage.Contains(pattern))
            {
                return "An internal error occurred. Please check logs for details.";
            }
        }
        
        return message;
    }

    /// <summary>
    /// Validates caller identity and role requirements for dashboard endpoints.
    /// </summary>
    private async Task<HttpResponseData?> AuthorizeRequestAsync(HttpRequestData req, bool requireAdmin = false)
    {
        var identity = await ParseClientPrincipalAsync(req);
        if (identity == null || !identity.IsAuthenticated)
        {
            _logger.LogWarning("Unauthorized request to {Method} {Url}", req.Method, req.Url);
            return await CreateErrorResponse(req, "Authentication is required.", HttpStatusCode.Unauthorized);
        }

        var hasReadAccess = identity.Roles.Contains("admin")
                    || identity.Roles.Contains("reader")
                    || identity.Roles.Contains("authenticated");
        if (!hasReadAccess)
        {
            _logger.LogWarning("Forbidden request by user {UserId} to {Method} {Url} - missing reader/admin role", identity.UserId ?? "unknown", req.Method, req.Url);
            return await CreateErrorResponse(req, "Reader or admin role is required.", HttpStatusCode.Forbidden);
        }

        if (requireAdmin && !identity.Roles.Contains("admin"))
        {
            _logger.LogWarning("Forbidden request by user {UserId} to {Method} {Url}", identity.UserId ?? "unknown", req.Method, req.Url);
            return await CreateErrorResponse(req, "Admin role is required.", HttpStatusCode.Forbidden);
        }

        return null;
    }

    /// <summary>
    /// Parses the caller identity from request headers/tokens.
    /// Order matters for security: validated AAD token first (signature-verified),
    /// then SWA client principal header, then unsigned SWA JWT (last resort).
    /// </summary>
    private async Task<RequestIdentity?> ParseClientPrincipalAsync(HttpRequestData req)
    {
        // 1. Try validated AAD token first — most secure (signature + issuer verified)
        var tokenIdentity = await ParseClientPrincipalFromValidatedAuthTokenAsync(req);
        if (tokenIdentity != null)
        {
            return tokenIdentity;
        }

        // 2. Try x-ms-client-principal base64 header — set by SWA reverse proxy
        var encodedPrincipal = GetHeaderValue(req, "x-ms-client-principal");
        if (!string.IsNullOrWhiteSpace(encodedPrincipal))
        {
            try
            {
                var json = DecodePrincipalPayload(encodedPrincipal);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    using var document = JsonDocument.Parse(json);
                    var root = document.RootElement;
                    if (root.TryGetProperty("clientPrincipal", out var wrappedPrincipal) && wrappedPrincipal.ValueKind == JsonValueKind.Object)
                    {
                        root = wrappedPrincipal;
                    }

                    var identity = BuildIdentityFromPrincipalRoot(root);
                    if (identity != null)
                    {
                        return identity;
                    }
                }
            }
            catch
            {
            }
        }

        // 3. Try SWA-issued JWT — unsigned, but only trusted for explicitly configured SWA hostnames.
        // Required for SWA linked backends where x-ms-client-principal is not forwarded.
        var swaTokenIdentity = ParseIdentityFromSwaIssuedToken(req);
        if (swaTokenIdentity != null)
        {
            return swaTokenIdentity;
        }

        return null;
    }

    /// <summary>
    /// Decodes a SWA-issued JWT (issuer = SWA hostname/.auth) without signature validation.
    /// Same trust model as x-ms-client-principal: both are set by SWA's reverse proxy.
    /// Only trusts tokens whose issuer matches a configured/known SWA hostname.
    /// </summary>
    private RequestIdentity? ParseIdentityFromSwaIssuedToken(HttpRequestData req)
    {
        var candidates = GetCandidateAuthTokens(req).ToList();
        if (candidates.Count == 0)
        {
            return null;
        }

        var handler = new JwtSecurityTokenHandler();

        foreach (var (source, token) in candidates)
        {
            JwtSecurityToken? jwt;
            try
            {
                jwt = handler.ReadJwtToken(token);
            }
            catch
            {
                continue;
            }

            var issuer = jwt.Issuer;

            // Check if this is a SWA-issued token by matching issuer against explicitly configured hostnames.
            // No auto-detect: SWA_HOSTNAME must be configured to prevent forged tokens from unknown issuers.
            if (_trustedSwaIssuers.Count == 0)
            {
                _logger.LogWarning("SWA_HOSTNAME is not configured. Cannot authenticate SWA-issued tokens. Set SWA_HOSTNAME in Function App settings.");
                return null;
            }

            var isTrustedSwa = _trustedSwaIssuers.Contains(issuer);

            if (!isTrustedSwa)
            {
                continue;
            }

            // Extract claims from SWA token payload
            var userId = jwt.Claims.FirstOrDefault(c => c.Type == "oid")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "stable_sid")?.Value;

            var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var claimRoleValues = new List<string>();
            var claimGroupValues = new List<string>();

            // SWA embeds the full client principal (including userRoles) in the "prn" claim as base64 JSON
            var prnClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, "prn", StringComparison.OrdinalIgnoreCase))?.Value;
            if (!string.IsNullOrWhiteSpace(prnClaim))
            {
                try
                {
                    var prnJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(prnClaim));
                    using var prnDoc = JsonDocument.Parse(prnJson);
                    var prnRoot = prnDoc.RootElement;

                    // Extract userId from prn if not already found
                    if (string.IsNullOrWhiteSpace(userId))
                    {
                        userId = TryGetString(prnRoot, "userId");
                    }

                    // Extract userRoles from prn — these are the roles assigned by SWA (including custom roles from GetRoles)
                    if (prnRoot.TryGetProperty("userRoles", out var prnRoles) && prnRoles.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var roleEl in prnRoles.EnumerateArray())
                        {
                            var role = roleEl.GetString();
                            if (!string.IsNullOrWhiteSpace(role))
                            {
                                roles.Add(role);
                            }
                        }
                    }

                    _logger.LogInformation("Extracted {RoleCount} roles from SWA prn claim: {Roles}", roles.Count, string.Join(", ", roles));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to decode prn claim from SWA token");
                }
            }

            // Also check standard JWT role/group claims as fallback
            foreach (var rv in jwt.Claims
                .Where(c => string.Equals(c.Type, "roles", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v)))
            {
                claimRoleValues.Add(rv);
            }

            foreach (var gv in jwt.Claims
                .Where(c => string.Equals(c.Type, "groups", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v)))
            {
                claimGroupValues.Add(gv);
            }

            ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

            if (roles.Count == 0 && !string.IsNullOrWhiteSpace(userId))
            {
                roles.Add("authenticated");
            }

            if (!IsAuthenticatedPrincipal(userId, roles))
            {
                continue;
            }

            _logger.LogInformation("Authenticated request identity from SWA-issued token via {TokenSource}", source);

            return new RequestIdentity
            {
                UserId = userId,
                IsAuthenticated = true,
                Roles = roles
            };
        }

        return null;
    }

    /// <summary>
    /// Validates forwarded identity token against Entra signing keys/issuer, then extracts identity and role claims.
    /// </summary>
    private async Task<RequestIdentity?> ParseClientPrincipalFromValidatedAuthTokenAsync(HttpRequestData req)
    {
        var candidateTokens = GetCandidateAuthTokens(req).ToList();
        if (candidateTokens.Count == 0)
        {
            return null;
        }

        if (_oidcConfigurationManager == null || string.IsNullOrWhiteSpace(_tenantId))
        {
            _logger.LogWarning("Cannot validate x-ms-auth-token because TenantId is not configured on Function App settings.");
            return null;
        }

        var oidcConfig = await _oidcConfigurationManager.GetConfigurationAsync(CancellationToken.None);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = oidcConfig.SigningKeys,
            ValidateIssuer = true,
            ValidIssuers = new[]
            {
                $"https://login.microsoftonline.com/{_tenantId}/v2.0",
                $"https://sts.windows.net/{_tenantId}/"
            },
            ValidateAudience = _allowedAudiences.Count > 0,
            ValidAudiences = _allowedAudiences,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        var handler = new JwtSecurityTokenHandler();

        foreach (var (source, token) in candidateTokens)
        {
            try
            {
                var principal = handler.ValidateToken(token, validationParameters, out _);

                var userId = principal.FindFirst("oid")?.Value
                             ?? principal.FindFirst("sub")?.Value
                             ?? principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
                             ?? principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

                var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var claimRoleValues = principal.Claims
                    .Where(c =>
                        string.Equals(c.Type, "roles", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                    .Select(c => c.Value)
                    .Where(v => !string.IsNullOrWhiteSpace(v));

                var claimGroupValues = principal.Claims
                    .Where(c =>
                        string.Equals(c.Type, "groups", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                    .Select(c => c.Value)
                    .Where(v => !string.IsNullOrWhiteSpace(v));

                ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

                if (roles.Count == 0 && !string.IsNullOrWhiteSpace(userId))
                {
                    roles.Add("authenticated");
                }

                if (!IsAuthenticatedPrincipal(userId, roles))
                {
                    continue;
                }

                _logger.LogInformation("Authenticated request identity from token source {TokenSource}", source);

                return new RequestIdentity
                {
                    UserId = userId,
                    IsAuthenticated = true,
                    Roles = roles
                };
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogDebug(ex, "Token from source {TokenSource} failed validation.", source);
            }
        }

        _logger.LogWarning("No forwarded token source produced a valid authenticated principal.");
        return null;
    }

    private IEnumerable<(string Source, string Token)> GetCandidateAuthTokens(HttpRequestData req)
    {
        var candidates = new List<(string Source, string Token)>();

        AddCandidate(candidates, "x-ms-auth-token", GetHeaderValue(req, "x-ms-auth-token"));
        AddCandidate(candidates, "x-ms-token-aad-id-token", GetHeaderValue(req, "x-ms-token-aad-id-token"));
        AddCandidate(candidates, "x-ms-token-aad-access-token", GetHeaderValue(req, "x-ms-token-aad-access-token"));
        AddCandidate(candidates, "authorization", GetHeaderValue(req, "authorization"));

        return candidates;
    }

    private static void AddCandidate(List<(string Source, string Token)> candidates, string source, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return;
        }

        var token = rawValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? rawValue.Substring("Bearer ".Length).Trim()
            : rawValue.Trim();

        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        candidates.Add((source, token));
    }

    private static void AddAudienceIfPresent(HashSet<string> audiences, string? audience)
    {
        if (!string.IsNullOrWhiteSpace(audience))
        {
            audiences.Add(audience.Trim());
        }
    }

    /// <summary>
    /// Builds an internal identity model from SWA principal payload fields and claims.
    /// </summary>
    private RequestIdentity? BuildIdentityFromPrincipalRoot(JsonElement root)
    {
        var userId = TryGetString(root, "userId");
        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var claimRoleValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var claimGroupValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (root.TryGetProperty("userRoles", out var userRolesElement) && userRolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var roleElement in userRolesElement.EnumerateArray())
            {
                var role = roleElement.GetString();
                if (!string.IsNullOrWhiteSpace(role))
                {
                    roles.Add(role);
                }
            }
        }

        if (root.TryGetProperty("claims", out var claimsElement) && claimsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var claimElement in claimsElement.EnumerateArray())
            {
                if (claimElement.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var claimType = TryGetString(claimElement, "typ") ?? TryGetString(claimElement, "type");
                var claimValue = TryGetString(claimElement, "val") ?? TryGetString(claimElement, "value");

                if (string.IsNullOrWhiteSpace(claimType) || string.IsNullOrWhiteSpace(claimValue))
                {
                    continue;
                }

                if (string.Equals(claimType, "roles", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claimType, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                {
                    claimRoleValues.Add(claimValue);
                }

                if (string.Equals(claimType, "groups", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claimType, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                {
                    claimGroupValues.Add(claimValue);
                }

                if (string.IsNullOrWhiteSpace(userId) &&
                    (string.Equals(claimType, "oid", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "sub", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "nameid", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "http://schemas.microsoft.com/identity/claims/objectidentifier", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", StringComparison.OrdinalIgnoreCase)))
                {
                    userId = claimValue;
                }
            }
        }

        ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

        if (roles.Count == 0 && !string.IsNullOrWhiteSpace(userId))
        {
            roles.Add("authenticated");
        }

        if (roles.Count == 0)
        {
            return null;
        }

        return new RequestIdentity
        {
            UserId = userId,
            IsAuthenticated = IsAuthenticatedPrincipal(userId, roles),
            Roles = roles
        };
    }

    /// <summary>
    /// Treats principals with a user id or recognized roles as authenticated.
    /// </summary>
    private static bool IsAuthenticatedPrincipal(string? userId, HashSet<string> roles)
    {
        return !string.IsNullOrWhiteSpace(userId)
               || roles.Contains("authenticated")
               || roles.Contains("admin")
               || roles.Contains("reader");
    }

    /// <summary>
    /// Maps app-role or group claims to local admin/reader dashboard roles.
    /// </summary>
    private void ApplyConfiguredRoleMappings(HashSet<string> roles, IEnumerable<string> claimRoleValues, IEnumerable<string> claimGroupValues)
    {
        var configuredAdminAppRole = _configuration["SWA_ADMIN_APP_ROLE"];
        var configuredReaderAppRole = _configuration["SWA_READER_APP_ROLE"];
        var configuredAdminGroup = _configuration["SWA_ADMIN_GROUP_ID"];
        var configuredReaderGroup = _configuration["SWA_READER_GROUP_ID"];

        if (string.IsNullOrWhiteSpace(configuredAdminAppRole))
        {
            configuredAdminAppRole = "SamlCertRotation.Admin";
        }

        if (string.IsNullOrWhiteSpace(configuredReaderAppRole))
        {
            configuredReaderAppRole = "SamlCertRotation.Reader";
        }

        var roleSet = claimRoleValues is HashSet<string> roleHash
            ? roleHash
            : new HashSet<string>(claimRoleValues.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);

        var groupSet = claimGroupValues is HashSet<string> groupHash
            ? groupHash
            : new HashSet<string>(claimGroupValues.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);

        var isAdminByClaimRole = !string.IsNullOrWhiteSpace(configuredAdminAppRole) && roleSet.Contains(configuredAdminAppRole);
        var isReaderByClaimRole = !string.IsNullOrWhiteSpace(configuredReaderAppRole) && roleSet.Contains(configuredReaderAppRole);
        var isAdminByClaimGroup = !string.IsNullOrWhiteSpace(configuredAdminGroup) && groupSet.Contains(configuredAdminGroup);
        var isReaderByClaimGroup = !string.IsNullOrWhiteSpace(configuredReaderGroup) && groupSet.Contains(configuredReaderGroup);

        if (isAdminByClaimRole || isAdminByClaimGroup || roles.Contains("admin"))
        {
            roles.Add("admin");
            roles.Add("reader");
        }
        else if (isReaderByClaimRole || isReaderByClaimGroup || roles.Contains("reader"))
        {
            roles.Add("reader");
        }
    }

    /// <summary>
    /// Reads a header value with case-insensitive fallback for Functions header collections.
    /// </summary>
    private static string? GetHeaderValue(HttpRequestData req, string headerName)
    {
        if (req.Headers.TryGetValues(headerName, out var values))
        {
            var direct = values.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(direct))
            {
                return direct;
            }
        }

        foreach (var header in req.Headers)
        {
            if (!string.Equals(header.Key, headerName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = header.Value?.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>
    /// Decodes URL/base64 encoded principal payloads; returns JSON when available.
    /// </summary>
    private static string? DecodePrincipalPayload(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        var trimmed = payload.Trim();
        var decoded = Uri.UnescapeDataString(trimmed);

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(NormalizeBase64(decoded)));
        }
        catch
        {
            if (decoded.StartsWith("{", StringComparison.Ordinal) || decoded.StartsWith("[", StringComparison.Ordinal))
            {
                return decoded;
            }

            return null;
        }
    }

    /// <summary>
    /// Converts URL-safe base64 to standard base64 and pads to valid length.
    /// </summary>
    private static string NormalizeBase64(string value)
    {
        var normalized = value
            .Replace('-', '+')
            .Replace('_', '/');

        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');
        }

        return normalized;
    }

    private static string? TryGetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    /// <summary>
    /// Checks whether a string is a valid GUID.
    /// </summary>
    private static bool IsValidGuid(string value)
    {
        return !string.IsNullOrEmpty(value) && Guid.TryParse(value, out _);
    }

    /// <summary>
    /// Builds a deep-link to the managed app SAML sign-on blade in Entra admin center.
    /// </summary>
    private static string BuildEntraManagedAppUrl(string servicePrincipalObjectId, string appId)
    {
        return $"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn/objectId/{Uri.EscapeDataString(servicePrincipalObjectId)}/appId/{Uri.EscapeDataString(appId)}/preferredSingleSignOnMode/saml/servicePrincipalType/Application/fromNav/";
    }

    /// <summary>
    /// Returns normalized status buckets used by the dashboard and sponsor notifications.
    /// </summary>
    private static string GetCertificateStatus(int daysUntilExpiry, int warningThresholdDays, int criticalThresholdDays)
    {
        if (daysUntilExpiry < 0)
        {
            return "Expired";
        }

        if (daysUntilExpiry <= criticalThresholdDays)
        {
            return "Critical";
        }

        if (daysUntilExpiry <= warningThresholdDays)
        {
            return "Warning";
        }

        return "OK";
    }

    /// <summary>
    /// Validates email format for sponsor updates.
    /// </summary>
    private static bool IsValidEmail(string email)
    {
        try
        {
            _ = new MailAddress(email);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private sealed class SponsorUpdateRequest
    {
        public string? SponsorEmail { get; set; }
    }

    private sealed class RequestIdentity
    {
        public string? UserId { get; set; }
        public bool IsAuthenticated { get; set; }
        public HashSet<string> Roles { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Computes successful/skipped/failed totals for rotation run summaries.
    /// </summary>
    private static (int successful, int skipped, int failed) GetRotationOutcomeCounts(List<RotationResult> results)
    {
        var successful = results.Count(r =>
            r.Success && (
                string.Equals(r.Action, "Created", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Activated", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Create", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.Action, "Would Activate", StringComparison.OrdinalIgnoreCase)));

        var failed = results.Count(r => !r.Success);
        var skipped = Math.Max(0, results.Count - successful - failed);
        return (successful, skipped, failed);
    }
}
