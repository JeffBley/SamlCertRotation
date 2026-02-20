using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
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
    private readonly ISwaSettingsService _swaSettingsService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DashboardFunctions> _logger;
    private readonly SecretClient? _secretClient;

    private const string SwaClientSecretName = "SwaClientSecret";

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
        ISwaSettingsService swaSettingsService,
        IConfiguration configuration,
        ILogger<DashboardFunctions> logger)
    {
        _rotationService = rotationService;
        _graphService = graphService;
        _policyService = policyService;
        _auditService = auditService;
        _notificationService = notificationService;
        _swaSettingsService = swaSettingsService;
        _configuration = configuration;
        _logger = logger;

        // Initialize Key Vault client
        var keyVaultUri = configuration["KeyVaultUri"];
        if (!string.IsNullOrEmpty(keyVaultUri))
        {
            var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ManagedIdentityClientId = configuration["AZURE_CLIENT_ID"]
            });
            _secretClient = new SecretClient(new Uri(keyVaultUri), credential);
        }
    }

    /// <summary>
    /// Temporary endpoint to debug auth header forwarding from SWA.
    /// Remove after auth issue is resolved.
    /// </summary>
    [Function("DebugIdentity")]
    public async Task<HttpResponseData> DebugIdentity(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "debug/identity")] HttpRequestData req)
    {
        var parsedIdentity = ParseClientPrincipal(req);

        var headerSnapshot = req.Headers
            .Where(h => h.Key.StartsWith("x-ms-", StringComparison.OrdinalIgnoreCase) ||
                        h.Key.StartsWith("x-arr-", StringComparison.OrdinalIgnoreCase) ||
                        h.Key.StartsWith("x-forwarded-", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(
                h => h.Key,
                h => h.Value?.Select(v => TruncateForDebug(v)).ToArray() ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);

        var response = new
        {
            message = "Temporary auth debug endpoint. Remove after troubleshooting.",
            url = req.Url.ToString(),
            method = req.Method,
            hasClientPrincipalHeader = !string.IsNullOrWhiteSpace(GetHeaderValue(req, "x-ms-client-principal")),
            clientPrincipalId = GetHeaderValue(req, "x-ms-client-principal-id"),
            clientPrincipalName = GetHeaderValue(req, "x-ms-client-principal-name"),
            clientPrincipalUserRoles = GetHeaderValue(req, "x-ms-client-principal-user-roles"),
            parsedIdentity = parsedIdentity == null
                ? null
                : new
                {
                    parsedIdentity.UserId,
                    parsedIdentity.IsAuthenticated,
                    Roles = parsedIdentity.Roles.OrderBy(r => r).ToArray()
                },
            headers = headerSnapshot
        };

        return await CreateJsonResponse(req, response);
    }

    /// <summary>
    /// Get dashboard statistics
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
    /// Rotate the dashboard application client secret and store in Key Vault
    /// </summary>
    [Function("RotateDashboardSecret")]
    public async Task<HttpResponseData> RotateDashboardSecret(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "settings/rotate-secret")] HttpRequestData req)
    {
        var authError = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null)
        {
            return authError;
        }

        _logger.LogInformation("Rotating dashboard client secret");

        try
        {
            if (_secretClient == null)
            {
                return await CreateErrorResponse(req, "Key Vault not configured - cannot store rotated secret", HttpStatusCode.BadRequest);
            }

            var clientId = _configuration["SWA_CLIENT_ID"];
            if (string.IsNullOrEmpty(clientId))
            {
                return await CreateErrorResponse(req, "SWA_CLIENT_ID not configured in Function App settings", HttpStatusCode.BadRequest);
            }

            var result = await _graphService.RotateAppClientSecretAsync(clientId);
            if (result == null)
            {
                return await CreateErrorResponse(req, "Failed to rotate client secret");
            }

            if (string.IsNullOrEmpty(result.SecretValue))
            {
                return await CreateErrorResponse(req, "New secret was created but value was not returned");
            }

            // Store the new secret in Key Vault
            var secret = new KeyVaultSecret(SwaClientSecretName, result.SecretValue)
            {
                Properties =
                {
                    ExpiresOn = result.EndDateTime,
                    ContentType = "application/x-password",
                    Tags =
                    {
                        ["AppClientId"] = clientId,
                        ["CreatedBy"] = "SamlCertRotation-ManualRotate",
                        ["RotatedAt"] = DateTime.UtcNow.ToString("o")
                    }
                }
            };

            await _secretClient.SetSecretAsync(secret);
            _logger.LogInformation("New client secret stored in Key Vault as '{SecretName}'", SwaClientSecretName);

            // Update the SWA app settings with the new secret
            var swaUpdated = await _swaSettingsService.UpdateClientSecretAsync(result.SecretValue);
            if (!swaUpdated)
            {
                _logger.LogWarning("Failed to update SWA app settings - manual update may be required");
            }

            await _auditService.LogSuccessAsync(
                clientId,
                "Dashboard Application",
                "Client Secret Rotated",
                $"Dashboard client secret was rotated and stored in Key Vault. SWA updated: {swaUpdated}. Expires: {result.EndDateTime:yyyy-MM-dd}");

            return await CreateJsonResponse(req, new
            {
                message = swaUpdated 
                    ? "Client secret rotated, stored in Key Vault, and SWA updated successfully." 
                    : "Client secret rotated and stored in Key Vault. SWA update failed - manual configuration may be required.",
                secretHint = result.Hint,
                expiresAt = result.EndDateTime,
                keyVaultSecretName = SwaClientSecretName,
                swaUpdated = swaUpdated
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error rotating dashboard client secret");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    private async Task<HttpResponseData> CreateJsonResponse<T>(HttpRequestData req, T data, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(data, JsonOptions));
        return response;
    }

    private async Task<HttpResponseData> CreateErrorResponse(HttpRequestData req, string message, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
    {
        // Sanitize error messages to avoid exposing internal details
        var sanitizedMessage = SanitizeErrorMessage(message);
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(new { error = sanitizedMessage }, JsonOptions));
        return response;
    }

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

    private async Task<HttpResponseData?> AuthorizeRequestAsync(HttpRequestData req, bool requireAdmin = false)
    {
        var identity = ParseClientPrincipal(req);
        if (identity == null || !identity.IsAuthenticated)
        {
            _logger.LogWarning("Unauthorized request to {Method} {Url}", req.Method, req.Url);
            return await CreateErrorResponse(req, "Authentication is required.", HttpStatusCode.Unauthorized);
        }

        var hasReadAccess = identity.Roles.Contains("admin") || identity.Roles.Contains("reader");
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

    private RequestIdentity? ParseClientPrincipal(HttpRequestData req)
    {
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
                        }
                    }

                    ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

                    if (roles.Count > 0)
                    {
                        return new RequestIdentity
                        {
                            UserId = userId,
                            IsAuthenticated = IsAuthenticatedPrincipal(userId, roles),
                            Roles = roles
                        };
                    }
                }
            }
            catch
            {
            }
        }

        return ParseClientPrincipalFromFallbackHeaders(req);
    }

    private RequestIdentity? ParseClientPrincipalFromFallbackHeaders(HttpRequestData req)
    {
        var userId = GetHeaderValue(req, "x-ms-client-principal-id")
                     ?? GetHeaderValue(req, "x-ms-client-principal-name")
                     ?? GetHeaderValue(req, "x-ms-client-principal-userid");

        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var claimRoleValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var claimGroupValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var role in ParseHeaderList(GetHeaderValue(req, "x-ms-client-principal-user-roles")))
        {
            roles.Add(role);
            claimRoleValues.Add(role);
        }

        foreach (var role in ParseHeaderList(GetHeaderValue(req, "x-ms-client-principal-roles")))
        {
            roles.Add(role);
            claimRoleValues.Add(role);
        }

        foreach (var role in ParseHeaderList(GetHeaderValue(req, "x-ms-client-principal-role")))
        {
            roles.Add(role);
            claimRoleValues.Add(role);
        }

        foreach (var group in ParseHeaderList(GetHeaderValue(req, "x-ms-client-principal-groups")))
        {
            claimGroupValues.Add(group);
        }

        ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

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

    private static bool IsAuthenticatedPrincipal(string? userId, HashSet<string> roles)
    {
        return !string.IsNullOrWhiteSpace(userId)
               || roles.Contains("authenticated")
               || roles.Contains("admin")
               || roles.Contains("reader");
    }

    private void ApplyConfiguredRoleMappings(HashSet<string> roles, IEnumerable<string> claimRoleValues, IEnumerable<string> claimGroupValues)
    {
        var configuredAdminAppRole = _configuration["SWA_ADMIN_APP_ROLE"] ?? "SamlCertRotation.Admin";
        var configuredReaderAppRole = _configuration["SWA_READER_APP_ROLE"] ?? "SamlCertRotation.Reader";
        var configuredAdminGroup = _configuration["SWA_ADMIN_GROUP_ID"];
        var configuredReaderGroup = _configuration["SWA_READER_GROUP_ID"];

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

    private static IEnumerable<string> ParseHeaderList(string? headerValue)
    {
        var results = new List<string>();

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return results;
        }

        var raw = headerValue.Trim();

        if (raw.StartsWith("[", StringComparison.Ordinal))
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var element in doc.RootElement.EnumerateArray())
                    {
                        if (element.ValueKind == JsonValueKind.String)
                        {
                            var value = element.GetString();
                            if (!string.IsNullOrWhiteSpace(value))
                            {
                                results.Add(value);
                            }
                        }
                    }
                }

                return results;
            }
            catch
            {
            }
        }

        foreach (var token in raw.Split(new[] { ',', ';', ' ', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!string.IsNullOrWhiteSpace(token))
            {
                results.Add(token);
            }
        }

        return results;
    }

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

    private static bool IsValidGuid(string value)
    {
        return !string.IsNullOrEmpty(value) && Guid.TryParse(value, out _);
    }

    private static string BuildEntraManagedAppUrl(string servicePrincipalObjectId, string appId)
    {
        return $"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn/objectId/{Uri.EscapeDataString(servicePrincipalObjectId)}/appId/{Uri.EscapeDataString(appId)}/preferredSingleSignOnMode/saml/servicePrincipalType/Application/fromNav/";
    }

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

    private static string TruncateForDebug(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        const int maxLength = 200;
        return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...(truncated)";
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
