using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Helpers;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// Admin-only HTTP functions: certificate CRUD, sponsor management, rotation triggers, testing.
/// </summary>
public class AdminFunctions : DashboardFunctionBase
{
    /// <summary>
    /// Simple in-memory cooldown to prevent accidental rapid-fire rotation triggers (#20).
    /// Not distributed — applies per instance only.
    /// </summary>
    private static DateTime _lastRotationTrigger = DateTime.MinValue;
    private static readonly TimeSpan RotationCooldown = TimeSpan.FromSeconds(60);

    public AdminFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<AdminFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Create a new SAML certificate for an application
    /// </summary>
    [Function("CreateCertificate")]
    public async Task<HttpResponseData> CreateCertificate(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "applications/{id}/certificate")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

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
                $"New certificate created via dashboard. KeyId: {cert.KeyId}",
                performedBy: GetPerformedBy(identity));

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
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

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
                $"Certificate activated via dashboard. KeyId: {newestCert.KeyId}, Thumbprint: {newestCert.Thumbprint}, Expires: {newestCert.EndDateTime:yyyy-MM-dd}",
                performedBy: GetPerformedBy(identity));

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
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

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

            var appUrl = UrlHelper.BuildEntraManagedAppUrl(app.Id, app.AppId);
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
                activeCert.Thumbprint,
                performedBy: GetPerformedBy(identity));

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
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

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

            var request = JsonSerializer.Deserialize<SponsorUpdateRequest>(body, JsonDeserializeOptions);

            var sponsorEmail = request?.SponsorEmail?.Trim();
            if (string.IsNullOrWhiteSpace(sponsorEmail))
            {
                return await CreateErrorResponse(req, "Sponsor email is required", HttpStatusCode.BadRequest);
            }

            // Validate each email in a semicolon-separated list
            var sponsorEmails = sponsorEmail.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var email in sponsorEmails)
            {
                if (!IsValidEmail(email))
                {
                    return await CreateErrorResponse(req, $"Invalid sponsor email format: {email}", HttpStatusCode.BadRequest);
                }
            }
            // Normalize: trim each part and rejoin
            sponsorEmail = string.Join(";", sponsorEmails);

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
                $"Sponsor updated to AppSponsor={sponsorEmail}",
                performedBy: GetPerformedBy(identity));

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
                ex.Message,
                performedBy: GetPerformedBy(identity));

            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Bulk update sponsors for multiple applications
    /// </summary>
    [Function("BulkUpdateSponsors")]
    public async Task<HttpResponseData> BulkUpdateSponsors(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "applications/bulk-update-sponsors")] HttpRequestData req)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        _logger.LogInformation("Bulk updating sponsors");

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var updates = JsonSerializer.Deserialize<List<BulkSponsorUpdate>>(body, JsonDeserializeOptions);

            if (updates == null || updates.Count == 0)
            {
                return await CreateErrorResponse(req, "No updates provided", HttpStatusCode.BadRequest);
            }

            if (updates.Count > 500)
            {
                return await CreateErrorResponse(req, "Bulk update is limited to 500 items per request", HttpStatusCode.BadRequest);
            }

            var results = new System.Collections.Concurrent.ConcurrentBag<object>();
            var successCount = 0;
            var clearCount = 0;
            var failCount = 0;
            var skippedCount = 0;
            var performedBy = GetPerformedBy(identity);

            // Pre-validate synchronously (fast) to separate invalid entries from valid ones
            var validUpdates = new List<BulkSponsorUpdate>();
            foreach (var update in updates)
            {
                if (string.IsNullOrWhiteSpace(update.ApplicationId) || !IsValidGuid(update.ApplicationId))
                {
                    results.Add(new { applicationId = update.ApplicationId, status = "skipped", reason = "Invalid application ID" });
                    Interlocked.Increment(ref skippedCount);
                    continue;
                }

                var newSponsor = update.SponsorEmail?.Trim() ?? "";
                if (!string.IsNullOrWhiteSpace(newSponsor))
                {
                    // Validate each email in a semicolon-separated list (consistent with single-update endpoints)
                    var emailParts = newSponsor.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    var invalidEmail = emailParts.FirstOrDefault(e => !IsValidEmail(e));
                    if (invalidEmail != null)
                    {
                        results.Add(new { applicationId = update.ApplicationId, status = "skipped", reason = $"Invalid email: {invalidEmail}" });
                        Interlocked.Increment(ref skippedCount);
                        continue;
                    }
                    // Normalize: trim each part and rejoin
                    newSponsor = string.Join(";", emailParts);
                }

                validUpdates.Add(update);
            }

            // Process valid updates concurrently (limit parallelism to avoid Graph throttling)
            await Parallel.ForEachAsync(validUpdates, new ParallelOptions { MaxDegreeOfParallelism = 5 }, async (update, ct) =>
            {
                try
                {
                    var app = await _graphService.GetSamlApplicationAsync(update.ApplicationId!);
                    if (app == null)
                    {
                        results.Add(new { applicationId = update.ApplicationId, status = "skipped", reason = "Application not found" });
                        Interlocked.Increment(ref skippedCount);
                        return;
                    }

                    var newSponsor = update.SponsorEmail?.Trim() ?? "";
                    var currentSponsor = app.Sponsor?.Trim() ?? "";

                    // Skip if no change
                    if (string.Equals(newSponsor, currentSponsor, StringComparison.OrdinalIgnoreCase))
                    {
                        results.Add(new { applicationId = update.ApplicationId, displayName = app.DisplayName, status = "unchanged" });
                        Interlocked.Increment(ref skippedCount);
                        return;
                    }

                    bool updated;
                    if (string.IsNullOrWhiteSpace(newSponsor))
                    {
                        // Clear sponsor
                        updated = await _graphService.ClearAppSponsorTagAsync(update.ApplicationId!);
                        if (updated)
                        {
                            await _auditService.LogSuccessAsync(
                                update.ApplicationId!,
                                app.DisplayName,
                                AuditActionType.SponsorUpdated,
                                $"Sponsor cleared via bulk update (was: {currentSponsor})",
                                performedBy: performedBy);
                            results.Add(new { applicationId = update.ApplicationId, displayName = app.DisplayName, status = "cleared", previousSponsor = currentSponsor });
                            Interlocked.Increment(ref clearCount);
                        }
                        else
                        {
                            results.Add(new { applicationId = update.ApplicationId, displayName = app.DisplayName, status = "failed", reason = "Failed to clear sponsor tag" });
                            Interlocked.Increment(ref failCount);
                        }
                    }
                    else
                    {
                        updated = await _graphService.UpdateAppSponsorTagAsync(update.ApplicationId!, newSponsor);
                        if (updated)
                        {
                            await _auditService.LogSuccessAsync(
                                update.ApplicationId!,
                                app.DisplayName,
                                AuditActionType.SponsorUpdated,
                                $"Sponsor updated via bulk update: {currentSponsor} → {newSponsor}",
                                performedBy: performedBy);
                            results.Add(new { applicationId = update.ApplicationId, displayName = app.DisplayName, status = "updated", previousSponsor = currentSponsor, newSponsor });
                            Interlocked.Increment(ref successCount);
                        }
                        else
                        {
                            results.Add(new { applicationId = update.ApplicationId, displayName = app.DisplayName, status = "failed", reason = "Failed to update sponsor tag" });
                            Interlocked.Increment(ref failCount);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in bulk update for application {Id}", update.ApplicationId);
                    results.Add(new { applicationId = update.ApplicationId, status = "failed", reason = ex.Message });
                    Interlocked.Increment(ref failCount);
                }
            });

            return await CreateJsonResponse(req, new
            {
                message = $"Bulk update complete: {successCount} updated, {clearCount} cleared, {skippedCount} skipped, {failCount} failed",
                updated = successCount,
                cleared = clearCount,
                skipped = skippedCount,
                failed = failCount,
                results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in bulk sponsor update");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Manually trigger certificate rotation in report-only mode.
    /// Route uses rotation/ prefix (not admin/) to avoid conflict with Functions host reserved admin path.
    /// </summary>
    [Function("TriggerRotationReportOnly")]
    public async Task<HttpResponseData> TriggerRotationReportOnly(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "rotation/trigger/report-only")] HttpRequestData req)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        // Rate-limit: Prevent accidental rapid-fire triggers (#20)
        if (DateTime.UtcNow - _lastRotationTrigger < RotationCooldown)
        {
            return await CreateErrorResponse(req, "A rotation was recently triggered. Please wait before trying again.", HttpStatusCode.TooManyRequests);
        }
        _lastRotationTrigger = DateTime.UtcNow;

        _logger.LogInformation("Manual report-only rotation triggered");

        var performedBy = GetPerformedBy(identity);

        try
        {
            var results = await _rotationService.RunRotationAsync(true, performedBy);
            var (successful, skipped, failed) = RotationResult.GetOutcomeCounts(results);

            // Save run report
            var report = new RunReport
            {
                RunDate = DateTime.UtcNow,
                Mode = "report-only",
                TriggeredBy = performedBy ?? "Manual",
                TotalProcessed = results.Count,
                Successful = successful,
                Skipped = skipped,
                Failed = failed,
                ResultsJson = JsonSerializer.Serialize(results.Where(r => r.IsActionable).ToList(), JsonOptions)
            };
            await _reportService.SaveRunReportAsync(report);

            return await CreateJsonResponse(req, new
            {
                message = "Report-only run completed",
                mode = "report-only",
                totalProcessed = results.Count,
                successful,
                skipped,
                failed,
                results = results.Where(r => r.IsActionable).ToList()
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during manual report-only rotation");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Manually trigger certificate rotation in production mode.
    /// Route uses rotation/ prefix (not admin/) to avoid conflict with Functions host reserved admin path.
    /// </summary>
    [Function("TriggerRotationProd")]
    public async Task<HttpResponseData> TriggerRotationProd(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "rotation/trigger/prod")] HttpRequestData req)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        // Rate-limit: Prevent accidental rapid-fire triggers (#20)
        if (DateTime.UtcNow - _lastRotationTrigger < RotationCooldown)
        {
            return await CreateErrorResponse(req, "A rotation was recently triggered. Please wait before trying again.", HttpStatusCode.TooManyRequests);
        }
        _lastRotationTrigger = DateTime.UtcNow;

        _logger.LogInformation("Manual production rotation triggered");

        var performedBy = GetPerformedBy(identity);

        try
        {
            var results = await _rotationService.RunRotationAsync(false, performedBy);
            var (successful, skipped, failed) = RotationResult.GetOutcomeCounts(results);

            // Save run report
            var report = new RunReport
            {
                RunDate = DateTime.UtcNow,
                Mode = "prod",
                TriggeredBy = performedBy ?? "Manual",
                TotalProcessed = results.Count,
                Successful = successful,
                Skipped = skipped,
                Failed = failed,
                ResultsJson = JsonSerializer.Serialize(results.Where(r => r.IsActionable).ToList(), JsonOptions)
            };
            await _reportService.SaveRunReportAsync(report);

            return await CreateJsonResponse(req, new
            {
                message = "Completed production rotation run",
                mode = "prod",
                totalProcessed = results.Count,
                successful,
                skipped,
                failed,
                results = results.Where(r => r.IsActionable).ToList()
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during manual production rotation");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Send a test email using a named template with sample data
    /// </summary>
    [Function("SendTestEmail")]
    public async Task<HttpResponseData> SendTestEmail(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "testing/send-test-email")] HttpRequestData req)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var request = JsonSerializer.Deserialize<TestEmailRequest>(body, JsonDeserializeOptions);

            if (string.IsNullOrWhiteSpace(request?.Template))
            {
                return await CreateErrorResponse(req, "Template name is required", HttpStatusCode.BadRequest);
            }

            if (string.IsNullOrWhiteSpace(request?.ToEmail))
            {
                return await CreateErrorResponse(req, "Recipient email is required", HttpStatusCode.BadRequest);
            }

            if (!IsValidEmail(request.ToEmail))
            {
                return await CreateErrorResponse(req, "Invalid email address format", HttpStatusCode.BadRequest);
            }

            if (!NotificationService.TestTemplateNames.Contains(request.Template))
            {
                return await CreateErrorResponse(req, $"Unknown template: {request.Template}", HttpStatusCode.BadRequest);
            }

            _logger.LogInformation("Sending test email: template={Template}, to={To}", request.Template, request.ToEmail);

            var sent = await _notificationService.SendTestEmailAsync(request.Template, request.ToEmail);

            if (sent)
            {
                await _auditService.LogSuccessAsync(
                    "System",
                    "Test Email",
                    AuditActionType.SettingsUpdated,
                    $"Test email sent: template={request.Template}, to={request.ToEmail}",
                    performedBy: GetPerformedBy(identity));

                return await CreateJsonResponse(req, new { message = "Test email sent successfully", template = request.Template, to = request.ToEmail });
            }
            else
            {
                return await CreateErrorResponse(req, "Failed to send test email. Check Graph API permissions and mail-from configuration.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending test email");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get available test email templates
    /// </summary>
    [Function("GetTestEmailTemplates")]
    public async Task<HttpResponseData> GetTestEmailTemplates(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "testing/email-templates")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        var templates = NotificationService.TestTemplateNames.Select(t => new
        {
            name = t,
            description = t switch
            {
                "CertificateCreated" => "Sent to sponsor when a new certificate is created",
                "CertificateActivated" => "Sent to sponsor when a certificate is activated",
                "Error" => "Sent when a certificate operation fails",
                "DailySummary" => "Daily rotation summary sent to admins",
                "NotifyReminder" => "Expiration reminder for apps marked as Notify",
                "SponsorExpirationExpired" => "Sponsor notification for expired certificate",
                "SponsorExpirationCritical" => "Manual sponsor reminder for critical certificate status",
                "SponsorExpirationWarning" => "Manual sponsor reminder for warning certificate status",
                "ConsolidatedSponsor" => "Consolidated sponsor summary sent after production runs",
                _ => ""
            }
        });

        return await CreateJsonResponse(req, new { templates });
    }
}
