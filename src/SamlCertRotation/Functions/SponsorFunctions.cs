using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// HTTP functions for sponsor self-service operations (create cert, activate cert, update policy, update sponsor).
/// </summary>
public class SponsorFunctions : DashboardFunctionBase
{
    public SponsorFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<SponsorFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Create a new SAML certificate for an application (sponsor-accessible when setting is enabled).
    /// </summary>
    [Function("SponsorCreateCertificate")]
    public async Task<HttpResponseData> SponsorCreateCertificate(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "sponsor/applications/{id}/certificate")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, allowSponsor: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        var userEmail = identity?.UserPrincipalName;
        var isAdmin = identity?.Roles.Contains(DashboardRoles.Admin) ?? false;

        // Fetch the app once — reused for both authorization and the operation itself
        var app = await _graphService.GetSamlApplicationAsync(id);
        if (app == null)
        {
            return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
        }

        if (!isAdmin)
        {
            if (!(identity?.Roles.Contains(DashboardRoles.Sponsor) ?? false))
            {
                return await CreateErrorResponse(req, "Sponsor role is required.", HttpStatusCode.Forbidden);
            }

            var sponsorsCanRotate = await _policyService.GetSponsorsCanRotateCertsEnabledAsync();
            if (!sponsorsCanRotate)
            {
                return await CreateErrorResponse(req, "Sponsors are not permitted to create certificates. This feature is disabled.", HttpStatusCode.Forbidden);
            }

            if (!IsSponsorOf(app.Sponsor, userEmail))
            {
                return await CreateErrorResponse(req, "You are not a sponsor of this application.", HttpStatusCode.Forbidden);
            }
        }

        _logger.LogInformation("Sponsor {UserEmail} creating certificate for application {Id}", userEmail, id);

        try
        {
            var cert = await _graphService.CreateSamlCertificateAsync(id);
            if (cert == null)
            {
                return await CreateErrorResponse(req, "Failed to create certificate");
            }

            await _auditService.LogSuccessAsync(
                id,
                app.DisplayName,
                AuditActionType.CertificateCreated,
                $"New certificate created via sponsor portal. KeyId: {cert.KeyId}",
                performedBy: userEmail);

            return await CreateJsonResponse(req, new
            {
                message = "Certificate created successfully",
                certificate = cert
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating certificate for application {Id} by sponsor {UserEmail}", id, userEmail);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Activate the newest certificate for an application (sponsor-accessible when setting is enabled).
    /// </summary>
    [Function("SponsorActivateNewestCertificate")]
    public async Task<HttpResponseData> SponsorActivateNewestCertificate(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "sponsor/applications/{id}/certificate/activate")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, allowSponsor: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        var userEmail = identity?.UserPrincipalName;
        var isAdmin = identity?.Roles.Contains(DashboardRoles.Admin) ?? false;

        // Fetch the app once — reused for both authorization and the operation itself
        var app = await _graphService.GetSamlApplicationAsync(id);
        if (app == null)
        {
            return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
        }

        if (!isAdmin)
        {
            if (!(identity?.Roles.Contains(DashboardRoles.Sponsor) ?? false))
            {
                return await CreateErrorResponse(req, "Sponsor role is required.", HttpStatusCode.Forbidden);
            }

            var sponsorsCanRotate = await _policyService.GetSponsorsCanRotateCertsEnabledAsync();
            if (!sponsorsCanRotate)
            {
                return await CreateErrorResponse(req, "Sponsors are not permitted to activate certificates. This feature is disabled.", HttpStatusCode.Forbidden);
            }

            if (!IsSponsorOf(app.Sponsor, userEmail))
            {
                return await CreateErrorResponse(req, "You are not a sponsor of this application.", HttpStatusCode.Forbidden);
            }
        }

        _logger.LogInformation("Sponsor {UserEmail} activating newest certificate for application {Id}", userEmail, id);

        try
        {
            if (app.Certificates == null || !app.Certificates.Any())
            {
                return await CreateErrorResponse(req, "No certificates found for this application", HttpStatusCode.BadRequest);
            }

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
                $"Certificate activated via sponsor portal. KeyId: {newestCert.KeyId}, Thumbprint: {newestCert.Thumbprint}, Expires: {newestCert.EndDateTime:yyyy-MM-dd}",
                performedBy: userEmail);

            return await CreateJsonResponse(req, new
            {
                message = "Certificate activated successfully",
                activatedKeyId = newestCert.KeyId
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error activating certificate for application {Id} by sponsor {UserEmail}", id, userEmail);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Update app policy (sponsor-accessible when setting is enabled).
    /// </summary>
    [Function("SponsorUpdateAppPolicy")]
    public async Task<HttpResponseData> SponsorUpdateAppPolicy(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "sponsor/applications/{id}/policy")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, allowSponsor: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        var userEmail = identity?.UserPrincipalName;
        var isAdmin = identity?.Roles.Contains(DashboardRoles.Admin) ?? false;

        if (!isAdmin)
        {
            if (!(identity?.Roles.Contains(DashboardRoles.Sponsor) ?? false))
            {
                return await CreateErrorResponse(req, "Sponsor role is required.", HttpStatusCode.Forbidden);
            }

            var sponsorsCanUpdatePolicy = await _policyService.GetSponsorsCanUpdatePolicyEnabledAsync();
            if (!sponsorsCanUpdatePolicy)
            {
                return await CreateErrorResponse(req, "Sponsors are not permitted to update policies. This feature is disabled.", HttpStatusCode.Forbidden);
            }

            var app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
            }

            if (!IsSponsorOf(app.Sponsor, userEmail))
            {
                return await CreateErrorResponse(req, "You are not a sponsor of this application.", HttpStatusCode.Forbidden);
            }
        }

        _logger.LogInformation("Sponsor {UserEmail} updating policy for application {Id}", userEmail, id);

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrEmpty(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var policy = JsonSerializer.Deserialize<AppPolicy>(body, JsonDeserializeOptions);
            if (policy == null)
            {
                return await CreateErrorResponse(req, "Invalid policy format", HttpStatusCode.BadRequest);
            }

            var policyValidationError = ValidateAppPolicyValues(policy);
            if (policyValidationError != null)
            {
                return await CreateErrorResponse(req, policyValidationError, HttpStatusCode.BadRequest);
            }

            policy.RowKey = id;

            var beforePolicy = await _policyService.GetAppPolicyAsync(id);

            var success = await _policyService.UpsertAppPolicyAsync(policy);

            if (success)
            {
                var changes = new List<string>();
                var beforeCreate = beforePolicy?.CreateCertDaysBeforeExpiry;
                var beforeActivate = beforePolicy?.ActivateCertDaysBeforeExpiry;
                var beforeAdditionalEmails = beforePolicy?.AdditionalNotificationEmails ?? "";
                var beforeNotifyOverride = beforePolicy?.CreateCertsForNotifyOverride;

                if (policy.CreateCertDaysBeforeExpiry != beforeCreate)
                    changes.Add($"CreateCertDaysBeforeExpiry: {beforeCreate?.ToString() ?? "global default"} → {policy.CreateCertDaysBeforeExpiry?.ToString() ?? "global default"}");
                if (policy.ActivateCertDaysBeforeExpiry != beforeActivate)
                    changes.Add($"ActivateCertDaysBeforeExpiry: {beforeActivate?.ToString() ?? "global default"} → {policy.ActivateCertDaysBeforeExpiry?.ToString() ?? "global default"}");
                if ((policy.AdditionalNotificationEmails ?? "") != beforeAdditionalEmails)
                    changes.Add($"AdditionalNotificationEmails: \"{beforeAdditionalEmails}\" → \"{policy.AdditionalNotificationEmails ?? ""}\"");
                if (policy.CreateCertsForNotifyOverride != beforeNotifyOverride)
                {
                    string FormatOverride(bool? v) => v switch { true => "Enabled", false => "Disabled", null => "Default (Global)" };
                    changes.Add($"CreateCertsForNotifyOverride: {FormatOverride(beforeNotifyOverride)} → {FormatOverride(policy.CreateCertsForNotifyOverride)}");
                }

                if (changes.Count > 0)
                {
                    await _auditService.LogSuccessAsync(
                        id,
                        policy.AppDisplayName ?? id,
                        AuditActionType.SettingsUpdated,
                        $"Policy updated via sponsor portal. {string.Join("; ", changes)}",
                        performedBy: userEmail);
                }

                return await CreateJsonResponse(req, new { message = "App policy updated successfully" });
            }
            else
            {
                return await CreateErrorResponse(req, "Failed to update app policy");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating app policy for {Id} by sponsor {UserEmail}", id, userEmail);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Update sponsor for an application (sponsor-accessible when setting is enabled).
    /// </summary>
    [Function("SponsorUpdateSponsor")]
    public async Task<HttpResponseData> SponsorUpdateSponsor(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "sponsor/applications/{id}/sponsor")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, allowSponsor: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        var userEmail = identity?.UserPrincipalName;
        var isAdmin = identity?.Roles.Contains(DashboardRoles.Admin) ?? false;

        // Fetch the app once — reused for both authorization and the operation itself
        var app = await _graphService.GetSamlApplicationAsync(id);
        if (app == null)
        {
            return await CreateErrorResponse(req, "Application not found", HttpStatusCode.NotFound);
        }

        if (!isAdmin)
        {
            if (!(identity?.Roles.Contains(DashboardRoles.Sponsor) ?? false))
            {
                return await CreateErrorResponse(req, "Sponsor role is required.", HttpStatusCode.Forbidden);
            }

            var sponsorsCanEditSponsors = await _policyService.GetSponsorsCanEditSponsorsEnabledAsync();
            if (!sponsorsCanEditSponsors)
            {
                return await CreateErrorResponse(req, "Sponsors are not permitted to edit sponsors. This feature is disabled.", HttpStatusCode.Forbidden);
            }

            if (!IsSponsorOf(app.Sponsor, userEmail))
            {
                return await CreateErrorResponse(req, "You are not a sponsor of this application.", HttpStatusCode.Forbidden);
            }
        }

        _logger.LogInformation("Sponsor {UserEmail} updating sponsor for application {Id}", userEmail, id);

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

            var updated = await _graphService.UpdateAppSponsorTagAsync(id, sponsorEmail);
            if (!updated)
            {
                return await CreateErrorResponse(req, "Failed to update sponsor tag");
            }

            await _auditService.LogSuccessAsync(
                id,
                app.DisplayName,
                AuditActionType.SponsorUpdated,
                $"Sponsor updated via sponsor portal. AppSponsor={sponsorEmail}",
                performedBy: userEmail);

            return await CreateJsonResponse(req, new
            {
                message = "Sponsor updated successfully",
                sponsor = sponsorEmail
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating sponsor for application {Id} by sponsor {UserEmail}", id, userEmail);

            await _auditService.LogFailureAsync(
                id,
                app.DisplayName,
                AuditActionType.SponsorUpdated,
                "Error updating sponsor via sponsor portal",
                ex.Message,
                performedBy: userEmail);

            return await CreateErrorResponse(req, ex.Message);
        }
    }
}
