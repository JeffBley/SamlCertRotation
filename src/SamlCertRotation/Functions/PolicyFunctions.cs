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
/// HTTP functions for global and per-app policy management.
/// </summary>
public class PolicyFunctions : DashboardFunctionBase
{
    public PolicyFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<PolicyFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Get global policy
    /// </summary>
    [Function("GetGlobalPolicy")]
    public async Task<HttpResponseData> GetGlobalPolicy(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

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
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        _logger.LogInformation("Updating global policy");

        try
        {
            var body = await req.ReadAsStringAsync();
            if (string.IsNullOrEmpty(body))
            {
                return await CreateErrorResponse(req, "Request body is required", HttpStatusCode.BadRequest);
            }

            var policy = JsonSerializer.Deserialize<RotationPolicy>(body, JsonDeserializeOptions);
            if (policy == null)
            {
                return await CreateErrorResponse(req, "Invalid policy format", HttpStatusCode.BadRequest);
            }

            // Snapshot current values before applying changes
            var beforePolicy = await _policyService.GetGlobalPolicyAsync();

            var success = await _policyService.UpdateGlobalPolicyAsync(policy);
            if (success)
            {
                var changes = new List<string>();
                if (policy.CreateCertDaysBeforeExpiry != beforePolicy.CreateCertDaysBeforeExpiry)
                    changes.Add($"CreateCertDaysBeforeExpiry: {beforePolicy.CreateCertDaysBeforeExpiry} → {policy.CreateCertDaysBeforeExpiry}");
                if (policy.ActivateCertDaysBeforeExpiry != beforePolicy.ActivateCertDaysBeforeExpiry)
                    changes.Add($"ActivateCertDaysBeforeExpiry: {beforePolicy.ActivateCertDaysBeforeExpiry} → {policy.ActivateCertDaysBeforeExpiry}");
                if (policy.IsEnabled != beforePolicy.IsEnabled)
                    changes.Add($"IsEnabled: {beforePolicy.IsEnabled} → {policy.IsEnabled}");

                if (changes.Count > 0)
                {
                    await _auditService.LogSuccessAsync(
                        "SYSTEM",
                        "Global Policy",
                        AuditActionType.SettingsUpdated,
                        string.Join("; ", changes),
                        performedBy: GetPerformedBy(identity));
                }

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
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

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
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

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

            // Snapshot current values before applying changes
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
                        string.Join("; ", changes),
                        performedBy: GetPerformedBy(identity));
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
            _logger.LogError(ex, "Error updating app policy");
            return await CreateErrorResponse(req, ex.Message);
        }
    }
}
