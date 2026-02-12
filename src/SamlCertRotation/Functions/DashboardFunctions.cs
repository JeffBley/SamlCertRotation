using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
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
    private readonly ILogger<DashboardFunctions> _logger;

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
        ILogger<DashboardFunctions> logger)
    {
        _rotationService = rotationService;
        _graphService = graphService;
        _policyService = policyService;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// Get dashboard statistics
    /// </summary>
    [Function("GetDashboardStats")]
    public async Task<HttpResponseData> GetDashboardStats(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "dashboard/stats")] HttpRequestData req)
    {
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
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "applications")] HttpRequestData req)
    {
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
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "applications/{id}")] HttpRequestData req,
        string id)
    {
        _logger.LogInformation("Getting application {Id}", id);

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
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "policy")] HttpRequestData req)
    {
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
        [HttpTrigger(AuthorizationLevel.Function, "put", Route = "policy")] HttpRequestData req)
    {
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
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "policy/app/{id}")] HttpRequestData req,
        string id)
    {
        _logger.LogInformation("Getting app policy for {Id}", id);

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
        [HttpTrigger(AuthorizationLevel.Function, "put", Route = "policy/app/{id}")] HttpRequestData req,
        string id)
    {
        _logger.LogInformation("Updating app policy for {Id}", id);

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
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "audit")] HttpRequestData req)
    {
        _logger.LogInformation("Getting audit logs");

        try
        {
            var daysParam = req.Query["days"];
            var days = int.TryParse(daysParam, out var d) ? d : 7;

            var entries = await _auditService.GetEntriesAsync(
                DateTime.UtcNow.AddDays(-days), 
                DateTime.UtcNow);

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
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "audit/app/{id}")] HttpRequestData req,
        string id)
    {
        _logger.LogInformation("Getting audit logs for app {Id}", id);

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
    /// Manually trigger certificate rotation (admin endpoint)
    /// </summary>
    [Function("TriggerRotation")]
    public async Task<HttpResponseData> TriggerRotation(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "admin/trigger-rotation")] HttpRequestData req)
    {
        _logger.LogInformation("Manual rotation triggered");

        try
        {
            var results = await _rotationService.RunRotationAsync();
            return await CreateJsonResponse(req, new
            {
                message = "Rotation completed",
                totalProcessed = results.Count,
                successful = results.Count(r => r.Success),
                failed = results.Count(r => !r.Success),
                results = results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during manual rotation");
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
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(new { error = message }, JsonOptions));
        return response;
    }
}
