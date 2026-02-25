using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// HTTP functions for audit log retrieval.
/// </summary>
public class AuditFunctions : DashboardFunctionBase
{
    public AuditFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<AuditFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Get audit logs
    /// </summary>
    [Function("GetAuditLogs")]
    public async Task<HttpResponseData> GetAuditLogs(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "audit")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

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
                days = Math.Clamp(days, 1, 365);
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
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

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
}
