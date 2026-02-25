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
/// HTTP functions for run report retrieval.
/// </summary>
public class ReportFunctions : DashboardFunctionBase
{
    public ReportFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<ReportFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Get all run reports within the configured retention window.
    /// Returns a list of report summaries (without per-app detail).
    /// </summary>
    [Function("GetRunReports")]
    public async Task<HttpResponseData> GetRunReports(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "reports")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

        try
        {
            var retentionDays = await _policyService.GetReportsRetentionPolicyDaysAsync();
            var reports = await _reportService.GetRunReportsAsync(retentionDays);

            // Return summaries without the full ResultsJson
            var summaries = reports.Select(r => new
            {
                id = r.RowKey,
                runDate = r.RunDate,
                mode = r.Mode,
                triggeredBy = r.TriggeredBy,
                totalProcessed = r.TotalProcessed,
                successful = r.Successful,
                skipped = r.Skipped,
                failed = r.Failed
            });

            return await CreateJsonResponse(req, summaries);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting run reports");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get a single run report with full per-app detail.
    /// </summary>
    [Function("GetRunReport")]
    public async Task<HttpResponseData> GetRunReport(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "reports/{id}")] HttpRequestData req,
        string id)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid report ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var report = await _reportService.GetRunReportAsync(id);
            if (report == null)
            {
                return await CreateErrorResponse(req, "Report not found", HttpStatusCode.NotFound);
            }

            // Deserialize the results JSON for the response
            var results = JsonSerializer.Deserialize<List<RotationResult>>(report.ResultsJson, JsonOptions)
                ?? new List<RotationResult>();

            return await CreateJsonResponse(req, new
            {
                id = report.RowKey,
                runDate = report.RunDate,
                mode = report.Mode,
                triggeredBy = report.TriggeredBy,
                totalProcessed = report.TotalProcessed,
                successful = report.Successful,
                skipped = report.Skipped,
                failed = report.Failed,
                results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting run report {Id}", id);
            return await CreateErrorResponse(req, ex.Message);
        }
    }
}
