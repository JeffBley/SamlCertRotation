using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// Timer-triggered function that runs daily to check and rotate SAML certificates
/// </summary>
public class CertificateCheckerFunction
{
    private readonly ICertificateRotationService _rotationService;
    private readonly IPolicyService _policyService;
    private readonly IAuditService _auditService;
    private readonly IReportService _reportService;
    private readonly ILogger<CertificateCheckerFunction> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public CertificateCheckerFunction(
        ICertificateRotationService rotationService,
        IPolicyService policyService,
        IAuditService auditService,
        IReportService reportService,
        ILogger<CertificateCheckerFunction> logger)
    {
        _rotationService = rotationService;
        _policyService = policyService;
        _auditService = auditService;
        _reportService = reportService;
        _logger = logger;
    }

    /// <summary>
    /// Runs on a configurable schedule (default: daily at 6:00 AM UTC) to check certificates and perform rotation.
    /// Configure via the RotationSchedule app setting in Azure Portal.
    /// </summary>
    /// <param name="timerInfo">Timer trigger information</param>
    [Function("CertificateChecker")]
    public async Task Run([TimerTrigger("%RotationSchedule%")] TimerInfo timerInfo)
    {
        _logger.LogInformation("Certificate checker started at: {Time}", DateTime.UtcNow);

        try
        {
            var reportOnlyMode = await _policyService.GetReportOnlyModeEnabledAsync();
            var results = await _rotationService.RunRotationAsync();

            var successCount = results.Count(r => r.Success);
            var failureCount = results.Count(r => !r.Success);

            _logger.LogInformation(
                "Certificate checker completed. Processed: {Total}, Success: {Success}, Failed: {Failed}",
                results.Count, successCount, failureCount);

            // Save run report
            var (successful, skipped, failed) = RotationResult.GetOutcomeCounts(results);
            var report = new RunReport
            {
                RunDate = DateTime.UtcNow,
                Mode = reportOnlyMode ? "report-only" : "prod",
                TriggeredBy = "Scheduled",
                TotalProcessed = results.Count,
                Successful = successful,
                Skipped = skipped,
                Failed = failed,
                ResultsJson = JsonSerializer.Serialize(results.Where(r => r.IsActionable).ToList(), JsonOptions)
            };
            await _reportService.SaveRunReportAsync(report);

            var retentionPolicyDays = await _policyService.GetRetentionPolicyDaysAsync();
            var purgedCount = await _auditService.PurgeEntriesOlderThanAsync(retentionPolicyDays);
            _logger.LogInformation(
                "Audit retention purge completed. Retention policy: {RetentionDays} day(s), Purged: {PurgedCount}",
                retentionPolicyDays,
                purgedCount);

            var reportsRetentionDays = await _policyService.GetReportsRetentionPolicyDaysAsync();
            var purgedReports = await _reportService.PurgeReportsOlderThanAsync(reportsRetentionDays);
            _logger.LogInformation(
                "Reports retention purge completed. Retention policy: {RetentionDays} day(s), Purged: {PurgedCount}",
                reportsRetentionDays,
                purgedReports);

            if (timerInfo.ScheduleStatus != null)
            {
                _logger.LogInformation("Next scheduled run: {NextRun}", timerInfo.ScheduleStatus.Next);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate checker failed");
            throw;
        }
    }
}
