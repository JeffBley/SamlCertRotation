using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
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
    private readonly ILogger<CertificateCheckerFunction> _logger;

    public CertificateCheckerFunction(
        ICertificateRotationService rotationService,
        IPolicyService policyService,
        IAuditService auditService,
        ILogger<CertificateCheckerFunction> logger)
    {
        _rotationService = rotationService;
        _policyService = policyService;
        _auditService = auditService;
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
            var results = await _rotationService.RunRotationAsync();

            var successCount = results.Count(r => r.Success);
            var failureCount = results.Count(r => !r.Success);

            _logger.LogInformation(
                "Certificate checker completed. Processed: {Total}, Success: {Success}, Failed: {Failed}",
                results.Count, successCount, failureCount);

            var retentionPolicyDays = await _policyService.GetRetentionPolicyDaysAsync();
            var purgedCount = await _auditService.PurgeEntriesOlderThanAsync(retentionPolicyDays);
            _logger.LogInformation(
                "Audit retention purge completed. Retention policy: {RetentionDays} day(s), Purged: {PurgedCount}",
                retentionPolicyDays,
                purgedCount);

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
