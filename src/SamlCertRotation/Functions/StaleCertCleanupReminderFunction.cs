using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// Timer-triggered function that sends monthly reminder emails to sponsors
/// listing their applications with expired inactive certificates that should be cleaned up.
/// Schedule is driven by the <c>StaleCertCleanupSchedule</c> app setting (default: 1st of every month at 6 AM UTC).
/// </summary>
public class StaleCertCleanupReminderFunction
{
    private readonly IGraphService _graphService;
    private readonly INotificationService _notificationService;
    private readonly IPolicyService _policyService;
    private readonly IAuditService _auditService;
    private readonly ILogger<StaleCertCleanupReminderFunction> _logger;

    public StaleCertCleanupReminderFunction(
        IGraphService graphService,
        INotificationService notificationService,
        IPolicyService policyService,
        IAuditService auditService,
        ILogger<StaleCertCleanupReminderFunction> logger)
    {
        _graphService = graphService;
        _notificationService = notificationService;
        _policyService = policyService;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// Runs on a configurable schedule (default: 1st of every month at 6:00 AM UTC) to send
    /// stale-certificate cleanup reminders to sponsors.
    /// Configure via the StaleCertCleanupSchedule app setting in Azure Portal.
    /// </summary>
    [Function("StaleCertCleanupReminder")]
    public async Task Run([TimerTrigger("%StaleCertCleanupSchedule%")] TimerInfo timerInfo)
    {
        _logger.LogInformation("Stale-cert cleanup reminder started at: {Time}", DateTime.UtcNow);

        try
        {
            // Check if the feature is enabled before making Graph calls
            var enabled = await _policyService.GetStaleCertCleanupRemindersEnabledAsync();
            if (!enabled)
            {
                _logger.LogInformation("Stale-cert cleanup reminders are disabled — exiting early");
                return;
            }

            var apps = await _graphService.GetSamlApplicationsAsync();
            var notifiedApps = await _notificationService.SendStaleCertCleanupRemindersAsync(apps);

            // Audit each app that was included in a cleanup reminder
            foreach (var app in notifiedApps)
            {
                var expiredCount = app.Certificates?.Count(c => !c.IsActive && c.EndDateTime < DateTime.UtcNow) ?? 0;
                await _auditService.LogSuccessAsync(
                    app.Id,
                    app.DisplayName,
                    AuditActionType.StaleCertCleanupReminderSent,
                    $"Stale-cert cleanup reminder sent to sponsor(s). Expired inactive certificates: {expiredCount}.");
            }

            _logger.LogInformation(
                "Stale-cert cleanup reminder completed at: {Time}. Apps notified: {Count}",
                DateTime.UtcNow, notifiedApps.Count);

            if (timerInfo.ScheduleStatus != null)
            {
                _logger.LogInformation("Next scheduled stale-cert cleanup run: {NextRun}", timerInfo.ScheduleStatus.Next);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Stale-cert cleanup reminder failed");
            throw;
        }
    }
}
