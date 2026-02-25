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
/// HTTP functions for reading and updating application settings.
/// </summary>
public class SettingsFunctions : DashboardFunctionBase
{
    public SettingsFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<SettingsFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Get application settings
    /// </summary>
    [Function("GetSettings")]
    public async Task<HttpResponseData> GetSettings(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "settings")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

        _logger.LogInformation("Getting settings");

        try
        {
            // Fetch all settings in parallel for better performance
            var notificationEmailsTask = _policyService.GetNotificationEmailsAsync();
            var reportOnlyModeEnabledTask = _policyService.GetReportOnlyModeEnabledAsync();
            var retentionPolicyDaysTask = _policyService.GetRetentionPolicyDaysAsync();
            var sponsorsReceiveNotificationsTask = _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
            var notifySponsorsOnExpirationTask = _policyService.GetNotifySponsorsOnExpirationEnabledAsync();
            var sponsorRemindersEnabledTask = _policyService.GetSponsorRemindersEnabledAsync();
            var sponsorReminderCountTask = _policyService.GetSponsorReminderCountAsync();
            var sponsorReminderDaysTask = _policyService.GetSponsorReminderDaysAsync();
            var sessionTimeoutMinutesTask = _policyService.GetSessionTimeoutMinutesAsync();
            var createCertsForNotifyAppsTask = _policyService.GetCreateCertsForNotifyAppsEnabledAsync();
            var reportsRetentionPolicyDaysTask = _policyService.GetReportsRetentionPolicyDaysAsync();
            var sponsorsCanRotateCertsTask = _policyService.GetSponsorsCanRotateCertsEnabledAsync();
            var sponsorsCanUpdatePolicyTask = _policyService.GetSponsorsCanUpdatePolicyEnabledAsync();
            var sponsorsCanEditSponsorsTask = _policyService.GetSponsorsCanEditSponsorsEnabledAsync();
            var staleCertCleanupRemindersTask = _policyService.GetStaleCertCleanupRemindersEnabledAsync();

            await Task.WhenAll(
                notificationEmailsTask, reportOnlyModeEnabledTask, retentionPolicyDaysTask,
                sponsorsReceiveNotificationsTask, notifySponsorsOnExpirationTask,
                sponsorRemindersEnabledTask, sponsorReminderCountTask, sponsorReminderDaysTask,
                sessionTimeoutMinutesTask, createCertsForNotifyAppsTask, reportsRetentionPolicyDaysTask,
                sponsorsCanRotateCertsTask, sponsorsCanUpdatePolicyTask, sponsorsCanEditSponsorsTask,
                staleCertCleanupRemindersTask);

            var notificationEmails = notificationEmailsTask.Result;
            if (string.IsNullOrWhiteSpace(notificationEmails))
            {
                notificationEmails = _configuration["AdminNotificationEmails"] ?? "";
            }

            var sponsorReminderDays = sponsorReminderDaysTask.Result;

            var settings = new
            {
                notificationEmails,
                tenantId = _configuration["TenantId"] ?? "",
                rotationSchedule = _configuration["RotationSchedule"] ?? "0 0 6 * * *",
                reportOnlyModeEnabled = reportOnlyModeEnabledTask.Result,
                retentionPolicyDays = retentionPolicyDaysTask.Result,
                sponsorsReceiveNotifications = sponsorsReceiveNotificationsTask.Result,
                notifySponsorsOnExpiration = notifySponsorsOnExpirationTask.Result,
                sponsorRemindersEnabled = sponsorRemindersEnabledTask.Result,
                sponsorReminderCount = sponsorReminderCountTask.Result,
                sponsorFirstReminderDays = sponsorReminderDays.firstReminderDays,
                sponsorSecondReminderDays = sponsorReminderDays.secondReminderDays,
                sponsorThirdReminderDays = sponsorReminderDays.thirdReminderDays,
                sessionTimeoutMinutes = sessionTimeoutMinutesTask.Result,
                createCertsForNotifyApps = createCertsForNotifyAppsTask.Result,
                reportsRetentionPolicyDays = reportsRetentionPolicyDaysTask.Result,
                sponsorsCanRotateCerts = sponsorsCanRotateCertsTask.Result,
                sponsorsCanUpdatePolicy = sponsorsCanUpdatePolicyTask.Result,
                sponsorsCanEditSponsors = sponsorsCanEditSponsorsTask.Result,
                staleCertCleanupRemindersEnabled = staleCertCleanupRemindersTask.Result,
                staleCertCleanupSchedule = _configuration["StaleCertCleanupSchedule"] ?? "0 0 6 1 * *"
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
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        _logger.LogInformation("Updating settings");

        try
        {
            var body = await req.ReadAsStringAsync();
            var settings = JsonSerializer.Deserialize<SettingsUpdateRequest>(body ?? "{}", JsonDeserializeOptions);

            if (settings == null)
            {
                return await CreateErrorResponse(req, "Invalid settings data", HttpStatusCode.BadRequest);
            }

            // ── Validate ALL inputs BEFORE writing anything ──
            // This prevents partial state when a later validation fails.
            var rawEmails = settings.NotificationEmails ?? "";
            if (!string.IsNullOrWhiteSpace(rawEmails))
            {
                var emailParts = rawEmails.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var emailPart in emailParts)
                {
                    var trimmed = emailPart.Trim();
                    if (!IsValidEmail(trimmed))
                    {
                        return await CreateErrorResponse(req, $"Invalid notification email address: {trimmed}", HttpStatusCode.BadRequest);
                    }
                }
            }

            if (settings.RetentionPolicyDays.HasValue && settings.RetentionPolicyDays.Value < 1)
            {
                return await CreateErrorResponse(req, "Retention policy must be at least 1 day", HttpStatusCode.BadRequest);
            }

            if (settings.SponsorReminderCount.HasValue && (settings.SponsorReminderCount.Value < 1 || settings.SponsorReminderCount.Value > 3))
            {
                return await CreateErrorResponse(req, "Sponsor reminder count must be between 1 and 3", HttpStatusCode.BadRequest);
            }

            // Cache validated reminder days to avoid re-fetching during the write phase
            (int first, int second, int third)? validatedReminderDays = null;
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

                validatedReminderDays = (firstReminderDays, secondReminderDays, thirdReminderDays);
            }

            if (settings.SessionTimeoutMinutes.HasValue && settings.SessionTimeoutMinutes.Value < 0)
            {
                return await CreateErrorResponse(req, "Session timeout must be 0 (disabled) or a positive number", HttpStatusCode.BadRequest);
            }

            if (settings.ReportsRetentionPolicyDays.HasValue && settings.ReportsRetentionPolicyDays.Value < 1)
            {
                return await CreateErrorResponse(req, "Reports retention policy must be at least 1 day", HttpStatusCode.BadRequest);
            }

            // ── Snapshot current values before applying changes (parallel) ──
            var beforeEmailsTask = _policyService.GetNotificationEmailsAsync();
            var beforeReportOnlyTask = _policyService.GetReportOnlyModeEnabledAsync();
            var beforeRetentionTask = _policyService.GetRetentionPolicyDaysAsync();
            var beforeSponsorsNotifyTask = _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
            var beforeNotifyOnExpirationTask = _policyService.GetNotifySponsorsOnExpirationEnabledAsync();
            var beforeRemindersEnabledTask = _policyService.GetSponsorRemindersEnabledAsync();
            var beforeReminderCountTask = _policyService.GetSponsorReminderCountAsync();
            var beforeRemindersTask = _policyService.GetSponsorReminderDaysAsync();
            var beforeTimeoutTask = _policyService.GetSessionTimeoutMinutesAsync();
            var beforeCreateCertsForNotifyTask = _policyService.GetCreateCertsForNotifyAppsEnabledAsync();
            var beforeReportsRetentionTask = _policyService.GetReportsRetentionPolicyDaysAsync();
            var beforeSponsorsCanRotateCertsTask = _policyService.GetSponsorsCanRotateCertsEnabledAsync();
            var beforeSponsorsCanUpdatePolicyTask = _policyService.GetSponsorsCanUpdatePolicyEnabledAsync();
            var beforeSponsorsCanEditSponsorsTask = _policyService.GetSponsorsCanEditSponsorsEnabledAsync();
            var beforeStaleCertCleanupTask = _policyService.GetStaleCertCleanupRemindersEnabledAsync();

            await Task.WhenAll(
                beforeEmailsTask, beforeReportOnlyTask, beforeRetentionTask,
                beforeSponsorsNotifyTask, beforeNotifyOnExpirationTask,
                beforeRemindersEnabledTask, beforeReminderCountTask, beforeRemindersTask,
                beforeTimeoutTask, beforeCreateCertsForNotifyTask, beforeReportsRetentionTask,
                beforeSponsorsCanRotateCertsTask, beforeSponsorsCanUpdatePolicyTask, beforeSponsorsCanEditSponsorsTask,
                beforeStaleCertCleanupTask);

            var beforeEmails = beforeEmailsTask.Result;
            var beforeReportOnly = beforeReportOnlyTask.Result;
            var beforeRetention = beforeRetentionTask.Result;
            var beforeSponsorsNotify = beforeSponsorsNotifyTask.Result;
            var beforeNotifyOnExpiration = beforeNotifyOnExpirationTask.Result;
            var beforeRemindersEnabled = beforeRemindersEnabledTask.Result;
            var beforeReminderCount = beforeReminderCountTask.Result;
            var beforeReminders = beforeRemindersTask.Result;
            var beforeTimeout = beforeTimeoutTask.Result;
            var beforeCreateCertsForNotify = beforeCreateCertsForNotifyTask.Result;
            var beforeReportsRetention = beforeReportsRetentionTask.Result;
            var beforeSponsorsCanRotateCerts = beforeSponsorsCanRotateCertsTask.Result;
            var beforeSponsorsCanUpdatePolicy = beforeSponsorsCanUpdatePolicyTask.Result;
            var beforeSponsorsCanEditSponsors = beforeSponsorsCanEditSponsorsTask.Result;
            var beforeStaleCertCleanup = beforeStaleCertCleanupTask.Result;

            // ── All validation passed — now apply writes ──
            await _policyService.UpdateNotificationEmailsAsync(rawEmails);

            if (settings.ReportOnlyModeEnabled.HasValue)
            {
                await _policyService.UpdateReportOnlyModeEnabledAsync(settings.ReportOnlyModeEnabled.Value);
            }

            if (settings.RetentionPolicyDays.HasValue)
            {
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

            if (settings.SponsorRemindersEnabled.HasValue)
            {
                await _policyService.UpdateSponsorRemindersEnabledAsync(settings.SponsorRemindersEnabled.Value);
            }

            if (settings.SponsorReminderCount.HasValue)
            {
                await _policyService.UpdateSponsorReminderCountAsync(settings.SponsorReminderCount.Value);
            }

            if (validatedReminderDays.HasValue)
            {
                await _policyService.UpdateSponsorReminderDaysAsync(
                    validatedReminderDays.Value.first,
                    validatedReminderDays.Value.second,
                    validatedReminderDays.Value.third);
            }

            if (settings.SessionTimeoutMinutes.HasValue)
            {
                await _policyService.UpdateSessionTimeoutMinutesAsync(settings.SessionTimeoutMinutes.Value);
            }

            if (settings.CreateCertsForNotifyApps.HasValue)
            {
                await _policyService.UpdateCreateCertsForNotifyAppsEnabledAsync(settings.CreateCertsForNotifyApps.Value);
            }

            if (settings.ReportsRetentionPolicyDays.HasValue)
            {
                await _policyService.UpdateReportsRetentionPolicyDaysAsync(settings.ReportsRetentionPolicyDays.Value);
            }

            if (settings.SponsorsCanRotateCerts.HasValue)
            {
                await _policyService.UpdateSponsorsCanRotateCertsEnabledAsync(settings.SponsorsCanRotateCerts.Value);
            }

            if (settings.SponsorsCanUpdatePolicy.HasValue)
            {
                await _policyService.UpdateSponsorsCanUpdatePolicyEnabledAsync(settings.SponsorsCanUpdatePolicy.Value);
            }

            if (settings.SponsorsCanEditSponsors.HasValue)
            {
                await _policyService.UpdateSponsorsCanEditSponsorsEnabledAsync(settings.SponsorsCanEditSponsors.Value);
            }

            if (settings.StaleCertCleanupRemindersEnabled.HasValue)
            {
                await _policyService.UpdateStaleCertCleanupRemindersEnabledAsync(settings.StaleCertCleanupRemindersEnabled.Value);
            }

            // ── Read back updated values (parallel) ──
            var reportOnlyModeEnabledTask2 = _policyService.GetReportOnlyModeEnabledAsync();
            var retentionPolicyDaysTask2 = _policyService.GetRetentionPolicyDaysAsync();
            var sponsorsReceiveNotificationsTask2 = _policyService.GetSponsorsReceiveNotificationsEnabledAsync();
            var notifySponsorsOnExpirationTask2 = _policyService.GetNotifySponsorsOnExpirationEnabledAsync();
            var sponsorRemindersEnabledTask2 = _policyService.GetSponsorRemindersEnabledAsync();
            var sponsorReminderCountTask2 = _policyService.GetSponsorReminderCountAsync();
            var sponsorReminderDaysTask2 = _policyService.GetSponsorReminderDaysAsync();
            var sessionTimeoutMinutesTask2 = _policyService.GetSessionTimeoutMinutesAsync();
            var createCertsForNotifyAppsTask2 = _policyService.GetCreateCertsForNotifyAppsEnabledAsync();
            var reportsRetentionPolicyDaysTask2 = _policyService.GetReportsRetentionPolicyDaysAsync();
            var sponsorsCanRotateCertsTask2 = _policyService.GetSponsorsCanRotateCertsEnabledAsync();
            var sponsorsCanUpdatePolicyTask2 = _policyService.GetSponsorsCanUpdatePolicyEnabledAsync();
            var sponsorsCanEditSponsorsTask2 = _policyService.GetSponsorsCanEditSponsorsEnabledAsync();
            var staleCertCleanupRemindersTask2 = _policyService.GetStaleCertCleanupRemindersEnabledAsync();

            await Task.WhenAll(
                reportOnlyModeEnabledTask2, retentionPolicyDaysTask2,
                sponsorsReceiveNotificationsTask2, notifySponsorsOnExpirationTask2,
                sponsorRemindersEnabledTask2, sponsorReminderCountTask2, sponsorReminderDaysTask2,
                sessionTimeoutMinutesTask2, createCertsForNotifyAppsTask2, reportsRetentionPolicyDaysTask2,
                sponsorsCanRotateCertsTask2, sponsorsCanUpdatePolicyTask2, sponsorsCanEditSponsorsTask2,
                staleCertCleanupRemindersTask2);

            var reportOnlyModeEnabled = reportOnlyModeEnabledTask2.Result;
            var retentionPolicyDays = retentionPolicyDaysTask2.Result;
            var sponsorsReceiveNotifications = sponsorsReceiveNotificationsTask2.Result;
            var notifySponsorsOnExpiration = notifySponsorsOnExpirationTask2.Result;
            var sponsorRemindersEnabled = sponsorRemindersEnabledTask2.Result;
            var sponsorReminderCount = sponsorReminderCountTask2.Result;
            var sponsorReminderDays = sponsorReminderDaysTask2.Result;
            var sessionTimeoutMinutes = sessionTimeoutMinutesTask2.Result;
            var createCertsForNotifyApps = createCertsForNotifyAppsTask2.Result;
            var reportsRetentionPolicyDays = reportsRetentionPolicyDaysTask2.Result;
            var sponsorsCanRotateCerts = sponsorsCanRotateCertsTask2.Result;
            var sponsorsCanUpdatePolicy = sponsorsCanUpdatePolicyTask2.Result;
            var sponsorsCanEditSponsors = sponsorsCanEditSponsorsTask2.Result;
            var staleCertCleanupRemindersEnabled = staleCertCleanupRemindersTask2.Result;

            // Build list of changed fields
            var changes = new List<string>();
            if ((settings.NotificationEmails ?? "") != beforeEmails)
                changes.Add($"NotificationEmails: \"{beforeEmails}\" → \"{settings.NotificationEmails ?? ""}\"");
            if (settings.ReportOnlyModeEnabled.HasValue && settings.ReportOnlyModeEnabled.Value != beforeReportOnly)
                changes.Add($"ReportOnlyMode: {beforeReportOnly} → {settings.ReportOnlyModeEnabled.Value}");
            if (settings.RetentionPolicyDays.HasValue && settings.RetentionPolicyDays.Value != beforeRetention)
                changes.Add($"RetentionPolicyDays: {beforeRetention} → {settings.RetentionPolicyDays.Value}");
            if (settings.SponsorsReceiveNotifications.HasValue && settings.SponsorsReceiveNotifications.Value != beforeSponsorsNotify)
                changes.Add($"SponsorsReceiveNotifications: {beforeSponsorsNotify} → {settings.SponsorsReceiveNotifications.Value}");
            if (settings.NotifySponsorsOnExpiration.HasValue && settings.NotifySponsorsOnExpiration.Value != beforeNotifyOnExpiration)
                changes.Add($"NotifySponsorsOnExpiration: {beforeNotifyOnExpiration} → {settings.NotifySponsorsOnExpiration.Value}");
            if (settings.SponsorRemindersEnabled.HasValue && settings.SponsorRemindersEnabled.Value != beforeRemindersEnabled)
                changes.Add($"SponsorRemindersEnabled: {beforeRemindersEnabled} → {settings.SponsorRemindersEnabled.Value}");
            if (settings.SponsorReminderCount.HasValue && settings.SponsorReminderCount.Value != beforeReminderCount)
                changes.Add($"SponsorReminderCount: {beforeReminderCount} → {settings.SponsorReminderCount.Value}");
            if (settings.SponsorFirstReminderDays.HasValue && settings.SponsorFirstReminderDays.Value != beforeReminders.firstReminderDays)
                changes.Add($"SponsorFirstReminderDays: {beforeReminders.firstReminderDays} → {settings.SponsorFirstReminderDays.Value}");
            if (settings.SponsorSecondReminderDays.HasValue && settings.SponsorSecondReminderDays.Value != beforeReminders.secondReminderDays)
                changes.Add($"SponsorSecondReminderDays: {beforeReminders.secondReminderDays} → {settings.SponsorSecondReminderDays.Value}");
            if (settings.SponsorThirdReminderDays.HasValue && settings.SponsorThirdReminderDays.Value != beforeReminders.thirdReminderDays)
                changes.Add($"SponsorThirdReminderDays: {beforeReminders.thirdReminderDays} → {settings.SponsorThirdReminderDays.Value}");
            if (settings.SessionTimeoutMinutes.HasValue && settings.SessionTimeoutMinutes.Value != beforeTimeout)
                changes.Add($"SessionTimeoutMinutes: {beforeTimeout} → {settings.SessionTimeoutMinutes.Value}");
            if (settings.CreateCertsForNotifyApps.HasValue && settings.CreateCertsForNotifyApps.Value != beforeCreateCertsForNotify)
                changes.Add($"CreateCertsForNotifyApps: {beforeCreateCertsForNotify} → {settings.CreateCertsForNotifyApps.Value}");
            if (settings.ReportsRetentionPolicyDays.HasValue && settings.ReportsRetentionPolicyDays.Value != beforeReportsRetention)
                changes.Add($"ReportsRetentionPolicyDays: {beforeReportsRetention} → {settings.ReportsRetentionPolicyDays.Value}");
            if (settings.SponsorsCanRotateCerts.HasValue && settings.SponsorsCanRotateCerts.Value != beforeSponsorsCanRotateCerts)
                changes.Add($"SponsorsCanRotateCerts: {beforeSponsorsCanRotateCerts} → {settings.SponsorsCanRotateCerts.Value}");
            if (settings.SponsorsCanUpdatePolicy.HasValue && settings.SponsorsCanUpdatePolicy.Value != beforeSponsorsCanUpdatePolicy)
                changes.Add($"SponsorsCanUpdatePolicy: {beforeSponsorsCanUpdatePolicy} → {settings.SponsorsCanUpdatePolicy.Value}");
            if (settings.SponsorsCanEditSponsors.HasValue && settings.SponsorsCanEditSponsors.Value != beforeSponsorsCanEditSponsors)
                changes.Add($"SponsorsCanEditSponsors: {beforeSponsorsCanEditSponsors} → {settings.SponsorsCanEditSponsors.Value}");
            if (settings.StaleCertCleanupRemindersEnabled.HasValue && settings.StaleCertCleanupRemindersEnabled.Value != beforeStaleCertCleanup)
                changes.Add($"StaleCertCleanupReminders: {beforeStaleCertCleanup} → {settings.StaleCertCleanupRemindersEnabled.Value}");

            if (changes.Count > 0)
            {
                await _auditService.LogSuccessAsync(
                    "SYSTEM",
                    "Settings",
                    AuditActionType.SettingsUpdated,
                    string.Join("; ", changes),
                    performedBy: GetPerformedBy(identity));
            }

            return await CreateJsonResponse(req, new 
            { 
                message = "Settings updated successfully",
                notificationEmails = settings.NotificationEmails,
                reportOnlyModeEnabled,
                retentionPolicyDays,
                sponsorsReceiveNotifications,
                notifySponsorsOnExpiration,
                sponsorRemindersEnabled,
                sponsorReminderCount,
                sponsorFirstReminderDays = sponsorReminderDays.firstReminderDays,
                sponsorSecondReminderDays = sponsorReminderDays.secondReminderDays,
                sponsorThirdReminderDays = sponsorReminderDays.thirdReminderDays,
                sessionTimeoutMinutes,
                createCertsForNotifyApps,
                reportsRetentionPolicyDays,
                sponsorsCanRotateCerts,
                sponsorsCanUpdatePolicy,
                sponsorsCanEditSponsors,
                staleCertCleanupRemindersEnabled,
                staleCertCleanupSchedule = _configuration["StaleCertCleanupSchedule"] ?? "0 0 6 1 * *"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating settings");
            return await CreateErrorResponse(req, ex.Message);
        }
    }
}
