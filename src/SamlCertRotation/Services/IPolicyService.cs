using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Interface for policy management operations
/// </summary>
public interface IPolicyService
{
    /// <summary>
    /// Get the global rotation policy
    /// </summary>
    Task<RotationPolicy> GetGlobalPolicyAsync();

    /// <summary>
    /// Update the global rotation policy
    /// </summary>
    Task<bool> UpdateGlobalPolicyAsync(RotationPolicy policy);

    /// <summary>
    /// Get app-specific policy override
    /// </summary>
    Task<AppPolicy?> GetAppPolicyAsync(string servicePrincipalId);

    /// <summary>
    /// Update or create app-specific policy
    /// </summary>
    Task<bool> UpsertAppPolicyAsync(AppPolicy policy);

    /// <summary>
    /// Get effective policy for an application (merges global + app-specific)
    /// </summary>
    Task<RotationPolicy> GetEffectivePolicyAsync(string servicePrincipalId);

    /// <summary>
    /// List all app-specific policies
    /// </summary>
    Task<List<AppPolicy>> ListAppPoliciesAsync();

    /// <summary>
    /// Get notification emails from settings
    /// </summary>
    Task<string> GetNotificationEmailsAsync();

    /// <summary>
    /// Update notification emails setting
    /// </summary>
    Task UpdateNotificationEmailsAsync(string emails);

    /// <summary>
    /// Get report-only mode setting (default true/enabled)
    /// </summary>
    Task<bool> GetReportOnlyModeEnabledAsync();

    /// <summary>
    /// Update report-only mode setting
    /// </summary>
    Task UpdateReportOnlyModeEnabledAsync(bool enabled);

    /// <summary>
    /// Get retention policy in days (default 180)
    /// </summary>
    Task<int> GetRetentionPolicyDaysAsync();

    /// <summary>
    /// Update retention policy in days
    /// </summary>
    Task UpdateRetentionPolicyDaysAsync(int days);

    /// <summary>
    /// Get sponsor notifications setting (default true/enabled)
    /// </summary>
    Task<bool> GetSponsorsReceiveNotificationsEnabledAsync();

    /// <summary>
    /// Update sponsor notifications setting
    /// </summary>
    Task UpdateSponsorsReceiveNotificationsEnabledAsync(bool enabled);

    /// <summary>
    /// Get automatic sponsor expiration notification setting (default false/disabled)
    /// </summary>
    Task<bool> GetNotifySponsorsOnExpirationEnabledAsync();

    /// <summary>
    /// Update automatic sponsor expiration notification setting
    /// </summary>
    Task UpdateNotifySponsorsOnExpirationEnabledAsync(bool enabled);

    /// <summary>
    /// Get whether sponsor reminders for notify apps are enabled (default true/enabled)
    /// </summary>
    Task<bool> GetSponsorRemindersEnabledAsync();

    /// <summary>
    /// Update sponsor reminders enabled setting
    /// </summary>
    Task UpdateSponsorRemindersEnabledAsync(bool enabled);

    /// <summary>
    /// Get the number of sponsor reminders to send (1-3, default 3)
    /// </summary>
    Task<int> GetSponsorReminderCountAsync();

    /// <summary>
    /// Update the number of sponsor reminders to send (1-3)
    /// </summary>
    Task UpdateSponsorReminderCountAsync(int count);

    /// <summary>
    /// Get sponsor reminder days (defaults: 30, 7, 1)
    /// </summary>
    Task<(int firstReminderDays, int secondReminderDays, int thirdReminderDays)> GetSponsorReminderDaysAsync();

    /// <summary>
    /// Update sponsor reminder days (must be 1..180)
    /// </summary>
    Task UpdateSponsorReminderDaysAsync(int firstReminderDays, int secondReminderDays, int thirdReminderDays);

    /// <summary>
    /// Get session timeout in minutes (default 0 = disabled)
    /// </summary>
    Task<int> GetSessionTimeoutMinutesAsync();

    /// <summary>
    /// Update session timeout in minutes (0 = disabled)
    /// </summary>
    Task UpdateSessionTimeoutMinutesAsync(int minutes);

    /// <summary>
    /// Get whether to auto-create (but not activate) certs for notify-only apps (default true/enabled)
    /// </summary>
    Task<bool> GetCreateCertsForNotifyAppsEnabledAsync();

    /// <summary>
    /// Update the create-certs-for-notify-apps setting
    /// </summary>
    Task UpdateCreateCertsForNotifyAppsEnabledAsync(bool enabled);

    /// <summary>
    /// Get reports retention policy in days (default 14)
    /// </summary>
    Task<int> GetReportsRetentionPolicyDaysAsync();

    /// <summary>
    /// Update reports retention policy in days
    /// </summary>
    Task UpdateReportsRetentionPolicyDaysAsync(int days);

    /// <summary>
    /// Get whether sponsors can create and rotate certificates (default false/disabled)
    /// </summary>
    Task<bool> GetSponsorsCanRotateCertsEnabledAsync();

    /// <summary>
    /// Update sponsors can rotate certificates setting
    /// </summary>
    Task UpdateSponsorsCanRotateCertsEnabledAsync(bool enabled);
}
