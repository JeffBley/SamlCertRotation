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
}
