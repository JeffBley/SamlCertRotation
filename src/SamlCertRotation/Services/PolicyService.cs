using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of policy management using Azure Table Storage
/// </summary>
public class PolicyService : IPolicyService
{
    private readonly TableClient _policyTable;
    private readonly ILogger<PolicyService> _logger;
    private readonly int _defaultCreateDays;
    private readonly int _defaultActivateDays;
    private bool _tableInitialized;

    private const string PolicyTableName = "RotationPolicies";
    private const int DefaultRetentionPolicyDays = 180;
    private const int DefaultSessionTimeoutMinutes = 15;
    private const int DefaultFirstSponsorReminderDays = 30;
    private const int DefaultSecondSponsorReminderDays = 7;
    private const int DefaultThirdSponsorReminderDays = 1;
    private const int MinSponsorReminderDays = 1;
    private const int MaxSponsorReminderDays = 180;

    public PolicyService(
        TableServiceClient tableServiceClient, 
        ILogger<PolicyService> logger,
        IConfiguration configuration)
    {
        _policyTable = tableServiceClient.GetTableClient(PolicyTableName);
        _logger = logger;
        _defaultCreateDays = int.TryParse(configuration["DefaultCreateCertDaysBeforeExpiry"], out var createDays)
            ? createDays
            : 60;
        _defaultActivateDays = int.TryParse(configuration["DefaultActivateCertDaysBeforeExpiry"], out var activateDays)
            ? activateDays
            : 30;
    }

    private async Task EnsureTableExistsAsync()
    {
        if (_tableInitialized) return;
        await _policyTable.CreateIfNotExistsAsync();
        _tableInitialized = true;
    }

    /// <inheritdoc />
    public async Task<RotationPolicy> GetGlobalPolicyAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<RotationPolicy>("GlobalPolicy", "Default");
            
            if (response.HasValue && response.Value != null)
            {
                return response.Value;
            }

            // Return default policy if none exists
            var defaultPolicy = new RotationPolicy
            {
                PartitionKey = "GlobalPolicy",
                RowKey = "Default",
                CreateCertDaysBeforeExpiry = _defaultCreateDays,
                ActivateCertDaysBeforeExpiry = _defaultActivateDays,
                IsEnabled = true,
                Description = "Default global rotation policy"
            };

            // Save the default policy
            await _policyTable.UpsertEntityAsync(defaultPolicy);
            _logger.LogInformation("Created default global policy");

            return defaultPolicy;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving global policy");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<bool> UpdateGlobalPolicyAsync(RotationPolicy policy)
    {
        if (policy.CreateCertDaysBeforeExpiry < 1)
            throw new ArgumentException("CreateCertDaysBeforeExpiry must be at least 1.", nameof(policy));
        if (policy.ActivateCertDaysBeforeExpiry < 1)
            throw new ArgumentException("ActivateCertDaysBeforeExpiry must be at least 1.", nameof(policy));
        if (policy.ActivateCertDaysBeforeExpiry >= policy.CreateCertDaysBeforeExpiry)
            throw new ArgumentException("ActivateCertDaysBeforeExpiry must be less than CreateCertDaysBeforeExpiry.", nameof(policy));

        try
        {
            await EnsureTableExistsAsync();
            policy.PartitionKey = "GlobalPolicy";
            policy.RowKey = "Default";

            await _policyTable.UpsertEntityAsync(policy, TableUpdateMode.Replace);
            _logger.LogInformation("Updated global policy");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating global policy");
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<AppPolicy?> GetAppPolicyAsync(string servicePrincipalId)
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<AppPolicy>("AppPolicy", servicePrincipalId);
            return response.HasValue ? response.Value : null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving app policy for {Id}", servicePrincipalId);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<bool> UpsertAppPolicyAsync(AppPolicy policy)
    {
        // Validate create > activate when both are specified
        if (policy.CreateCertDaysBeforeExpiry.HasValue && policy.ActivateCertDaysBeforeExpiry.HasValue)
        {
            if (policy.ActivateCertDaysBeforeExpiry.Value >= policy.CreateCertDaysBeforeExpiry.Value)
                throw new ArgumentException("Activate cert days must be less than Create cert days.");
        }

        try
        {
            await EnsureTableExistsAsync();
            policy.PartitionKey = "AppPolicy";
            await _policyTable.UpsertEntityAsync(policy, TableUpdateMode.Replace);
            _logger.LogInformation("Updated app policy for {Id}", policy.RowKey);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating app policy");
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<RotationPolicy> GetEffectivePolicyAsync(string servicePrincipalId)
    {
        await EnsureTableExistsAsync();
        var globalPolicy = await GetGlobalPolicyAsync();
        var appPolicy = await GetAppPolicyAsync(servicePrincipalId);

        if (appPolicy == null)
        {
            return globalPolicy;
        }

        // Merge app-specific overrides with global policy
        return new RotationPolicy
        {
            PartitionKey = "EffectivePolicy",
            RowKey = servicePrincipalId,
            CreateCertDaysBeforeExpiry = appPolicy.CreateCertDaysBeforeExpiry ?? globalPolicy.CreateCertDaysBeforeExpiry,
            ActivateCertDaysBeforeExpiry = appPolicy.ActivateCertDaysBeforeExpiry ?? globalPolicy.ActivateCertDaysBeforeExpiry,
            IsEnabled = globalPolicy.IsEnabled,
            Description = $"Effective policy for {servicePrincipalId}"
        };
    }

    /// <inheritdoc />
    public async Task<List<AppPolicy>> ListAppPoliciesAsync()
    {
        var policies = new List<AppPolicy>();

        try
        {
            await EnsureTableExistsAsync();
            await foreach (var policy in _policyTable.QueryAsync<AppPolicy>(p => p.PartitionKey == "AppPolicy"))
            {
                policies.Add(policy);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error listing app policies");
        }

        return policies;
    }

    /// <inheritdoc />
    public async Task<string> GetNotificationEmailsAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "NotificationEmails");
            if (response.HasValue && response.Value != null)
            {
                return response.Value.GetString("Emails") ?? "";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting notification emails from storage");
        }
        return "";
    }

    /// <inheritdoc />
    public async Task UpdateNotificationEmailsAsync(string emails)
    {
        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "NotificationEmails")
            {
                { "Emails", emails }
            };
            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated notification emails: {Emails}", emails);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating notification emails");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<bool> GetReportOnlyModeEnabledAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "ReportOnlyMode");
            if (response.HasValue && response.Value != null)
            {
                var value = response.Value.GetString("Enabled");
                if (bool.TryParse(value, out var enabled))
                {
                    return enabled;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting report-only mode setting from storage");
        }

        return true;
    }

    /// <inheritdoc />
    public async Task UpdateReportOnlyModeEnabledAsync(bool enabled)
    {
        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "ReportOnlyMode")
            {
                { "Enabled", enabled.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated report-only mode: {Enabled}", enabled);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating report-only mode setting");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<int> GetRetentionPolicyDaysAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "RetentionPolicyDays");
            if (response.HasValue && response.Value != null)
            {
                var value = response.Value.GetString("Days");
                if (int.TryParse(value, out var days) && days > 0)
                {
                    return days;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting retention policy setting from storage");
        }

        return DefaultRetentionPolicyDays;
    }

    /// <inheritdoc />
    public async Task UpdateRetentionPolicyDaysAsync(int days)
    {
        if (days < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "Retention policy must be at least 1 day.");
        }

        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "RetentionPolicyDays")
            {
                { "Days", days.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated retention policy days: {Days}", days);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating retention policy setting");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<bool> GetSponsorsReceiveNotificationsEnabledAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "SponsorsReceiveNotifications");
            if (response.HasValue && response.Value != null)
            {
                var value = response.Value.GetString("Enabled");
                if (bool.TryParse(value, out var enabled))
                {
                    return enabled;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting sponsor notifications setting from storage");
        }

        return true;
    }

    /// <inheritdoc />
    public async Task UpdateSponsorsReceiveNotificationsEnabledAsync(bool enabled)
    {
        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "SponsorsReceiveNotifications")
            {
                { "Enabled", enabled.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated sponsor notifications setting: {Enabled}", enabled);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating sponsor notifications setting");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<bool> GetNotifySponsorsOnExpirationEnabledAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "NotifySponsorsOnExpiration");
            if (response.HasValue && response.Value != null)
            {
                var value = response.Value.GetString("Enabled");
                if (bool.TryParse(value, out var enabled))
                {
                    return enabled;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting sponsor expiration notification setting from storage");
        }

        return true;
    }

    /// <inheritdoc />
    public async Task UpdateNotifySponsorsOnExpirationEnabledAsync(bool enabled)
    {
        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "NotifySponsorsOnExpiration")
            {
                { "Enabled", enabled.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated sponsor expiration notifications setting: {Enabled}", enabled);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating sponsor expiration notifications setting");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<(int firstReminderDays, int secondReminderDays, int thirdReminderDays)> GetSponsorReminderDaysAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "SponsorReminderDays");
            if (response.HasValue && response.Value != null)
            {
                var first = ParseReminderDays(response.Value.GetString("FirstReminderDays"), DefaultFirstSponsorReminderDays);
                var second = ParseReminderDays(response.Value.GetString("SecondReminderDays"), DefaultSecondSponsorReminderDays);
                var third = ParseReminderDays(response.Value.GetString("ThirdReminderDays"), DefaultThirdSponsorReminderDays);
                return (first, second, third);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting sponsor reminder day settings from storage");
        }

        return (DefaultFirstSponsorReminderDays, DefaultSecondSponsorReminderDays, DefaultThirdSponsorReminderDays);
    }

    /// <inheritdoc />
    public async Task UpdateSponsorReminderDaysAsync(int firstReminderDays, int secondReminderDays, int thirdReminderDays)
    {
        ValidateReminderDays(firstReminderDays, nameof(firstReminderDays));
        ValidateReminderDays(secondReminderDays, nameof(secondReminderDays));
        ValidateReminderDays(thirdReminderDays, nameof(thirdReminderDays));

        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "SponsorReminderDays")
            {
                { "FirstReminderDays", firstReminderDays.ToString() },
                { "SecondReminderDays", secondReminderDays.ToString() },
                { "ThirdReminderDays", thirdReminderDays.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation(
                "Updated sponsor reminder day settings: first={First}, second={Second}, third={Third}",
                firstReminderDays,
                secondReminderDays,
                thirdReminderDays);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating sponsor reminder day settings");
            throw;
        }
    }

    private static int ParseReminderDays(string? value, int defaultValue)
    {
        if (int.TryParse(value, out var parsed) && parsed >= MinSponsorReminderDays && parsed <= MaxSponsorReminderDays)
        {
            return parsed;
        }

        return defaultValue;
    }

    private static void ValidateReminderDays(int days, string paramName)
    {
        if (days < MinSponsorReminderDays || days > MaxSponsorReminderDays)
        {
            throw new ArgumentOutOfRangeException(paramName, $"Reminder day value must be between {MinSponsorReminderDays} and {MaxSponsorReminderDays}.");
        }
    }

    /// <inheritdoc />
    public async Task<int> GetSessionTimeoutMinutesAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "SessionTimeoutMinutes");
            if (response.HasValue && response.Value != null)
            {
                var value = response.Value.GetString("Minutes");
                if (int.TryParse(value, out var minutes) && minutes >= 0)
                {
                    return minutes;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting session timeout setting from storage");
        }

        return DefaultSessionTimeoutMinutes;
    }

    /// <inheritdoc />
    public async Task UpdateSessionTimeoutMinutesAsync(int minutes)
    {
        if (minutes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minutes), "Session timeout must be 0 (disabled) or a positive number.");
        }

        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "SessionTimeoutMinutes")
            {
                { "Minutes", minutes.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated session timeout minutes: {Minutes}", minutes);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating session timeout setting");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<bool> GetCreateCertsForNotifyAppsEnabledAsync()
    {
        try
        {
            await EnsureTableExistsAsync();
            var response = await _policyTable.GetEntityIfExistsAsync<TableEntity>("Settings", "CreateCertsForNotifyApps");
            if (response.HasValue && response.Value != null)
            {
                var value = response.Value.GetString("Enabled");
                if (bool.TryParse(value, out var enabled))
                {
                    return enabled;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting create-certs-for-notify-apps setting from storage");
        }

        return true;
    }

    /// <inheritdoc />
    public async Task UpdateCreateCertsForNotifyAppsEnabledAsync(bool enabled)
    {
        try
        {
            await EnsureTableExistsAsync();
            var entity = new TableEntity("Settings", "CreateCertsForNotifyApps")
            {
                { "Enabled", enabled.ToString() }
            };

            await _policyTable.UpsertEntityAsync(entity, TableUpdateMode.Replace);
            _logger.LogInformation("Updated create-certs-for-notify-apps setting: {Enabled}", enabled);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating create-certs-for-notify-apps setting");
            throw;
        }
    }
}
