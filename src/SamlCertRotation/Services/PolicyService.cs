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

    private const string PolicyTableName = "RotationPolicies";

    public PolicyService(
        TableServiceClient tableServiceClient, 
        ILogger<PolicyService> logger,
        IConfiguration configuration)
    {
        _policyTable = tableServiceClient.GetTableClient(PolicyTableName);
        _policyTable.CreateIfNotExists();
        _logger = logger;
        _defaultCreateDays = int.Parse(configuration["DefaultCreateCertDaysBeforeExpiry"] ?? "60");
        _defaultActivateDays = int.Parse(configuration["DefaultActivateCertDaysBeforeExpiry"] ?? "30");
    }

    /// <inheritdoc />
    public async Task<RotationPolicy> GetGlobalPolicyAsync()
    {
        try
        {
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
        try
        {
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
        try
        {
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
}
