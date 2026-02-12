using Azure.Data.Tables;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of audit logging using Azure Table Storage
/// </summary>
public class AuditService : IAuditService
{
    private readonly TableClient _auditTable;
    private readonly ILogger<AuditService> _logger;

    private const string AuditTableName = "AuditLog";

    public AuditService(TableServiceClient tableServiceClient, ILogger<AuditService> logger)
    {
        _auditTable = tableServiceClient.GetTableClient(AuditTableName);
        _auditTable.CreateIfNotExists();
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task LogAsync(AuditEntry entry)
    {
        try
        {
            await _auditTable.AddEntityAsync(entry);
            _logger.LogInformation("Audit entry created: {ActionType} for {AppName}", 
                entry.ActionType, entry.AppDisplayName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create audit entry");
        }
    }

    /// <inheritdoc />
    public async Task LogSuccessAsync(string servicePrincipalId, string appDisplayName, string actionType, 
        string description, string? certificateThumbprint = null, string? newCertificateThumbprint = null)
    {
        var entry = new AuditEntry
        {
            ServicePrincipalId = servicePrincipalId,
            AppDisplayName = appDisplayName,
            ActionType = actionType,
            Description = description,
            IsSuccess = true,
            CertificateThumbprint = certificateThumbprint,
            NewCertificateThumbprint = newCertificateThumbprint
        };

        await LogAsync(entry);
    }

    /// <inheritdoc />
    public async Task LogFailureAsync(string servicePrincipalId, string appDisplayName, string actionType, 
        string description, string errorMessage)
    {
        var entry = new AuditEntry
        {
            ServicePrincipalId = servicePrincipalId,
            AppDisplayName = appDisplayName,
            ActionType = actionType,
            Description = description,
            IsSuccess = false,
            ErrorMessage = errorMessage
        };

        await LogAsync(entry);
    }

    /// <inheritdoc />
    public async Task<List<AuditEntry>> GetEntriesAsync(DateTime startDate, DateTime endDate)
    {
        var entries = new List<AuditEntry>();

        try
        {
            // Partition keys are dates in yyyy-MM-dd format
            for (var date = startDate.Date; date <= endDate.Date; date = date.AddDays(1))
            {
                var partitionKey = date.ToString("yyyy-MM-dd");
                await foreach (var entry in _auditTable.QueryAsync<AuditEntry>(e => e.PartitionKey == partitionKey))
                {
                    entries.Add(entry);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving audit entries");
        }

        return entries.OrderByDescending(e => e.Timestamp).ToList();
    }

    /// <inheritdoc />
    public async Task<List<AuditEntry>> GetEntriesForAppAsync(string servicePrincipalId, int maxResults = 100)
    {
        var entries = new List<AuditEntry>();

        try
        {
            // Query last 30 days for the specific app
            var endDate = DateTime.UtcNow.Date;
            var startDate = endDate.AddDays(-30);

            for (var date = endDate; date >= startDate && entries.Count < maxResults; date = date.AddDays(-1))
            {
                var partitionKey = date.ToString("yyyy-MM-dd");
                await foreach (var entry in _auditTable.QueryAsync<AuditEntry>(
                    e => e.PartitionKey == partitionKey && e.ServicePrincipalId == servicePrincipalId))
                {
                    entries.Add(entry);
                    if (entries.Count >= maxResults) break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving audit entries for app {Id}", servicePrincipalId);
        }

        return entries;
    }
}
