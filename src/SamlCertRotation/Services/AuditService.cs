using Azure.Data.Tables;
using Azure;
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
    private bool _tableInitialized;

    private const string AuditTableName = "AuditLog";

    public AuditService(TableServiceClient tableServiceClient, ILogger<AuditService> logger)
    {
        _auditTable = tableServiceClient.GetTableClient(AuditTableName);
        _logger = logger;
    }

    private async Task EnsureTableExistsAsync()
    {
        if (_tableInitialized) return;
        await _auditTable.CreateIfNotExistsAsync();
        _tableInitialized = true;
    }

    /// <inheritdoc />
    public async Task LogAsync(AuditEntry entry)
    {
        try
        {
            await EnsureTableExistsAsync();
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
            // Use a range filter instead of querying day by day
            await EnsureTableExistsAsync();
            var startPartitionKey = startDate.Date.ToString("yyyy-MM-dd");
            var endPartitionKey = endDate.Date.ToString("yyyy-MM-dd");
            var filter = $"PartitionKey ge '{startPartitionKey}' and PartitionKey le '{endPartitionKey}'";

            await foreach (var entry in _auditTable.QueryAsync<AuditEntry>(filter: filter))
            {
                entries.Add(entry);
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
            // Query last 30 days for the specific app using a range filter
            await EnsureTableExistsAsync();
            var endDate = DateTime.UtcNow.Date;
            var startDate = endDate.AddDays(-30);
            var startPartitionKey = startDate.ToString("yyyy-MM-dd");
            var endPartitionKey = endDate.ToString("yyyy-MM-dd");
            var filter = $"PartitionKey ge '{startPartitionKey}' and PartitionKey le '{endPartitionKey}' and ServicePrincipalId eq '{servicePrincipalId}'";

            await foreach (var entry in _auditTable.QueryAsync<AuditEntry>(filter: filter, maxPerPage: maxResults))
            {
                entries.Add(entry);
                if (entries.Count >= maxResults) break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving audit entries for app {Id}", servicePrincipalId);
        }

        return entries.OrderByDescending(e => e.Timestamp).ToList();
    }

    /// <inheritdoc />
    public async Task<Dictionary<string, List<AuditEntry>>> GetRecentEntriesForAppsAsync(IEnumerable<string> servicePrincipalIds, int daysBack = 30)
    {
        var result = new Dictionary<string, List<AuditEntry>>(StringComparer.OrdinalIgnoreCase);

        try
        {
            await EnsureTableExistsAsync();
            var endDate = DateTime.UtcNow.Date;
            var startDate = endDate.AddDays(-daysBack);
            var startPartitionKey = startDate.ToString("yyyy-MM-dd");
            var endPartitionKey = endDate.ToString("yyyy-MM-dd");

            // Build a filter for the requested service principal IDs
            var idSet = servicePrincipalIds.Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (idSet.Count == 0) return result;

            var filter = $"PartitionKey ge '{startPartitionKey}' and PartitionKey le '{endPartitionKey}'";

            // If only a small number of IDs, add them to the server-side filter
            if (idSet.Count <= 15)
            {
                var idFilters = string.Join(" or ", idSet.Select(id => $"ServicePrincipalId eq '{id}'"));
                filter += $" and ({idFilters})";
            }

            var idLookup = new HashSet<string>(idSet, StringComparer.OrdinalIgnoreCase);
            await foreach (var entry in _auditTable.QueryAsync<AuditEntry>(filter: filter))
            {
                if (!idLookup.Contains(entry.ServicePrincipalId)) continue;

                if (!result.TryGetValue(entry.ServicePrincipalId, out var list))
                {
                    list = new List<AuditEntry>();
                    result[entry.ServicePrincipalId] = list;
                }
                list.Add(entry);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving bulk audit entries for {Count} apps", servicePrincipalIds.Count());
        }

        return result;
    }

    /// <inheritdoc />
    public async Task<int> PurgeEntriesOlderThanAsync(int retentionDays)
    {
        if (retentionDays < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(retentionDays), "Retention days must be at least 1.");
        }

        var deletedCount = 0;
        var cutoffDate = DateTime.UtcNow.Date.AddDays(-retentionDays);
        var cutoffPartitionKey = cutoffDate.ToString("yyyy-MM-dd");

        try
        {
            // Group deletes by partition key and batch them (max 100 per batch in Table Storage)
            await EnsureTableExistsAsync();
            var entriesToDelete = new List<(string PartitionKey, string RowKey)>();
            await foreach (var entry in _auditTable.QueryAsync<AuditEntry>(filter: $"PartitionKey lt '{cutoffPartitionKey}'"))
            {
                entriesToDelete.Add((entry.PartitionKey, entry.RowKey));
            }

            var grouped = entriesToDelete.GroupBy(e => e.PartitionKey);
            foreach (var group in grouped)
            {
                foreach (var batch in group.Chunk(100))
                {
                    var transactionActions = batch.Select(e =>
                        new TableTransactionAction(TableTransactionActionType.Delete,
                            new TableEntity(e.PartitionKey, e.RowKey), ETag.All));
                    await _auditTable.SubmitTransactionAsync(transactionActions);
                    deletedCount += batch.Length;
                }
            }

            _logger.LogInformation(
                "Purged {Count} audit entries older than {CutoffDate} (retention days: {RetentionDays})",
                deletedCount,
                cutoffDate,
                retentionDays);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error purging audit entries older than {CutoffDate}", cutoffDate);
            throw;
        }

        return deletedCount;
    }
}
