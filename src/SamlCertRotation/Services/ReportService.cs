using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of run report storage using Azure Table Storage.
/// </summary>
public class ReportService : IReportService
{
    private readonly TableClient _reportTable;
    private readonly ILogger<ReportService> _logger;
    private bool _tableInitialized;

    private const string ReportTableName = "RunReports";

    public ReportService(TableServiceClient tableServiceClient, ILogger<ReportService> logger)
    {
        _reportTable = tableServiceClient.GetTableClient(ReportTableName);
        _logger = logger;
    }

    private async Task EnsureTableExistsAsync()
    {
        if (_tableInitialized) return;
        await _reportTable.CreateIfNotExistsAsync();
        _tableInitialized = true;
    }

    /// <inheritdoc />
    public async Task SaveRunReportAsync(RunReport report)
    {
        try
        {
            await EnsureTableExistsAsync();
            await _reportTable.AddEntityAsync(report);
            _logger.LogInformation("Run report saved: {RunId}, Mode={Mode}, Total={Total}",
                report.RowKey, report.Mode, report.TotalProcessed);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save run report {RunId}", report.RowKey);
        }
    }

    /// <inheritdoc />
    public async Task<List<RunReport>> GetRunReportsAsync(int daysBack = 14)
    {
        var reports = new List<RunReport>();

        try
        {
            await EnsureTableExistsAsync();
            var startDate = DateTime.UtcNow.Date.AddDays(-daysBack);
            var startPartitionKey = startDate.ToString("yyyy-MM-dd");
            var filter = $"PartitionKey ge '{startPartitionKey}'";

            await foreach (var report in _reportTable.QueryAsync<RunReport>(filter: filter))
            {
                reports.Add(report);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving run reports");
        }

        return reports.OrderByDescending(r => r.RunDate).ToList();
    }

    /// <inheritdoc />
    public async Task<RunReport?> GetRunReportAsync(string runId)
    {
        try
        {
            await EnsureTableExistsAsync();

            // We don't know the PartitionKey, so scan for the RowKey
            var filter = $"RowKey eq '{runId}'";
            await foreach (var report in _reportTable.QueryAsync<RunReport>(filter: filter, maxPerPage: 1))
            {
                return report;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving run report {RunId}", runId);
        }

        return null;
    }

    /// <inheritdoc />
    public async Task<int> PurgeReportsOlderThanAsync(int retentionDays)
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
            await EnsureTableExistsAsync();
            var entriesToDelete = new List<(string PartitionKey, string RowKey)>();

            await foreach (var report in _reportTable.QueryAsync<RunReport>(filter: $"PartitionKey lt '{cutoffPartitionKey}'"))
            {
                entriesToDelete.Add((report.PartitionKey, report.RowKey));
            }

            var grouped = entriesToDelete.GroupBy(e => e.PartitionKey);
            foreach (var group in grouped)
            {
                foreach (var batch in group.Chunk(100))
                {
                    var transactionActions = batch.Select(e =>
                        new TableTransactionAction(TableTransactionActionType.Delete,
                            new TableEntity(e.PartitionKey, e.RowKey), ETag.All));
                    await _reportTable.SubmitTransactionAsync(transactionActions);
                    deletedCount += batch.Length;
                }
            }

            _logger.LogInformation(
                "Purged {Count} run reports older than {CutoffDate} (retention days: {RetentionDays})",
                deletedCount, cutoffDate, retentionDays);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error purging run reports older than {CutoffDate}", cutoffDate);
            throw;
        }

        return deletedCount;
    }
}
