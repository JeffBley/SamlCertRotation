using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;
using System.IO.Compression;
using System.Text;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of run report storage using Azure Table Storage.
/// </summary>
public class ReportService : IReportService
{
    private readonly TableClient _reportTable;
    private readonly ILogger<ReportService> _logger;
    private volatile Task? _ensureTableTask;

    private const string ReportTableName = "RunReports";

    public ReportService(TableServiceClient tableServiceClient, ILogger<ReportService> logger)
    {
        _reportTable = tableServiceClient.GetTableClient(ReportTableName);
        _logger = logger;
    }

    /// <summary>
    /// Ensures the table exists with retry-safe caching.
    /// Unlike Lazy&lt;Task&gt;, a faulted/canceled task is discarded so the next call retries.
    /// </summary>
    private Task EnsureTableExistsAsync()
    {
        var task = _ensureTableTask;
        if (task is not null && !task.IsFaulted && !task.IsCanceled)
            return task;
        return _ensureTableTask = _reportTable.CreateIfNotExistsAsync();
    }

    /// <inheritdoc />
    public async Task SaveRunReportAsync(RunReport report)
    {
        try
        {
            await EnsureTableExistsAsync();

            // Compress ResultsJson → byte[] to avoid the 32K-char (64KB UTF-16)
            // string property limit in Azure Table Storage.
            CompressResults(report);

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
            var filter = TableClient.CreateQueryFilter($"PartitionKey ge {startPartitionKey}");

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
        if (!Guid.TryParse(runId, out _))
        {
            _logger.LogWarning("Invalid run ID format (not a GUID): {RunId}", runId);
            return null;
        }

        try
        {
            await EnsureTableExistsAsync();

            // We don't know the PartitionKey, so scan for the RowKey
            var filter = TableClient.CreateQueryFilter($"RowKey eq {runId}");
            await foreach (var report in _reportTable.QueryAsync<RunReport>(filter: filter, maxPerPage: 1))
            {
                DecompressResults(report);
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

            await foreach (var report in _reportTable.QueryAsync<RunReport>(filter: TableClient.CreateQueryFilter($"PartitionKey lt {cutoffPartitionKey}")))
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

    /// <summary>
    /// Compresses <see cref="RunReport.ResultsJson"/> into
    /// <see cref="RunReport.ResultsJsonCompressed"/> and clears the string
    /// property so the entity stays within Table Storage limits.
    /// </summary>
    private static void CompressResults(RunReport report)
    {
        if (string.IsNullOrEmpty(report.ResultsJson) || report.ResultsJson == "[]")
            return;

        var rawBytes = Encoding.UTF8.GetBytes(report.ResultsJson);
        using var ms = new MemoryStream();
        using (var gzip = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(rawBytes, 0, rawBytes.Length);
        }

        report.ResultsJsonCompressed = ms.ToArray();
        report.ResultsJson = "[]"; // clear to avoid the 32K-char limit
    }

    /// <summary>
    /// Restores <see cref="RunReport.ResultsJson"/> from the compressed
    /// binary property if present. Falls back to the uncompressed string
    /// for backward compatibility with older reports.
    /// </summary>
    private static void DecompressResults(RunReport report)
    {
        if (report.ResultsJsonCompressed is { Length: > 0 })
        {
            using var ms = new MemoryStream(report.ResultsJsonCompressed);
            using var gzip = new GZipStream(ms, CompressionMode.Decompress);
            using var reader = new StreamReader(gzip, Encoding.UTF8);
            report.ResultsJson = reader.ReadToEnd();
        }
        // else: ResultsJson already has the data (old uncompressed format)
    }
}
