using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Interface for run report storage and retrieval.
/// </summary>
public interface IReportService
{
    /// <summary>
    /// Save a run report after a rotation run completes.
    /// </summary>
    Task SaveRunReportAsync(RunReport report);

    /// <summary>
    /// Get all run reports within the last N days, ordered by RunDate descending.
    /// </summary>
    Task<List<RunReport>> GetRunReportsAsync(int daysBack = 14);

    /// <summary>
    /// Get a single run report by its ID (RowKey).
    /// </summary>
    Task<RunReport?> GetRunReportAsync(string runId);

    /// <summary>
    /// Purge run reports older than the specified retention in days.
    /// Returns the number of deleted reports.
    /// </summary>
    Task<int> PurgeReportsOlderThanAsync(int retentionDays);
}
