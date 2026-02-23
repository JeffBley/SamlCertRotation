using Azure;
using Azure.Data.Tables;

namespace SamlCertRotation.Models;

/// <summary>
/// Represents a single automation run report stored in Azure Table Storage.
/// PartitionKey = date ("yyyy-MM-dd"), RowKey = RunId (GUID).
/// </summary>
public class RunReport : ITableEntity
{
    /// <summary>
    /// Date partition key (yyyy-MM-dd) for efficient date-range queries and purging.
    /// </summary>
    public string PartitionKey { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd");

    /// <summary>
    /// Unique run identifier (GUID).
    /// </summary>
    public string RowKey { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>
    /// When the run started (UTC).
    /// </summary>
    public DateTime RunDate { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Run mode: "report-only" or "prod".
    /// </summary>
    public string Mode { get; set; } = "report-only";

    /// <summary>
    /// Who triggered the run. "Scheduled" for timer runs, UPN for manual triggers.
    /// </summary>
    public string TriggeredBy { get; set; } = "Scheduled";

    /// <summary>
    /// Total number of applications processed.
    /// </summary>
    public int TotalProcessed { get; set; }

    /// <summary>
    /// Number of successful actions (created, activated, would create, etc.).
    /// </summary>
    public int Successful { get; set; }

    /// <summary>
    /// Number of skipped applications.
    /// </summary>
    public int Skipped { get; set; }

    /// <summary>
    /// Number of failed operations.
    /// </summary>
    public int Failed { get; set; }

    /// <summary>
    /// JSON-serialized List&lt;RotationResult&gt; with per-app details.
    /// </summary>
    public string ResultsJson { get; set; } = "[]";

    /// <summary>
    /// Azure Table Storage timestamp (auto-populated).
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>
    /// ETag for optimistic concurrency.
    /// </summary>
    public ETag ETag { get; set; }
}
