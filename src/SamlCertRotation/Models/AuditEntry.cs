using Azure;
using Azure.Data.Tables;

namespace SamlCertRotation.Models;

/// <summary>
/// Audit log entry for tracking all certificate operations
/// </summary>
public class AuditEntry : ITableEntity
{
    /// <summary>
    /// Partition key - Date in format yyyy-MM-dd for efficient querying
    /// </summary>
    public string PartitionKey { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd");

    /// <summary>
    /// Row key - Unique identifier (timestamp + GUID)
    /// </summary>
    public string RowKey { get; set; } = $"{DateTime.UtcNow:HHmmss}-{Guid.NewGuid():N}";

    /// <summary>
    /// Service principal object ID
    /// </summary>
    public string ServicePrincipalId { get; set; } = string.Empty;

    /// <summary>
    /// Application display name
    /// </summary>
    public string AppDisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Type of action performed
    /// </summary>
    public string ActionType { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of the action
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether the action was successful
    /// </summary>
    public bool IsSuccess { get; set; }

    /// <summary>
    /// Error message if the action failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Certificate thumbprint involved (if applicable)
    /// </summary>
    public string? CertificateThumbprint { get; set; }

    /// <summary>
    /// New certificate thumbprint (for rotation operations)
    /// </summary>
    public string? NewCertificateThumbprint { get; set; }

    /// <summary>
    /// Notification sent to these emails
    /// </summary>
    public string? NotificationsSentTo { get; set; }

    /// <summary>
    /// Timestamp of the audit entry
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>
    /// ETag for optimistic concurrency
    /// </summary>
    public ETag ETag { get; set; }
}

/// <summary>
/// Types of actions that can be audited
/// </summary>
public static class AuditActionType
{
    public const string CertificateCreated = "CertificateCreated";
    public const string CertificateCreatedReportOnly = "CertificateCreatedReportOnly";
    public const string CertificateActivated = "CertificateActivated";
    public const string CertificateActivatedReportOnly = "CertificateActivatedReportOnly";
    public const string CertificateExpiringSoon = "CertificateExpiringSoon";
    public const string NotificationSent = "NotificationSent";
    public const string PolicyUpdated = "PolicyUpdated";
    public const string ScanCompleted = "ScanCompleted";
    public const string ScanCompletedReportOnly = "ScanCompletedReportOnly";
    public const string SponsorUpdated = "SponsorUpdated";
    public const string SponsorExpirationReminderSent = "SponsorExpirationReminderSent";
    public const string Error = "Error";
}
