using Azure;
using Azure.Data.Tables;

namespace SamlCertRotation.Models;

/// <summary>
/// Policy configuration for certificate rotation
/// </summary>
public class RotationPolicy : ITableEntity
{
    /// <summary>
    /// Partition key - typically "Policy" for global or AppId for app-specific
    /// </summary>
    public string PartitionKey { get; set; } = "GlobalPolicy";

    /// <summary>
    /// Row key - "Default" for global policy or specific policy name
    /// </summary>
    public string RowKey { get; set; } = "Default";

    /// <summary>
    /// Days before expiry to create a new certificate
    /// </summary>
    public int CreateCertDaysBeforeExpiry { get; set; } = 60;

    /// <summary>
    /// Days before expiry to activate the new certificate
    /// </summary>
    public int ActivateCertDaysBeforeExpiry { get; set; } = 30;

    /// <summary>
    /// Whether the policy is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Description for this policy
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Last modified timestamp
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>
    /// ETag for optimistic concurrency
    /// </summary>
    public ETag ETag { get; set; }
}

/// <summary>
/// App-specific policy override
/// </summary>
public class AppPolicy : ITableEntity
{
    /// <summary>
    /// Partition key - "AppPolicy"
    /// </summary>
    public string PartitionKey { get; set; } = "AppPolicy";

    /// <summary>
    /// Row key - The service principal object ID
    /// </summary>
    public string RowKey { get; set; } = string.Empty;

    /// <summary>
    /// Application display name (for reference)
    /// </summary>
    public string? AppDisplayName { get; set; }

    /// <summary>
    /// Override: Days before expiry to create a new certificate (null = use global)
    /// </summary>
    public int? CreateCertDaysBeforeExpiry { get; set; }

    /// <summary>
    /// Override: Days before expiry to activate the new certificate (null = use global)
    /// </summary>
    public int? ActivateCertDaysBeforeExpiry { get; set; }

    /// <summary>
    /// Override: create certs for notify-only apps (null = use global, true = enabled, false = disabled)
    /// </summary>
    public bool? CreateCertsForNotifyOverride { get; set; }

    /// <summary>
    /// Additional notification emails specific to this app
    /// </summary>
    public string? AdditionalNotificationEmails { get; set; }

    /// <summary>
    /// Last modified timestamp
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>
    /// ETag for optimistic concurrency
    /// </summary>
    public ETag ETag { get; set; }
}
