using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Interface for audit logging operations
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Log an audit entry
    /// </summary>
    Task LogAsync(AuditEntry entry);

    /// <summary>
    /// Log a successful operation
    /// </summary>
    Task LogSuccessAsync(string servicePrincipalId, string appDisplayName, string actionType, string description, 
        string? certificateThumbprint = null, string? newCertificateThumbprint = null);

    /// <summary>
    /// Log a failed operation
    /// </summary>
    Task LogFailureAsync(string servicePrincipalId, string appDisplayName, string actionType, string description, 
        string errorMessage);

    /// <summary>
    /// Get audit entries for a specific date range
    /// </summary>
    Task<List<AuditEntry>> GetEntriesAsync(DateTime startDate, DateTime endDate);

    /// <summary>
    /// Get audit entries for a specific application
    /// </summary>
    Task<List<AuditEntry>> GetEntriesForAppAsync(string servicePrincipalId, int maxResults = 100);

    /// <summary>
    /// Purge audit entries older than the specified retention in days
    /// </summary>
    Task<int> PurgeEntriesOlderThanAsync(int retentionDays);
}
