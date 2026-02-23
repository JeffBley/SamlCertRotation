using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Interface for the main certificate rotation orchestration
/// </summary>
public interface ICertificateRotationService
{
    /// <summary>
    /// Run the full certificate check and rotation process
    /// </summary>
    Task<List<RotationResult>> RunRotationAsync(bool? forceReportOnlyMode = null, string? performedBy = null);

    /// <summary>
    /// Get dashboard statistics (fetches apps from Graph)
    /// </summary>
    Task<DashboardStats> GetDashboardStatsAsync();

    /// <summary>
    /// Get dashboard statistics using a pre-fetched apps list (avoids redundant Graph calls)
    /// </summary>
    Task<DashboardStats> GetDashboardStatsAsync(List<SamlApplication> apps);

    /// <summary>
    /// Process a single application
    /// </summary>
    Task<RotationResult> ProcessApplicationAsync(SamlApplication app, bool reportOnlyMode = false);
}
