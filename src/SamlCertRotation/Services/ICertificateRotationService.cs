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
    Task<List<RotationResult>> RunRotationAsync(bool? forceReportOnlyMode = null);

    /// <summary>
    /// Get dashboard statistics
    /// </summary>
    Task<DashboardStats> GetDashboardStatsAsync();

    /// <summary>
    /// Process a single application
    /// </summary>
    Task<RotationResult> ProcessApplicationAsync(SamlApplication app, bool reportOnlyMode = false);
}
