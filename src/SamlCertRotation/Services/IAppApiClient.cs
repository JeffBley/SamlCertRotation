using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Calls a target SAML application's control-plane API using the credentials stored for it,
/// supporting all four authentication types defined in <see cref="ApiAuthType"/>.
/// </summary>
public interface IAppApiClient
{
    /// <summary>
    /// Fetches the list of SAML certificates the target application is aware of.
    /// </summary>
    /// <param name="config">App API configuration (non-secret fields).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// A list of <see cref="RemoteSamlCertInfo"/> representing the certs known by the app.
    /// </returns>
    Task<IReadOnlyList<RemoteSamlCertInfo>> GetRemoteKeysAsync(
        AppApiConfiguration config, CancellationToken ct = default);

    /// <summary>
    /// Instructs the target application to promote a specific certificate to the active / primary
    /// signing key.
    /// </summary>
    /// <param name="config">App API configuration (non-secret fields).</param>
    /// <param name="certId">The identifier of the certificate to activate (typically a GUID).</param>
    /// <param name="reason">Optional human-readable reason for the activation (audit trail).</param>
    /// <param name="ct">Cancellation token.</param>
    Task ActivateRemoteKeyAsync(
        AppApiConfiguration config, string certId, string? reason = null, CancellationToken ct = default);
}

/// <summary>
/// Represents a SAML signing certificate as returned by the target application's
/// control-plane API.
/// </summary>
public class RemoteSamlCertInfo
{
    /// <summary>Opaque identifier used by the app to reference this certificate.</summary>
    public string CertId { get; init; } = string.Empty;

    public string Thumbprint { get; init; } = string.Empty;
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public DateTimeOffset NotBeforeUtc { get; init; }
    public DateTimeOffset NotAfterUtc { get; init; }

    /// <summary>
    /// Application-reported state, e.g. <c>"active"</c>, <c>"staged"</c>.
    /// </summary>
    public string State { get; init; } = string.Empty;

    public bool IsActive => string.Equals(State, "active", StringComparison.OrdinalIgnoreCase);

    public int DaysUntilExpiry =>
        (int)(NotAfterUtc - DateTimeOffset.UtcNow).TotalDays;
}
