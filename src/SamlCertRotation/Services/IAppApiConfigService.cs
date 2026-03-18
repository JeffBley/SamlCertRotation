using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Persists and retrieves per-app API access configurations.
/// The sensitive credential (API key / OAuth client secret) is stored in Key Vault,
/// not in Table Storage. This service manages both halves atomically.
/// </summary>
public interface IAppApiConfigService
{
    /// <summary>
    /// Returns the API configuration for the specified application, or null if none exists.
    /// The returned object never contains the raw secret — callers that need the credential
    /// must call <see cref="GetSecretAsync"/>.
    /// </summary>
    Task<AppApiConfiguration?> GetConfigAsync(string appId, CancellationToken ct = default);

    /// <summary>
    /// Saves (create or update) the API configuration for the specified application.
    /// </summary>
    /// <param name="config">Configuration to persist — must have <see cref="AppApiConfiguration.RowKey"/> set to the SP object ID.</param>
    /// <param name="secret">
    /// The raw sensitive credential to store in Key Vault (API key, OAuth client secret, or service-account token).
    /// Pass null to leave an existing secret unchanged when only updating non-secret fields.
    /// </param>
    Task SaveConfigAsync(AppApiConfiguration config, string? secret, CancellationToken ct = default);

    /// <summary>
    /// Reads the raw secret for the app from Key Vault. Returns null if no secret is stored.
    /// </summary>
    Task<string?> GetSecretAsync(AppApiConfiguration config, CancellationToken ct = default);

    /// <summary>
    /// Deletes the configuration from Table Storage and removes the secret from Key Vault.
    /// </summary>
    Task DeleteConfigAsync(string appId, CancellationToken ct = default);

    /// <summary>
    /// Returns API configurations for all applications that have one configured.
    /// </summary>
    Task<IReadOnlyList<AppApiConfiguration>> GetAllConfigsAsync(CancellationToken ct = default);
}
