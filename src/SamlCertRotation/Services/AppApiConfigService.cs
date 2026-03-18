using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of <see cref="IAppApiConfigService"/>.
///
/// Non-secret configuration is persisted in the existing <c>RotationPolicies</c>
/// Azure Table (PartitionKey = "AppApiConfig").
///
/// The raw credential (API key, OAuth client secret, service-account token) is
/// written to Key Vault via <see cref="SecretClientFactory"/>, which resolves the
/// correct vault per app (using <see cref="AppApiConfiguration.CredentialKeyVaultUri"/>
/// if set, otherwise falling back to the global <c>KeyVaultUri</c> app setting).
/// The managed identity must hold <c>Key Vault Secrets Officer</c> on each vault used.
/// </summary>
public class AppApiConfigService : IAppApiConfigService
{
    private readonly TableClient _policyTable;
    private readonly SecretClientFactory _kvFactory;
    private readonly ILogger<AppApiConfigService> _logger;
    private readonly object _ensureTableLock = new();
    private volatile Task? _ensureTableTask;

    private const string PolicyTableName = "RotationPolicies";
    private const string PartitionKey = "AppApiConfig";

    public AppApiConfigService(
        TableServiceClient tableServiceClient,
        SecretClientFactory kvFactory,
        ILogger<AppApiConfigService> logger)
    {
        _policyTable = tableServiceClient.GetTableClient(PolicyTableName);
        _kvFactory = kvFactory;
        _logger = logger;
    }

    // ── Table helpers ─────────────────────────────────────────────────────────

    private Task EnsureTableExistsAsync()
    {
        var task = _ensureTableTask;
        if (task is not null && !task.IsFaulted && !task.IsCanceled)
            return task;

        lock (_ensureTableLock)
        {
            task = _ensureTableTask;
            if (task is not null && !task.IsFaulted && !task.IsCanceled)
                return task;
            return _ensureTableTask = _policyTable.CreateIfNotExistsAsync();
        }
    }

    // ── IAppApiConfigService ──────────────────────────────────────────────────

    /// <inheritdoc />
    public async Task<AppApiConfiguration?> GetConfigAsync(string appId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appId);
        await EnsureTableExistsAsync();

        try
        {
            var response = await _policyTable.GetEntityIfExistsAsync<AppApiConfiguration>(
                PartitionKey, appId, cancellationToken: ct);

            return response.HasValue ? response.Value : null;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve API config for app {AppId}", appId);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task SaveConfigAsync(AppApiConfiguration config, string? secret, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (string.IsNullOrWhiteSpace(config.RowKey))
            throw new ArgumentException("RowKey (app object ID) must be set.", nameof(config));

        // Enforce HTTPS on the API base URL before persisting.
        if (!string.IsNullOrWhiteSpace(config.ApiBaseUrl))
        {
            if (!Uri.TryCreate(config.ApiBaseUrl, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "ApiBaseUrl must be an absolute HTTPS URL.", nameof(config));
            }
        }

        await EnsureTableExistsAsync();

        config.PartitionKey = PartitionKey;
        config.UpdatedUtc = DateTimeOffset.UtcNow;

        // Persist non-secret config to Table Storage.
        await _policyTable.UpsertEntityAsync(config, TableUpdateMode.Replace, ct);
        _logger.LogInformation(
            "Saved API configuration for app {AppId} ({AppName}), authType={AuthType}",
            config.RowKey, config.AppDisplayName, config.AuthType);

        // If a secret value was supplied, write it to Key Vault.
        if (secret is not null)
        {
            await PutSecretAsync(config.GetKeyVaultSecretName(), secret, config.CredentialKeyVaultUri, ct);
        }
    }

    /// <inheritdoc />
    public async Task<string?> GetSecretAsync(AppApiConfiguration config, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        var secretName = config.GetKeyVaultSecretName();
        var kv = _kvFactory.GetClient(config.CredentialKeyVaultUri);

        try
        {
            var response = await kv.GetSecretAsync(secretName, cancellationToken: ct);
            return response.Value.Value;
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve Key Vault secret {SecretName} from {KvUri}",
                secretName, _kvFactory.GetClient(config.CredentialKeyVaultUri).VaultUri);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task DeleteConfigAsync(string appId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appId);
        await EnsureTableExistsAsync();

        try
        {
            await _policyTable.DeleteEntityAsync(PartitionKey, appId, cancellationToken: ct);
            _logger.LogInformation("Deleted API configuration for app {AppId}", appId);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Idempotent — entity already absent.
        }

        // Best-effort secret removal. Key Vault soft-delete retains it for the configured
        // retention period; this starts the delete so the name can be reused after purge.
        // Use the default vault since we no longer have the config entity's KV URI override.
        var secretName = new AppApiConfiguration { RowKey = appId }.GetKeyVaultSecretName();
        try
        {
            await _kvFactory.GetClient().StartDeleteSecretAsync(secretName, ct);
            _logger.LogInformation("Initiated Key Vault secret deletion: {SecretName}", secretName);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Secret never existed or already deleted — ignore.
        }
        catch (Exception ex)
        {
            // Non-fatal: log and continue; the table record is already gone.
            _logger.LogWarning(ex, "Could not delete Key Vault secret {SecretName} — manual cleanup may be required", secretName);
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AppApiConfiguration>> GetAllConfigsAsync(CancellationToken ct = default)
    {
        await EnsureTableExistsAsync();

        var results = new List<AppApiConfiguration>();
        await foreach (var entity in _policyTable.QueryAsync<AppApiConfiguration>(
            filter: $"PartitionKey eq '{PartitionKey}'",
            cancellationToken: ct))
        {
            results.Add(entity);
        }
        return results;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private async Task PutSecretAsync(string secretName, string secretValue, string? kvUri, CancellationToken ct)
    {
        // Key Vault secret names: 1-127 characters, alphanumerics and dashes only.
        if (string.IsNullOrWhiteSpace(secretName))
            throw new ArgumentException("Secret name must not be empty.", nameof(secretName));

        var kv = _kvFactory.GetClient(kvUri);
        await kv.SetSecretAsync(secretName, secretValue, ct);
        _logger.LogInformation("Stored/updated Key Vault secret: {SecretName}", secretName);
    }
}
