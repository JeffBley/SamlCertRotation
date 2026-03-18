using System.Collections.Concurrent;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SamlCertRotation.Services;

/// <summary>
/// Creates and caches <see cref="SecretClient"/> instances per Key Vault URI.
///
/// The managed identity works against any vault in the same Entra tenant, so no
/// additional auth configuration is needed for non-default vaults.
///
/// Thread-safe: a ConcurrentDictionary ensures only one client is lazily created
/// per unique vault URI, even under concurrent access.
/// </summary>
public class SecretClientFactory
{
    private readonly TokenCredential _credential;
    private readonly string _defaultKvUri;
    private readonly ConcurrentDictionary<string, SecretClient> _clients = new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger<SecretClientFactory> _logger;

    public SecretClientFactory(
        TokenCredential credential,
        IConfiguration configuration,
        ILogger<SecretClientFactory> logger)
    {
        _credential = credential;
        _defaultKvUri = configuration["KeyVaultUri"]
            ?? throw new InvalidOperationException(
                "KeyVaultUri is not configured. Ensure the app setting is set.");
        _logger = logger;
    }

    /// <summary>
    /// Returns a <see cref="SecretClient"/> for the specified vault URI,
    /// or for the default global vault if <paramref name="kvUri"/> is null or empty.
    /// </summary>
    public SecretClient GetClient(string? kvUri = null)
    {
        var uri = string.IsNullOrWhiteSpace(kvUri) ? _defaultKvUri : kvUri.TrimEnd('/');

        return _clients.GetOrAdd(uri, u =>
        {
            _logger.LogDebug("Creating SecretClient for vault: {KvUri}", u);
            return new SecretClient(new Uri(u), _credential);
        });
    }

    /// <summary>The default global Key Vault URI from app configuration.</summary>
    public string DefaultKvUri => _defaultKvUri;
}
