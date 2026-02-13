using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// Function to automatically rotate the SWA Dashboard app registration client secret.
/// Runs daily and creates a new secret when the current one is within 30 days of expiration.
/// </summary>
public class ClientSecretRotationFunction
{
    private readonly ILogger<ClientSecretRotationFunction> _logger;
    private readonly IConfiguration _configuration;
    private readonly GraphServiceClient _graphClient;
    private readonly SecretClient? _secretClient;
    private readonly ISwaSettingsService _swaSettingsService;

    // Key Vault secret name for storing the SWA client secret
    private const string SwaClientSecretName = "SwaClientSecret";
    private const int DaysBeforeExpiryToRotate = 30;
    private const int NewSecretValidityYears = 2;

    public ClientSecretRotationFunction(
        ILogger<ClientSecretRotationFunction> logger,
        IConfiguration configuration,
        ISwaSettingsService swaSettingsService)
    {
        _logger = logger;
        _configuration = configuration;
        _swaSettingsService = swaSettingsService;

        // Initialize Graph client with managed identity
        var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ManagedIdentityClientId = configuration["AZURE_CLIENT_ID"]
        });

        _graphClient = new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });

        // Initialize Key Vault client
        var keyVaultUri = configuration["KeyVaultUri"];
        if (!string.IsNullOrEmpty(keyVaultUri))
        {
            _secretClient = new SecretClient(new Uri(keyVaultUri), credential);
        }
        else
        {
            _logger.LogWarning("KeyVaultUri not configured - secret rotation will not work");
        }
    }

    /// <summary>
    /// Timer-triggered function to check and rotate the SWA client secret.
    /// Runs daily at 3:00 AM UTC.
    /// </summary>
    [Function("RotateSwaClientSecret")]
    public async Task RotateSwaClientSecret(
        [TimerTrigger("0 0 3 * * *")] TimerInfo timerInfo)
    {
        _logger.LogInformation("Starting SWA client secret rotation check at {Time}", DateTime.UtcNow);

        if (_secretClient == null)
        {
            _logger.LogError("Key Vault client not initialized - cannot rotate secrets");
            return;
        }

        var swaClientId = _configuration["SWA_CLIENT_ID"];
        if (string.IsNullOrEmpty(swaClientId))
        {
            _logger.LogWarning("SWA_CLIENT_ID not configured - skipping secret rotation");
            return;
        }

        try
        {
            await CheckAndRotateSecretAsync(swaClientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during SWA client secret rotation");
            throw;
        }
    }

    private async Task CheckAndRotateSecretAsync(string clientId)
    {
        // Get the app registration
        var app = await _graphClient.Applications
            .GetAsync(config => config.QueryParameters.Filter = $"appId eq '{clientId}'");

        if (app?.Value == null || app.Value.Count == 0)
        {
            _logger.LogError("App registration not found for client ID: {ClientId}", clientId);
            return;
        }

        var appRegistration = app.Value[0];
        var appObjectId = appRegistration.Id;

        _logger.LogInformation("Checking credentials for app: {AppName} ({ClientId})", 
            appRegistration.DisplayName, clientId);

        // Get current password credentials
        var credentials = appRegistration.PasswordCredentials ?? new List<PasswordCredential>();
        
        // Find credentials that are still valid
        var validCredentials = credentials
            .Where(c => c.EndDateTime.HasValue && c.EndDateTime.Value > DateTimeOffset.UtcNow)
            .OrderByDescending(c => c.EndDateTime)
            .ToList();

        if (validCredentials.Count == 0)
        {
            _logger.LogWarning("No valid credentials found - creating new secret immediately");
            await CreateAndStoreNewSecretAsync(appObjectId!, clientId);
            return;
        }

        // Check if the newest credential is expiring within threshold
        var newestCredential = validCredentials.First();
        var daysUntilExpiry = (newestCredential.EndDateTime!.Value - DateTimeOffset.UtcNow).TotalDays;

        _logger.LogInformation("Newest credential expires in {Days:F1} days on {ExpiryDate}", 
            daysUntilExpiry, newestCredential.EndDateTime.Value);

        if (daysUntilExpiry <= DaysBeforeExpiryToRotate)
        {
            _logger.LogInformation("Credential is within {Threshold} days of expiry - rotating", 
                DaysBeforeExpiryToRotate);
            
            // Create new secret
            var newCredentialKeyId = await CreateAndStoreNewSecretAsync(appObjectId!, clientId);

            // Clean up old credentials (keep only the newest one besides the one we just created)
            await CleanupOldCredentialsAsync(appObjectId!, newCredentialKeyId, validCredentials);
        }
        else
        {
            _logger.LogInformation("Credential is not expiring soon - no rotation needed");
        }
    }

    private async Task<Guid> CreateAndStoreNewSecretAsync(string appObjectId, string clientId)
    {
        _logger.LogInformation("Creating new client secret for app {AppObjectId}", appObjectId);

        // Create new password credential
        var newCredential = new PasswordCredential
        {
            DisplayName = $"SWA Auth Secret (Auto-rotated {DateTime.UtcNow:yyyy-MM-dd})",
            EndDateTime = DateTimeOffset.UtcNow.AddYears(NewSecretValidityYears)
        };

        var result = await _graphClient.Applications[appObjectId]
            .AddPassword
            .PostAsync(new Microsoft.Graph.Applications.Item.AddPassword.AddPasswordPostRequestBody
            {
                PasswordCredential = newCredential
            });

        if (result?.SecretText == null)
        {
            throw new InvalidOperationException("Failed to create new password credential");
        }

        _logger.LogInformation("New credential created with key ID: {KeyId}, expires: {Expiry}", 
            result.KeyId, result.EndDateTime);

        // Store in Key Vault
        var secret = new KeyVaultSecret(SwaClientSecretName, result.SecretText)
        {
            Properties =
            {
                ExpiresOn = result.EndDateTime,
                ContentType = "application/x-password",
                Tags =
                {
                    ["AppClientId"] = clientId,
                    ["KeyId"] = result.KeyId?.ToString() ?? "",
                    ["CreatedBy"] = "SamlCertRotation-AutoRotate"
                }
            }
        };

        await _secretClient!.SetSecretAsync(secret);
        _logger.LogInformation("Secret stored in Key Vault as '{SecretName}'", SwaClientSecretName);

        // Update the SWA app settings with the new secret
        var swaUpdated = await _swaSettingsService.UpdateClientSecretAsync(result.SecretText);
        if (swaUpdated)
        {
            _logger.LogInformation("SWA app settings updated with new client secret");
        }
        else
        {
            _logger.LogWarning("Failed to update SWA app settings - manual update may be required");
        }

        return result.KeyId ?? Guid.Empty;
    }

    private async Task CleanupOldCredentialsAsync(
        string appObjectId, 
        Guid newCredentialKeyId, 
        List<PasswordCredential> validCredentials)
    {
        // Keep only the credential we just created
        // Remove all others to prevent credential sprawl
        var credentialsToRemove = validCredentials
            .Where(c => c.KeyId != newCredentialKeyId)
            .ToList();

        foreach (var credential in credentialsToRemove)
        {
            try
            {
                _logger.LogInformation("Removing old credential with key ID: {KeyId}", credential.KeyId);
                
                await _graphClient.Applications[appObjectId]
                    .RemovePassword
                    .PostAsync(new Microsoft.Graph.Applications.Item.RemovePassword.RemovePasswordPostRequestBody
                    {
                        KeyId = credential.KeyId
                    });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to remove old credential {KeyId} - will retry on next run", 
                    credential.KeyId);
            }
        }
    }
}
