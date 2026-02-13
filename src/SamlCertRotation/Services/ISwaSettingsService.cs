namespace SamlCertRotation.Services;

/// <summary>
/// Service for managing Static Web App settings
/// </summary>
public interface ISwaSettingsService
{
    /// <summary>
    /// Updates the AAD_CLIENT_SECRET app setting in the Static Web App
    /// </summary>
    /// <param name="newSecretValue">The new client secret value</param>
    /// <returns>True if successful, false otherwise</returns>
    Task<bool> UpdateClientSecretAsync(string newSecretValue);
}
