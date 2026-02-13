using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// Interface for Microsoft Graph operations
/// </summary>
public interface IGraphService
{
    /// <summary>
    /// Get all SAML enterprise applications in the tenant
    /// </summary>
    Task<List<SamlApplication>> GetSamlApplicationsAsync();

    /// <summary>
    /// Get a specific SAML application by service principal ID
    /// </summary>
    Task<SamlApplication?> GetSamlApplicationAsync(string servicePrincipalId);

    /// <summary>
    /// Create a new SAML signing certificate for an application
    /// </summary>
    Task<SamlCertificate?> CreateSamlCertificateAsync(string servicePrincipalId, int validityInYears = 3);

    /// <summary>
    /// Set a certificate as the active SAML signing certificate
    /// </summary>
    Task<bool> ActivateCertificateAsync(string servicePrincipalId, string keyId);

    /// <summary>
    /// Get the custom security attribute value for an application
    /// </summary>
    Task<string?> GetCustomSecurityAttributeAsync(string servicePrincipalId, string attributeSet, string attributeName);

    /// <summary>
    /// Send an email notification via Microsoft Graph
    /// </summary>
    Task<bool> SendEmailAsync(string senderEmail, List<string> recipients, string subject, string htmlBody);

    /// <summary>
    /// Get notification email addresses for an application (owners, etc.)
    /// </summary>
    Task<List<string>> GetAppOwnersEmailsAsync(string servicePrincipalId);

    /// <summary>
    /// Delete inactive certificates for an application
    /// </summary>
    Task<int> DeleteInactiveCertificatesAsync(string servicePrincipalId, List<string> keyIds);

    /// <summary>
    /// Rotate an application's client secret and return the new secret info
    /// </summary>
    Task<ClientSecretInfo?> RotateAppClientSecretAsync(string clientId);
}
