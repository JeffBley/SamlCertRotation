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
    Task<bool> ActivateCertificateAsync(string servicePrincipalId, string thumbprint);

    /// <summary>
    /// Get the custom security attribute value for an application
    /// </summary>
    Task<string?> GetCustomSecurityAttributeAsync(string servicePrincipalId, string attributeSet, string attributeName);

    /// <summary>
    /// Send an email notification via Logic App
    /// </summary>
    Task<bool> SendEmailAsync(List<string> recipients, string subject, string htmlBody);

    /// <summary>
    /// Get notification email addresses for an application (owners, etc.)
    /// </summary>
    Task<List<string>> GetAppOwnersEmailsAsync(string servicePrincipalId);

    /// <summary>
    /// Upsert sponsor tag (AppSponsor=&lt;email1;email2;...&gt;) on a service principal while preserving all other tags.
    /// Supports multiple semicolon-separated sponsor emails.
    /// </summary>
    Task<bool> UpdateAppSponsorTagAsync(string servicePrincipalId, string sponsorEmails);

    /// <summary>
    /// Remove the AppSponsor tag from a service principal while preserving all other tags
    /// </summary>
    Task<bool> ClearAppSponsorTagAsync(string servicePrincipalId);
}
