using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.ServicePrincipals.Item.AddTokenSigningCertificate;
using SamlCertRotation.Models;
using System.Text.Json;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of Microsoft Graph operations for SAML certificate management
/// </summary>
public class GraphService : IGraphService
{
    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<GraphService> _logger;
    private readonly IConfiguration _configuration;
    private readonly string _customAttributeSet;
    private readonly string _customAttributeName;

    public GraphService(
        GraphServiceClient graphClient, 
        ILogger<GraphService> logger,
        IConfiguration configuration)
    {
        _graphClient = graphClient;
        _logger = logger;
        _configuration = configuration;
        _customAttributeSet = configuration["CustomSecurityAttributeSet"] ?? "SamlCertRotation";
        _customAttributeName = configuration["CustomSecurityAttributeName"] ?? "AutoRotate";
    }

    /// <inheritdoc />
    public async Task<List<SamlApplication>> GetSamlApplicationsAsync()
    {
        var samlApps = new List<SamlApplication>();

        try
        {
            // Query service principals that are SAML-based (preferredSingleSignOnMode = 'saml')
            var servicePrincipals = await _graphClient.ServicePrincipals
                .GetAsync(config =>
                {
                    config.QueryParameters.Filter = "preferredSingleSignOnMode eq 'saml'";
                    config.QueryParameters.Select = new[] 
                    { 
                        "id", "appId", "displayName", "keyCredentials", 
                        "preferredTokenSigningKeyThumbprint", "notificationEmailAddresses",
                        "customSecurityAttributes"
                    };
                    config.QueryParameters.Top = 999;
                });

            if (servicePrincipals?.Value == null)
            {
                _logger.LogWarning("No SAML applications found in tenant");
                return samlApps;
            }

            foreach (var sp in servicePrincipals.Value)
            {
                var samlApp = MapToSamlApplication(sp);
                samlApps.Add(samlApp);
            }

            _logger.LogInformation("Found {Count} SAML applications", samlApps.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving SAML applications from Microsoft Graph");
            throw;
        }

        return samlApps;
    }

    /// <inheritdoc />
    public async Task<SamlApplication?> GetSamlApplicationAsync(string servicePrincipalId)
    {
        try
        {
            var sp = await _graphClient.ServicePrincipals[servicePrincipalId]
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] 
                    { 
                        "id", "appId", "displayName", "keyCredentials", 
                        "preferredTokenSigningKeyThumbprint", "notificationEmailAddresses",
                        "customSecurityAttributes"
                    };
                });

            return sp != null ? MapToSamlApplication(sp) : null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving SAML application {Id}", servicePrincipalId);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<SamlCertificate?> CreateSamlCertificateAsync(string servicePrincipalId, int validityInYears = 3)
    {
        try
        {
            _logger.LogInformation("Creating new SAML certificate for service principal {Id}", servicePrincipalId);

            var requestBody = new AddTokenSigningCertificatePostRequestBody
            {
                DisplayName = $"CN=SamlCertRotation-{DateTime.UtcNow:yyyyMMdd}",
                EndDateTime = DateTimeOffset.UtcNow.AddYears(validityInYears)
            };

            var result = await _graphClient.ServicePrincipals[servicePrincipalId]
                .AddTokenSigningCertificate
                .PostAsync(requestBody);

            if (result == null)
            {
                _logger.LogError("Failed to create certificate - null response");
                return null;
            }

            var newCert = new SamlCertificate
            {
                KeyId = result.KeyId?.ToString() ?? string.Empty,
                Thumbprint = result.Thumbprint ?? string.Empty,
                StartDateTime = result.StartDateTime?.UtcDateTime ?? DateTime.UtcNow,
                EndDateTime = result.EndDateTime?.UtcDateTime ?? DateTime.UtcNow.AddYears(validityInYears),
                Type = result.Type ?? "AsymmetricX509Cert",
                Usage = result.Usage ?? "Sign",
                IsActive = false
            };

            _logger.LogInformation("Created new certificate with thumbprint {Thumbprint} for {Id}", 
                newCert.Thumbprint, servicePrincipalId);

            return newCert;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating SAML certificate for {Id}", servicePrincipalId);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<bool> ActivateCertificateAsync(string servicePrincipalId, string keyId)
    {
        try
        {
            _logger.LogInformation("Activating certificate {KeyId} for service principal {Id}", 
                keyId, servicePrincipalId);

            // Get the current service principal to get the thumbprint
            var sp = await _graphClient.ServicePrincipals[servicePrincipalId]
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "keyCredentials" };
                });

            var keyCredential = sp?.KeyCredentials?.FirstOrDefault(k => k.KeyId?.ToString() == keyId);
            if (keyCredential == null)
            {
                _logger.LogError("Certificate with KeyId {KeyId} not found", keyId);
                return false;
            }

            // Update the preferredTokenSigningKeyThumbprint to activate the certificate
            var updateBody = new ServicePrincipal
            {
                PreferredTokenSigningKeyThumbprint = Convert.ToBase64String(keyCredential.CustomKeyIdentifier ?? Array.Empty<byte>())
            };

            await _graphClient.ServicePrincipals[servicePrincipalId].PatchAsync(updateBody);

            _logger.LogInformation("Successfully activated certificate {KeyId}", keyId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error activating certificate {KeyId} for {Id}", keyId, servicePrincipalId);
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<string?> GetCustomSecurityAttributeAsync(string servicePrincipalId, string attributeSet, string attributeName)
    {
        try
        {
            var sp = await _graphClient.ServicePrincipals[servicePrincipalId]
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "customSecurityAttributes" };
                });

            if (sp?.CustomSecurityAttributes?.AdditionalData == null)
            {
                return null;
            }

            // Custom security attributes are returned as a dictionary
            if (sp.CustomSecurityAttributes.AdditionalData.TryGetValue(attributeSet, out var attributeSetValue))
            {
                if (attributeSetValue is JsonElement jsonElement)
                {
                    if (jsonElement.TryGetProperty(attributeName, out var attributeValue))
                    {
                        return attributeValue.GetString();
                    }
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting custom security attribute for {Id}", servicePrincipalId);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<bool> SendEmailAsync(string senderEmail, List<string> recipients, string subject, string htmlBody)
    {
        try
        {
            if (!recipients.Any())
            {
                _logger.LogWarning("No recipients specified for email notification");
                return false;
            }

            var message = new Message
            {
                Subject = subject,
                Body = new ItemBody
                {
                    ContentType = BodyType.Html,
                    Content = htmlBody
                },
                ToRecipients = recipients.Select(r => new Recipient
                {
                    EmailAddress = new EmailAddress { Address = r }
                }).ToList()
            };

            await _graphClient.Users[senderEmail]
                .SendMail
                .PostAsync(new Microsoft.Graph.Users.Item.SendMail.SendMailPostRequestBody
                {
                    Message = message,
                    SaveToSentItems = true
                });

            _logger.LogInformation("Email sent successfully to {Count} recipients", recipients.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email notification");
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<List<string>> GetAppOwnersEmailsAsync(string servicePrincipalId)
    {
        var emails = new List<string>();

        try
        {
            // Get notification emails from service principal
            var sp = await _graphClient.ServicePrincipals[servicePrincipalId]
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "notificationEmailAddresses" };
                });

            if (sp?.NotificationEmailAddresses != null)
            {
                emails.AddRange(sp.NotificationEmailAddresses);
            }

            // Also get owners of the service principal
            var owners = await _graphClient.ServicePrincipals[servicePrincipalId].Owners.GetAsync();
            if (owners?.Value != null)
            {
                foreach (var owner in owners.Value)
                {
                    if (owner is Microsoft.Graph.Models.User user && !string.IsNullOrEmpty(user.Mail))
                    {
                        emails.Add(user.Mail);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting owners for {Id}", servicePrincipalId);
        }

        return emails.Distinct().ToList();
    }

    private SamlApplication MapToSamlApplication(ServicePrincipal sp)
    {
        var samlApp = new SamlApplication
        {
            Id = sp.Id ?? string.Empty,
            AppId = sp.AppId ?? string.Empty,
            DisplayName = sp.DisplayName ?? string.Empty,
            ActiveCertificateThumbprint = sp.PreferredTokenSigningKeyThumbprint,
            NotificationEmails = sp.NotificationEmailAddresses?.ToList() ?? new List<string>()
        };

        // Parse custom security attributes
        if (sp.CustomSecurityAttributes?.AdditionalData != null)
        {
            if (sp.CustomSecurityAttributes.AdditionalData.TryGetValue(_customAttributeSet, out var attributeSetValue))
            {
                if (attributeSetValue is JsonElement jsonElement)
                {
                    if (jsonElement.TryGetProperty(_customAttributeName, out var attributeValue))
                    {
                        samlApp.AutoRotateStatus = attributeValue.GetString();
                    }
                }
            }
        }

        // Parse certificates
        if (sp.KeyCredentials != null)
        {
            foreach (var keyCredential in sp.KeyCredentials.Where(k => k.Usage == "Sign"))
            {
                var cert = new SamlCertificate
                {
                    KeyId = keyCredential.KeyId?.ToString() ?? string.Empty,
                    Thumbprint = keyCredential.CustomKeyIdentifier != null 
                        ? Convert.ToBase64String(keyCredential.CustomKeyIdentifier) 
                        : string.Empty,
                    StartDateTime = keyCredential.StartDateTime?.UtcDateTime ?? DateTime.MinValue,
                    EndDateTime = keyCredential.EndDateTime?.UtcDateTime ?? DateTime.MaxValue,
                    Type = keyCredential.Type ?? string.Empty,
                    Usage = keyCredential.Usage ?? string.Empty,
                    IsActive = keyCredential.CustomKeyIdentifier != null &&
                               Convert.ToBase64String(keyCredential.CustomKeyIdentifier) == sp.PreferredTokenSigningKeyThumbprint
                };

                samlApp.Certificates.Add(cert);
            }
        }

        return samlApp;
    }
}
