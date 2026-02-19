using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.ServicePrincipals.Item.AddTokenSigningCertificate;
using SamlCertRotation.Models;
using Azure.Core;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Net.Http.Headers;

namespace SamlCertRotation.Services;

/// <summary>
/// Implementation of Microsoft Graph operations for SAML certificate management
/// </summary>
public class GraphService : IGraphService
{
    private const string SponsorTagPrefix = "AppSponsor=";

    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<GraphService> _logger;
    private readonly IConfiguration _configuration;
    private readonly TokenCredential _tokenCredential;
    private readonly string _customAttributeSet;
    private readonly string _customAttributeName;

    public GraphService(
        GraphServiceClient graphClient, 
        ILogger<GraphService> logger,
        IConfiguration configuration,
        TokenCredential tokenCredential)
    {
        _graphClient = graphClient;
        _logger = logger;
        _configuration = configuration;
        _tokenCredential = tokenCredential;
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
                        "customSecurityAttributes", "tags"
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

                // In some Graph responses, customSecurityAttributes can be omitted or partially populated
                // for collection queries even when requested in $select. Fallback to per-object read.
                if (string.IsNullOrWhiteSpace(samlApp.AutoRotateStatus) && !string.IsNullOrWhiteSpace(sp.Id))
                {
                    samlApp.AutoRotateStatus = await GetCustomSecurityAttributeAsync(
                        sp.Id,
                        _customAttributeSet,
                        _customAttributeName);
                }

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
                        "customSecurityAttributes", "tags"
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
    public async Task<bool> ActivateCertificateAsync(string servicePrincipalId, string thumbprint)
    {
        try
        {
            _logger.LogInformation("Activating certificate with thumbprint {Thumbprint} for service principal {Id}", 
                thumbprint, servicePrincipalId);

            if (string.IsNullOrEmpty(thumbprint))
            {
                _logger.LogError("Thumbprint is null or empty");
                return false;
            }

            // Update the preferredTokenSigningKeyThumbprint to activate the certificate
            var updateBody = new ServicePrincipal
            {
                PreferredTokenSigningKeyThumbprint = thumbprint
            };

            await _graphClient.ServicePrincipals[servicePrincipalId].PatchAsync(updateBody);

            _logger.LogInformation("Successfully activated certificate with thumbprint {Thumbprint}", thumbprint);
            return true;
        }
        catch (Microsoft.Graph.Models.ODataErrors.ODataError odataEx)
        {
            var errorMessage = odataEx.Error?.Message ?? odataEx.Message;
            var errorCode = odataEx.Error?.Code ?? "Unknown";
            _logger.LogError(odataEx, "Graph API error activating certificate: {Code} - {Message}", 
                errorCode, errorMessage);
            throw new InvalidOperationException($"Graph API error ({errorCode}): {errorMessage}", odataEx);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error activating certificate for {Id}", servicePrincipalId);
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

            if (TryGetValueIgnoreCase(sp.CustomSecurityAttributes.AdditionalData, attributeSet, out var attributeSetValue))
            {
                var sdkValue = ExtractCustomSecurityAttributeValue(attributeSetValue, attributeName);
                if (!string.IsNullOrWhiteSpace(sdkValue))
                {
                    return sdkValue;
                }
            }

            return await GetCustomSecurityAttributeViaRestAsync(servicePrincipalId, attributeSet, attributeName);
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

            // Get Logic App URL from configuration
            var logicAppUrl = _configuration["LogicAppEmailUrl"];
            if (string.IsNullOrEmpty(logicAppUrl))
            {
                _logger.LogWarning("LogicAppEmailUrl not configured - email notifications disabled");
                return false;
            }

            // Call Logic App to send email
            using var httpClient = new HttpClient();
            var payload = new
            {
                to = string.Join(";", recipients),
                subject = subject,
                body = htmlBody
            };

            var content = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(payload),
                System.Text.Encoding.UTF8,
                "application/json");

            var response = await httpClient.PostAsync(logicAppUrl, content);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Email sent successfully via Logic App to {Count} recipients", recipients.Count);
                return true;
            }
            else
            {
                _logger.LogError("Logic App returned error: {StatusCode} - {Reason}", 
                    response.StatusCode, await response.Content.ReadAsStringAsync());
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email notification via Logic App");
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

    /// <inheritdoc />
    public async Task<bool> UpdateAppSponsorTagAsync(string servicePrincipalId, string sponsorEmail)
    {
        if (string.IsNullOrWhiteSpace(servicePrincipalId))
        {
            throw new ArgumentException("Service principal ID is required.", nameof(servicePrincipalId));
        }

        if (string.IsNullOrWhiteSpace(sponsorEmail))
        {
            throw new ArgumentException("Sponsor email is required.", nameof(sponsorEmail));
        }

        var normalizedSponsorEmail = sponsorEmail.Trim();

        try
        {
            var sp = await _graphClient.ServicePrincipals[servicePrincipalId]
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "id", "tags" };
                });

            if (sp == null)
            {
                _logger.LogWarning("Service principal {Id} not found while updating sponsor tag", servicePrincipalId);
                return false;
            }

            var existingTags = (sp.Tags ?? new List<string>())
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .ToList();

            var updatedTags = existingTags
                .Where(tag => !tag.StartsWith(SponsorTagPrefix, StringComparison.OrdinalIgnoreCase))
                .ToList();

            updatedTags.Add($"{SponsorTagPrefix}{normalizedSponsorEmail}");

            var patchBody = new ServicePrincipal
            {
                Tags = updatedTags
            };

            await _graphClient.ServicePrincipals[servicePrincipalId].PatchAsync(patchBody);

            _logger.LogInformation("Updated sponsor tag for service principal {Id}", servicePrincipalId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating sponsor tag for service principal {Id}", servicePrincipalId);
            throw;
        }
    }

    private SamlApplication MapToSamlApplication(ServicePrincipal sp)
    {
        var samlApp = new SamlApplication
        {
            Id = sp.Id ?? string.Empty,
            AppId = sp.AppId ?? string.Empty,
            DisplayName = sp.DisplayName ?? string.Empty,
            ActiveCertificateThumbprint = sp.PreferredTokenSigningKeyThumbprint,
            NotificationEmails = sp.NotificationEmailAddresses?.ToList() ?? new List<string>(),
            Sponsor = ExtractSponsorFromTags(sp.Tags)
        };

        // Parse custom security attributes
        if (sp.CustomSecurityAttributes?.AdditionalData != null)
        {
            if (TryGetValueIgnoreCase(sp.CustomSecurityAttributes.AdditionalData, _customAttributeSet, out var attributeSetValue))
            {
                samlApp.AutoRotateStatus = ExtractCustomSecurityAttributeValue(attributeSetValue, _customAttributeName);
            }
        }

        // Parse certificates - use Verify credentials which contain the public certificate
        // Sign and Verify credentials are paired and have the same thumbprint
        if (sp.KeyCredentials != null)
        {
            foreach (var keyCredential in sp.KeyCredentials.Where(k => k.Usage == "Verify"))
            {
                // Calculate the thumbprint from the certificate key
                string thumbprint = string.Empty;
                if (keyCredential.Key != null && keyCredential.Key.Length > 0)
                {
                    try
                    {
                        using var x509Cert = new X509Certificate2(keyCredential.Key);
                        thumbprint = x509Cert.Thumbprint; // SHA-1 hex string (uppercase)
                    }
                    catch
                    {
                        // If we can't parse the cert, fall back to empty thumbprint
                        thumbprint = string.Empty;
                    }
                }

                var cert = new SamlCertificate
                {
                    KeyId = keyCredential.KeyId?.ToString() ?? string.Empty,
                    Thumbprint = thumbprint,
                    StartDateTime = keyCredential.StartDateTime?.UtcDateTime ?? DateTime.MinValue,
                    EndDateTime = keyCredential.EndDateTime?.UtcDateTime ?? DateTime.MaxValue,
                    Type = keyCredential.Type ?? string.Empty,
                    Usage = keyCredential.Usage ?? string.Empty,
                    IsActive = !string.IsNullOrEmpty(thumbprint) && 
                               string.Equals(thumbprint, sp.PreferredTokenSigningKeyThumbprint, StringComparison.OrdinalIgnoreCase)
                };

                samlApp.Certificates.Add(cert);
            }
        }

        return samlApp;
    }

    private static string? ExtractSponsorFromTags(List<string>? tags)
    {
        if (tags == null || tags.Count == 0)
        {
            return null;
        }

        var sponsorTag = tags.FirstOrDefault(tag =>
            !string.IsNullOrWhiteSpace(tag) &&
            tag.StartsWith(SponsorTagPrefix, StringComparison.OrdinalIgnoreCase));

        if (string.IsNullOrWhiteSpace(sponsorTag))
        {
            return null;
        }

        var sponsorEmail = sponsorTag.Substring(SponsorTagPrefix.Length).Trim();
        return string.IsNullOrWhiteSpace(sponsorEmail) ? null : sponsorEmail;
    }

    private static string? ExtractCustomSecurityAttributeValue(object? attributeSetValue, string attributeName)
    {
        if (attributeSetValue == null)
        {
            return null;
        }

        if (attributeSetValue is JsonElement jsonElement)
        {
            return TryGetStringFromJsonElement(jsonElement, attributeName);
        }

        if (attributeSetValue is IDictionary<string, object> dictionary &&
            TryGetValueIgnoreCase(dictionary, attributeName, out var rawValue))
        {
            return ConvertRawAttributeValueToString(rawValue);
        }

        try
        {
            var serialized = JsonSerializer.Serialize(attributeSetValue);
            if (string.IsNullOrWhiteSpace(serialized))
            {
                return null;
            }

            using var doc = JsonDocument.Parse(serialized);
            return TryGetStringFromJsonElement(doc.RootElement, attributeName);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetStringFromJsonElement(JsonElement container, string attributeName)
    {
        if (container.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!TryGetPropertyIgnoreCase(container, attributeName, out var attributeValue))
        {
            return null;
        }

        return attributeValue.ValueKind switch
        {
            JsonValueKind.String => attributeValue.GetString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Number => attributeValue.ToString(),
            _ => null
        };
    }

    private static string? ConvertRawAttributeValueToString(object? rawValue)
    {
        if (rawValue == null)
        {
            return null;
        }

        if (rawValue is string str)
        {
            return str;
        }

        if (rawValue is JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Number => element.ToString(),
                _ => null
            };
        }

        return rawValue.ToString();
    }

    private static bool TryGetValueIgnoreCase(IDictionary<string, object> dictionary, string key, out object? value)
    {
        if (dictionary.TryGetValue(key, out value))
        {
            return true;
        }

        foreach (var pair in dictionary)
        {
            if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                value = pair.Value;
                return true;
            }
        }

        value = null;
        return false;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement container, string propertyName, out JsonElement value)
    {
        if (container.TryGetProperty(propertyName, out value))
        {
            return true;
        }

        foreach (var property in container.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private async Task<string?> GetCustomSecurityAttributeViaRestAsync(string servicePrincipalId, string attributeSet, string attributeName)
    {
        try
        {
            var token = await _tokenCredential.GetTokenAsync(
                new TokenRequestContext(new[] { "https://graph.microsoft.com/.default" }),
                CancellationToken.None);

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

            var requestUrl = $"https://graph.microsoft.com/v1.0/servicePrincipals/{servicePrincipalId}?$select=customSecurityAttributes";
            var response = await httpClient.GetAsync(requestUrl);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Raw Graph CSA read failed for {Id}. Status: {Status}",
                    servicePrincipalId,
                    (int)response.StatusCode);
                return null;
            }

            using var contentStream = await response.Content.ReadAsStreamAsync();
            using var document = await JsonDocument.ParseAsync(contentStream);

            if (!document.RootElement.TryGetProperty("customSecurityAttributes", out var csaElement) ||
                csaElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!TryGetPropertyIgnoreCase(csaElement, attributeSet, out var setElement))
            {
                return null;
            }

            return TryGetStringFromJsonElement(setElement, attributeName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Raw Graph fallback failed for custom security attribute read for {Id}", servicePrincipalId);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<ClientSecretInfo?> RotateAppClientSecretAsync(string clientId)
    {
        _logger.LogInformation("Rotating client secret for application {ClientId}", clientId);

        try
        {
            // First, find the application by clientId (appId)
            var apps = await _graphClient.Applications
                .GetAsync(config =>
                {
                    config.QueryParameters.Filter = $"appId eq '{clientId}'";
                    config.QueryParameters.Select = new[] { "id", "appId", "displayName", "passwordCredentials" };
                });

            var app = apps?.Value?.FirstOrDefault();
            if (app == null)
            {
                _logger.LogWarning("Application not found with clientId {ClientId}", clientId);
                return null;
            }

            // Add a new password credential
            var passwordCredential = new PasswordCredential
            {
                DisplayName = $"Dashboard Secret - {DateTime.UtcNow:yyyy-MM-dd}",
                EndDateTime = DateTimeOffset.UtcNow.AddYears(2)
            };

            var newSecret = await _graphClient.Applications[app.Id]
                .AddPassword
                .PostAsync(new Microsoft.Graph.Applications.Item.AddPassword.AddPasswordPostRequestBody
                {
                    PasswordCredential = passwordCredential
                });

            if (newSecret == null)
            {
                _logger.LogError("Failed to create new secret for {ClientId}", clientId);
                return null;
            }

            _logger.LogInformation("Successfully created new client secret for {ClientId}", clientId);

            return new ClientSecretInfo
            {
                Hint = newSecret.Hint ?? newSecret.SecretText?.Substring(0, Math.Min(4, newSecret.SecretText?.Length ?? 0)) ?? "",
                EndDateTime = newSecret.EndDateTime?.UtcDateTime ?? DateTime.UtcNow.AddYears(2),
                SecretValue = newSecret.SecretText
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error rotating client secret for {ClientId}", clientId);
            throw;
        }
    }
}
