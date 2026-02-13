using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SamlCertRotation.Services;

/// <summary>
/// Service for managing Static Web App settings using Azure REST API
/// </summary>
public class SwaSettingsService : ISwaSettingsService
{
    private readonly ILogger<SwaSettingsService> _logger;
    private readonly IConfiguration _configuration;
    private readonly string? _subscriptionId;
    private readonly string? _resourceGroupName;
    private readonly string? _swaName;
    private readonly DefaultAzureCredential? _credential;
    private readonly HttpClient _httpClient;

    private const string ArmEndpoint = "https://management.azure.com";
    private const string ApiVersion = "2023-01-01";

    public SwaSettingsService(ILogger<SwaSettingsService> logger, IConfiguration configuration, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _configuration = configuration;
        _httpClient = httpClientFactory.CreateClient();
        
        _subscriptionId = configuration["SubscriptionId"];
        _resourceGroupName = configuration["SwaResourceGroup"];
        _swaName = configuration["SwaName"];

        // Initialize credential with managed identity
        if (!string.IsNullOrEmpty(_subscriptionId) && 
            !string.IsNullOrEmpty(_resourceGroupName) && 
            !string.IsNullOrEmpty(_swaName))
        {
            _credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ManagedIdentityClientId = configuration["AZURE_CLIENT_ID"]
            });
        }
    }

    /// <inheritdoc />
    public async Task<bool> UpdateClientSecretAsync(string newSecretValue)
    {
        if (_credential == null || string.IsNullOrEmpty(_subscriptionId) || 
            string.IsNullOrEmpty(_resourceGroupName) || string.IsNullOrEmpty(_swaName))
        {
            _logger.LogWarning("SWA settings not configured. Set SubscriptionId, SwaResourceGroup, and SwaName in Function App settings.");
            return false;
        }

        try
        {
            _logger.LogInformation("Updating SWA client secret for {SwaName}", _swaName);

            // Get access token for ARM
            var tokenRequestContext = new TokenRequestContext(new[] { $"{ArmEndpoint}/.default" });
            var accessToken = await _credential.GetTokenAsync(tokenRequestContext);
            
            // First, get current app settings
            var getUrl = $"{ArmEndpoint}/subscriptions/{_subscriptionId}/resourceGroups/{_resourceGroupName}/providers/Microsoft.Web/staticSites/{_swaName}/listAppSettings?api-version={ApiVersion}";
            
            var getRequest = new HttpRequestMessage(HttpMethod.Post, getUrl);
            getRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken.Token);
            
            var getResponse = await _httpClient.SendAsync(getRequest);
            if (!getResponse.IsSuccessStatusCode)
            {
                var errorContent = await getResponse.Content.ReadAsStringAsync();
                _logger.LogError("Failed to get current SWA settings: {StatusCode} - {Error}", getResponse.StatusCode, errorContent);
                return false;
            }
            
            var currentSettingsJson = await getResponse.Content.ReadAsStringAsync();
            var currentSettings = JsonSerializer.Deserialize<SwaAppSettings>(currentSettingsJson);
            
            // Update the AAD_CLIENT_SECRET in the dictionary
            currentSettings ??= new SwaAppSettings();
            currentSettings.Properties ??= new Dictionary<string, string>();
            currentSettings.Properties["AAD_CLIENT_SECRET"] = newSecretValue;
            
            // PUT the updated settings
            var putUrl = $"{ArmEndpoint}/subscriptions/{_subscriptionId}/resourceGroups/{_resourceGroupName}/providers/Microsoft.Web/staticSites/{_swaName}/config/appsettings?api-version={ApiVersion}";
            
            var putRequest = new HttpRequestMessage(HttpMethod.Put, putUrl);
            putRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken.Token);
            putRequest.Content = new StringContent(
                JsonSerializer.Serialize(new { properties = currentSettings.Properties }),
                Encoding.UTF8,
                "application/json");
            
            var putResponse = await _httpClient.SendAsync(putRequest);
            if (!putResponse.IsSuccessStatusCode)
            {
                var errorContent = await putResponse.Content.ReadAsStringAsync();
                _logger.LogError("Failed to update SWA settings: {StatusCode} - {Error}", putResponse.StatusCode, errorContent);
                return false;
            }
            
            _logger.LogInformation("Successfully updated SWA client secret");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update SWA client secret: {Message}", ex.Message);
            return false;
        }
    }

    private class SwaAppSettings
    {
        public Dictionary<string, string>? Properties { get; set; }
    }
}
