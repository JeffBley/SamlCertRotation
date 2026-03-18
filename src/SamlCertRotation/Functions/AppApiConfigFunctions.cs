using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// Admin-only HTTP functions for managing per-app API access configuration
/// and for calling back into SAML application control-plane APIs to read
/// or activate SAML signing keys.
///
/// Routes:
///   GET  api/applications/{id}/api-config           — get stored config (no secret)
///   PUT  api/applications/{id}/api-config           — save/update config + secret
///   DELETE api/applications/{id}/api-config         — remove config
///   GET  api/applications/{id}/api-config/keys      — fetch keys from app's API
///   POST api/applications/{id}/api-config/activate  — activate a key on the app
/// </summary>
public class AppApiConfigFunctions : DashboardFunctionBase
{
    private readonly IAppApiConfigService _appApiConfigService;
    private readonly IAppApiClient _appApiClient;

    public AppApiConfigFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<AppApiConfigFunctions> logger,
        IAppApiConfigService appApiConfigService,
        IAppApiClient appApiClient)
        : base(rotationService, graphService, policyService, auditService,
               notificationService, reportService, configuration, logger)
    {
        _appApiConfigService = appApiConfigService;
        _appApiClient = appApiClient;
    }

    // ── GET api/applications/{id}/api-config ──────────────────────────────────

    /// <summary>
    /// Returns the stored API configuration for an app (never includes the raw secret).
    /// Returns 404 if no configuration has been saved.
    /// </summary>
    [Function("GetAppApiConfig")]
    public async Task<HttpResponseData> GetAppApiConfig(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get",
            Route = "applications/{id}/api-config")] HttpRequestData req,
        string id)
    {
        var (authError, _) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
            return await CreateErrorResponse(req, "Invalid application ID format.", HttpStatusCode.BadRequest);

        try
        {
            var config = await _appApiConfigService.GetConfigAsync(id);
            if (config is null)
                return await CreateErrorResponse(req, "No API configuration found for this application.", HttpStatusCode.NotFound);

            return await CreateJsonResponse(req, ToDto(config));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get API config for app {AppId}", id);
            return await CreateErrorResponse(req, SanitizeErrorMessage(ex.Message), HttpStatusCode.InternalServerError);
        }
    }

    // ── PUT api/applications/{id}/api-config ──────────────────────────────────

    /// <summary>
    /// Creates or updates the API configuration for an app.
    /// The request body may include a <c>secret</c> field; pass null/omit to leave
    /// an existing secret unchanged.
    /// </summary>
    [Function("SaveAppApiConfig")]
    public async Task<HttpResponseData> SaveAppApiConfig(
        [HttpTrigger(AuthorizationLevel.Anonymous, "put",
            Route = "applications/{id}/api-config")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
            return await CreateErrorResponse(req, "Invalid application ID format.", HttpStatusCode.BadRequest);

        AppApiConfigRequest? body;
        try
        {
            body = await JsonSerializer.DeserializeAsync<AppApiConfigRequest>(
                req.Body, JsonDeserializeOptions);
        }
        catch (JsonException)
        {
            return await CreateErrorResponse(req, "Invalid JSON body.", HttpStatusCode.BadRequest);
        }

        if (body is null)
            return await CreateErrorResponse(req, "Request body is required.", HttpStatusCode.BadRequest);

        // Validate auth type code is a known enum value.
        if (!Enum.IsDefined(typeof(ApiAuthType), body.AuthTypeCode))
            return await CreateErrorResponse(req, $"Unknown auth type code: {body.AuthTypeCode}.", HttpStatusCode.BadRequest);

        // Validate HTTPS requirement.
        if (!string.IsNullOrWhiteSpace(body.ApiBaseUrl))
        {
            if (!Uri.TryCreate(body.ApiBaseUrl, UriKind.Absolute, out var parsedUri) ||
                !string.Equals(parsedUri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                return await CreateErrorResponse(req, "ApiBaseUrl must be an absolute HTTPS URL.", HttpStatusCode.BadRequest);
            }
        }

        // Validate OAuth-specific required fields.
        var authType = (ApiAuthType)body.AuthTypeCode;
        if (authType is ApiAuthType.OAuthClientCredentials or ApiAuthType.OAuthSamlAssertionGrant)
        {
            if (string.IsNullOrWhiteSpace(body.OAuthTokenEndpoint))
                return await CreateErrorResponse(req, "OAuthTokenEndpoint is required for the selected auth type.", HttpStatusCode.BadRequest);
        }

        // Look up the SP display name from Graph to keep our record in sync.
        string? displayName = null;
        try
        {
            var app = await _graphService.GetSamlApplicationAsync(id);
            displayName = app?.DisplayName;
        }
        catch
        {
            // Non-blocking — fall back to what the caller provided.
        }

        var config = new AppApiConfiguration
        {
            RowKey = id,
            AppDisplayName = displayName ?? body.AppDisplayName ?? string.Empty,
            ApiBaseUrl = body.ApiBaseUrl ?? string.Empty,
            AuthTypeCode = body.AuthTypeCode,
            ApiKeyHeaderName = body.ApiKeyHeaderName,
            ApiKeyHeaderPrefix = body.ApiKeyHeaderPrefix,
            OAuthTokenEndpoint = body.OAuthTokenEndpoint,
            OAuthClientId = body.OAuthClientId,
            OAuthScope = body.OAuthScope,
            GetKeysRoute = body.GetKeysRoute,
            ActivateKeyRoute = body.ActivateKeyRoute,
            ConnectionId = body.ConnectionId,
            UpdatedBy = identity?.UserId ?? identity?.UserPrincipalName ?? "admin"
        };

        try
        {
            // body.Secret == null means "don't update the existing secret".
            await _appApiConfigService.SaveConfigAsync(config, body.Secret);

            await _auditService.LogSuccessAsync(
                id, displayName ?? id,
                AuditActionType.SettingsUpdated,
                $"API access configuration saved for app. Auth type: {authType}",
                performedBy: identity?.UserId ?? "admin");

            return await CreateJsonResponse(req, ToDto(config));
        }
        catch (ArgumentException aex)
        {
            return await CreateErrorResponse(req, aex.Message, HttpStatusCode.BadRequest);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save API config for app {AppId}", id);
            return await CreateErrorResponse(req, SanitizeErrorMessage(ex.Message), HttpStatusCode.InternalServerError);
        }
    }

    // ── DELETE api/applications/{id}/api-config ───────────────────────────────

    /// <summary>
    /// Removes the API configuration and deletes the Key Vault secret for an app.
    /// </summary>
    [Function("DeleteAppApiConfig")]
    public async Task<HttpResponseData> DeleteAppApiConfig(
        [HttpTrigger(AuthorizationLevel.Anonymous, "delete",
            Route = "applications/{id}/api-config")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
            return await CreateErrorResponse(req, "Invalid application ID format.", HttpStatusCode.BadRequest);

        try
        {
            await _appApiConfigService.DeleteConfigAsync(id);

            await _auditService.LogSuccessAsync(
                id, id,
                AuditActionType.SettingsUpdated,
                "API access configuration removed.",
                performedBy: identity?.UserId ?? "admin");

            return req.CreateResponse(HttpStatusCode.NoContent);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete API config for app {AppId}", id);
            return await CreateErrorResponse(req, SanitizeErrorMessage(ex.Message), HttpStatusCode.InternalServerError);
        }
    }

    // ── GET api/applications/{id}/api-config/keys ─────────────────────────────

    /// <summary>
    /// Calls the target SAML application's API to retrieve its known SAML signing certificates.
    /// Requires a saved API configuration for the app.
    /// </summary>
    [Function("GetAppRemoteKeys")]
    public async Task<HttpResponseData> GetAppRemoteKeys(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get",
            Route = "applications/{id}/api-config/keys")] HttpRequestData req,
        string id)
    {
        var (authError, _) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
            return await CreateErrorResponse(req, "Invalid application ID format.", HttpStatusCode.BadRequest);

        try
        {
            var config = await _appApiConfigService.GetConfigAsync(id);
            if (config is null)
                return await CreateErrorResponse(req,
                    "No API configuration found. Configure API access for this application first.",
                    HttpStatusCode.NotFound);

            var keys = await _appApiClient.GetRemoteKeysAsync(config);

            return await CreateJsonResponse(req, new
            {
                appId = id,
                appDisplayName = config.AppDisplayName,
                retrievedUtc = DateTimeOffset.UtcNow,
                keys = keys.Select(k => new
                {
                    certId = k.CertId,
                    thumbprint = k.Thumbprint,
                    subject = k.Subject,
                    issuer = k.Issuer,
                    notBeforeUtc = k.NotBeforeUtc,
                    notAfterUtc = k.NotAfterUtc,
                    state = k.State,
                    isActive = k.IsActive,
                    daysUntilExpiry = k.DaysUntilExpiry
                })
            });
        }
        catch (InvalidOperationException ioex)
        {
            // Missing secret or misconfiguration — surface as 400 (caller can fix it).
            return await CreateErrorResponse(req, ioex.Message, HttpStatusCode.BadRequest);
        }
        catch (HttpRequestException hrex)
        {
            _logger.LogError(hrex, "Remote API call failed for app {AppId}", id);
            return await CreateErrorResponse(req,
                $"Failed to fetch keys from the application's API: {SanitizeErrorMessage(hrex.Message)}",
                HttpStatusCode.BadGateway);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get remote keys for app {AppId}", id);
            return await CreateErrorResponse(req, SanitizeErrorMessage(ex.Message), HttpStatusCode.InternalServerError);
        }
    }

    // ── POST api/applications/{id}/api-config/activate ────────────────────────

    /// <summary>
    /// Instructs the target SAML application to promote a specific signing certificate
    /// to the active state.
    /// Body: { "certId": "&lt;cert-identifier&gt;", "reason": "&lt;optional&gt;" }
    /// </summary>
    [Function("ActivateAppRemoteKey")]
    public async Task<HttpResponseData> ActivateAppRemoteKey(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post",
            Route = "applications/{id}/api-config/activate")] HttpRequestData req,
        string id)
    {
        var (authError, identity) = await AuthorizeRequestAsync(req, requireAdmin: true);
        if (authError != null) return authError;

        if (!IsValidGuid(id))
            return await CreateErrorResponse(req, "Invalid application ID format.", HttpStatusCode.BadRequest);

        ActivateRemoteKeyRequest? body;
        try
        {
            body = await JsonSerializer.DeserializeAsync<ActivateRemoteKeyRequest>(
                req.Body, JsonDeserializeOptions);
        }
        catch (JsonException)
        {
            return await CreateErrorResponse(req, "Invalid JSON body.", HttpStatusCode.BadRequest);
        }

        if (body is null || string.IsNullOrWhiteSpace(body.CertId))
            return await CreateErrorResponse(req, "certId is required.", HttpStatusCode.BadRequest);

        try
        {
            var config = await _appApiConfigService.GetConfigAsync(id);
            if (config is null)
                return await CreateErrorResponse(req,
                    "No API configuration found. Configure API access for this application first.",
                    HttpStatusCode.NotFound);

            await _appApiClient.ActivateRemoteKeyAsync(config, body.CertId, body.Reason);

            await _auditService.LogSuccessAsync(
                id, config.AppDisplayName,
                AuditActionType.CertificateActivated,
                $"Remote key activation via control-plane API. CertId={body.CertId}. Reason: {body.Reason ?? "none"}",
                certificateThumbprint: body.CertId,
                performedBy: identity?.UserId ?? "admin");

            return await CreateJsonResponse(req, new
            {
                appId = id,
                certId = body.CertId,
                activatedUtc = DateTimeOffset.UtcNow,
                message = "Activation request accepted by the application's API."
            });
        }
        catch (InvalidOperationException ioex)
        {
            return await CreateErrorResponse(req, ioex.Message, HttpStatusCode.BadRequest);
        }
        catch (HttpRequestException hrex)
        {
            _logger.LogError(hrex, "Remote activate call failed for app {AppId}", id);

            await _auditService.LogFailureAsync(
                id, id,
                AuditActionType.CertificateActivated,
                $"Remote key activation failed. CertId={body.CertId}",
                hrex.Message,
                performedBy: identity?.UserId ?? "admin");

            return await CreateErrorResponse(req,
                $"Failed to activate key on the application's API: {SanitizeErrorMessage(hrex.Message)}",
                HttpStatusCode.BadGateway);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to activate remote key for app {AppId}", id);
            return await CreateErrorResponse(req, SanitizeErrorMessage(ex.Message), HttpStatusCode.InternalServerError);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>Maps an <see cref="AppApiConfiguration"/> to a DTO safe for wire transfer (no secrets).</summary>
    private static AppApiConfigDto ToDto(AppApiConfiguration c) => new()
    {
        AppId = c.RowKey,
        AppDisplayName = c.AppDisplayName,
        ApiBaseUrl = c.ApiBaseUrl,
        AuthTypeCode = c.AuthTypeCode,
        AuthTypeName = c.AuthType.ToString(),
        ApiKeyHeaderName = c.ApiKeyHeaderName,
        ApiKeyHeaderPrefix = c.ApiKeyHeaderPrefix,
        OAuthTokenEndpoint = c.OAuthTokenEndpoint,
        OAuthClientId = c.OAuthClientId,
        OAuthScope = c.OAuthScope,
        GetKeysRoute = c.GetKeysRoute,
        ActivateKeyRoute = c.ActivateKeyRoute,
        ConnectionId = c.ConnectionId,
        UpdatedUtc = c.UpdatedUtc,
        UpdatedBy = c.UpdatedBy,
        HasSecret = true  // We can't verify without a round-trip to KV; callers can test via /keys.
    };
}

// ── Request / response DTOs ───────────────────────────────────────────────────

/// <summary>Wire format for saving an API configuration.</summary>
public sealed class AppApiConfigRequest
{
    public string? AppDisplayName { get; set; }
    public string? ApiBaseUrl { get; set; }

    /// <summary>See <see cref="ApiAuthType"/> for valid values (1–4).</summary>
    public int AuthTypeCode { get; set; }

    // Option 1 / 4
    public string? ApiKeyHeaderName { get; set; }
    public string? ApiKeyHeaderPrefix { get; set; }

    // Option 2 / 3
    public string? OAuthTokenEndpoint { get; set; }
    public string? OAuthClientId { get; set; }
    public string? OAuthScope { get; set; }

    // Routing
    public string? GetKeysRoute { get; set; }
    public string? ActivateKeyRoute { get; set; }
    public string? ConnectionId { get; set; }

    /// <summary>
    /// The raw secret to store in Key Vault (API key, OAuth client secret, SAML assertion, etc.).
    /// Omit or pass null to leave an existing secret unchanged.
    /// </summary>
    public string? Secret { get; set; }
}

/// <summary>Wire format for requesting remote key activation.</summary>
public sealed class ActivateRemoteKeyRequest
{
    public string? CertId { get; set; }
    public string? Reason { get; set; }
}

/// <summary>Read-only wire format returned from GET endpoints (never contains the secret).</summary>
public sealed class AppApiConfigDto
{
    public string AppId { get; set; } = string.Empty;
    public string AppDisplayName { get; set; } = string.Empty;
    public string ApiBaseUrl { get; set; } = string.Empty;
    public int AuthTypeCode { get; set; }
    public string AuthTypeName { get; set; } = string.Empty;
    public string? ApiKeyHeaderName { get; set; }
    public string? ApiKeyHeaderPrefix { get; set; }
    public string? OAuthTokenEndpoint { get; set; }
    public string? OAuthClientId { get; set; }
    public string? OAuthScope { get; set; }
    public string? GetKeysRoute { get; set; }
    public string? ActivateKeyRoute { get; set; }
    public string? ConnectionId { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }
    public string? UpdatedBy { get; set; }

    /// <summary>True when a secret is believed to be present in Key Vault.</summary>
    public bool HasSecret { get; set; }
}
