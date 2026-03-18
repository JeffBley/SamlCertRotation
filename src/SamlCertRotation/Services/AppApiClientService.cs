using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Models;

namespace SamlCertRotation.Services;

/// <summary>
/// HTTP client wrapper that calls a target SAML application's control-plane API.
///
/// Supported auth types:
///   1. <see cref="ApiAuthType.ApiKey"/>                  — sends a static token in a
///      configurable header (X-API-Key, Authorization: Bearer …, etc.).
///   2. <see cref="ApiAuthType.OAuthClientCredentials"/>  — fetches a short-lived access token
///      via the OAuth 2.0 Client Credentials flow then sends it as a Bearer token.
///   3. <see cref="ApiAuthType.OAuthSamlAssertionGrant"/> — exchanges a SAML assertion for an
///      access token via RFC 7522 then sends it as a Bearer token.
///   4. <see cref="ApiAuthType.ServiceAccountToken"/>     — identical wire behaviour to Option 1;
///      provided as a distinct enum value to communicate legacy systems semantics in the UI.
/// </summary>
public class AppApiClientService : IAppApiClient
{
    private readonly IAppApiConfigService _configService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AppApiClientService> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public AppApiClientService(
        IAppApiConfigService configService,
        IHttpClientFactory httpClientFactory,
        ILogger<AppApiClientService> logger)
    {
        _configService = configService;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    // ── IAppApiClient ─────────────────────────────────────────────────────────

    /// <inheritdoc />
    public async Task<IReadOnlyList<RemoteSamlCertInfo>> GetRemoteKeysAsync(
        AppApiConfiguration config, CancellationToken ct = default)
    {
        var http = await BuildAuthorisedClientAsync(config, ct);

        var route = ResolveRoute(
            config.GetKeysRoute ?? "/v1/idp-connections/{connectionId}",
            config.ConnectionId);

        var url = BuildUrl(config.ApiBaseUrl, route);
        _logger.LogInformation("GET remote keys: {Url} (app={AppId})", url, config.RowKey);

        var response = await http.GetAsync(url, ct);
        await EnsureSuccessAsync(response, "GET keys", config.RowKey);

        var body = await response.Content.ReadAsStringAsync(ct);
        return ParseCertificates(body);
    }

    /// <inheritdoc />
    public async Task ActivateRemoteKeyAsync(
        AppApiConfiguration config, string certId, string? reason = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certId);

        var http = await BuildAuthorisedClientAsync(config, ct);

        var routeTemplate = config.ActivateKeyRoute
            ?? "/v1/idp-connections/{connectionId}/rotation/activate";

        // Resolve {connectionId} first, then {certId} (for path-based cert ID placement).
        var route = ResolveRoute(routeTemplate, config.ConnectionId);
        route = ResolveCertId(route, certId);

        var url = BuildUrl(config.ApiBaseUrl, route);

        // Determine HTTP method — default POST, allow PUT or PATCH.
        var method = config.ActivateHttpMethod?.Trim().ToUpperInvariant() switch
        {
            "PUT" => HttpMethod.Put,
            "PATCH" => HttpMethod.Patch,
            _ => HttpMethod.Post
        };

        // Determine whether cert ID goes in the URL path or the request body.
        var certIdLocation = config.ActivateCertIdLocation?.Trim().ToLowerInvariant();
        HttpContent? content = null;

        if (certIdLocation != "path")
        {
            // Body-based: build the JSON payload from a template or a safe default.
            var resolvedReason = reason ?? "Activated via SAML Cert Rotation dashboard";
            string payload;

            if (!string.IsNullOrWhiteSpace(config.ActivateBodyTemplate))
            {
                // Substitute {certId} and {reason} placeholders in the user-supplied template.
                // JSON-encode both values to prevent injection into the JSON structure.
                var encodedCertId = JsonSerializer.Serialize(certId)[1..^1]; // strip outer quotes
                var encodedReason = JsonSerializer.Serialize(resolvedReason)[1..^1];
                payload = config.ActivateBodyTemplate
                    .Replace("{certId}", encodedCertId, StringComparison.OrdinalIgnoreCase)
                    .Replace("{reason}", encodedReason, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                // Default payload — matches the SAML Sample App convention.
                payload = JsonSerializer.Serialize(new
                {
                    targetCertIds = new[] { certId },
                    overlapUntilUtc = DateTimeOffset.UtcNow,
                    reason = resolvedReason
                });
            }

            content = new StringContent(payload, Encoding.UTF8, "application/json");
        }

        _logger.LogInformation(
            "{Method} activate key {CertId} on {Url} (app={AppId}, certIdIn={Location})",
            method.Method, certId, url, config.RowKey, certIdLocation ?? "body");

        var request = new HttpRequestMessage(method, url) { Content = content };
        var response = await http.SendAsync(request, ct);
        await EnsureSuccessAsync(response, $"{method.Method} activate", config.RowKey);
    }

    // ── Auth token acquisition ─────────────────────────────────────────────────

    private async Task<HttpClient> BuildAuthorisedClientAsync(
        AppApiConfiguration config, CancellationToken ct)
    {
        var secret = await _configService.GetSecretAsync(config, ct)
            ?? throw new InvalidOperationException(
                $"No API secret found in Key Vault for app {config.RowKey}. Save the configuration with a secret first.");

        var http = _httpClientFactory.CreateClient("AppApiClient");

        switch (config.AuthType)
        {
            case ApiAuthType.ApiKey:
            case ApiAuthType.ServiceAccountToken:
                ApplyStaticTokenHeader(http, config, secret);
                break;

            case ApiAuthType.OAuthClientCredentials:
                var ccToken = await AcquireClientCredentialsTokenAsync(config, secret, ct);
                http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", ccToken);
                break;

            case ApiAuthType.OAuthSamlAssertionGrant:
                var samlToken = await AcquireSamlAssertionGrantTokenAsync(config, secret, ct);
                http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", samlToken);
                break;

            default:
                throw new NotSupportedException($"Unsupported auth type: {config.AuthType}");
        }

        return http;
    }

    /// <summary>
    /// Options 1 &amp; 4: Adds a single static header carrying the raw secret.
    /// The header name and optional prefix are taken from the configuration.
    /// </summary>
    private static void ApplyStaticTokenHeader(
        HttpClient http, AppApiConfiguration config, string secret)
    {
        var headerName = config.ApiKeyHeaderName ?? "X-API-Key";
        var prefix = config.ApiKeyHeaderPrefix ?? string.Empty;
        var headerValue = prefix + secret;

        // Use Authorization in a structured way when the header name matches.
        if (string.Equals(headerName, "Authorization", StringComparison.OrdinalIgnoreCase))
        {
            // Split "Bearer " prefix from the scheme token if present.
            var parts = headerValue.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2)
                http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue(parts[0], parts[1]);
            else
                http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue(headerValue);
        }
        else
        {
            http.DefaultRequestHeaders.TryAddWithoutValidation(headerName, headerValue);
        }
    }

    /// <summary>
    /// Option 2: OAuth 2.0 Client Credentials flow (RFC 6749 §4.4).
    /// The <paramref name="clientSecret"/> is the OAuth client_secret stored in Key Vault.
    /// </summary>
    private async Task<string> AcquireClientCredentialsTokenAsync(
        AppApiConfiguration config, string clientSecret, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.OAuthTokenEndpoint))
            throw new InvalidOperationException(
                "OAuthTokenEndpoint is required for OAuthClientCredentials auth type.");
        if (string.IsNullOrWhiteSpace(config.OAuthClientId))
            throw new InvalidOperationException(
                "OAuthClientId is required for OAuthClientCredentials auth type.");

        var tokenHttp = _httpClientFactory.CreateClient("AppApiTokenClient");

        var formValues = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
            new("client_id", config.OAuthClientId),
            new("client_secret", clientSecret)
        };

        if (!string.IsNullOrWhiteSpace(config.OAuthScope))
            formValues.Add(new("scope", config.OAuthScope));

        var tokenResponse = await tokenHttp.PostAsync(
            config.OAuthTokenEndpoint,
            new FormUrlEncodedContent(formValues),
            ct);

        if (!tokenResponse.IsSuccessStatusCode)
        {
            var err = await tokenResponse.Content.ReadAsStringAsync(ct);
            _logger.LogError(
                "OAuth token request failed ({Status}) for app {AppId}: {Error}",
                tokenResponse.StatusCode, config.RowKey, SanitiseTokenError(err));
            throw new HttpRequestException(
                $"OAuth token endpoint returned {(int)tokenResponse.StatusCode}.");
        }

        var tokenBody = await tokenResponse.Content.ReadAsStringAsync(ct);
        return ExtractAccessToken(tokenBody);
    }

    /// <summary>
    /// Option 3: OAuth 2.0 SAML Assertion Grant (RFC 7522).
    /// The <paramref name="samlAssertion"/> (base64-encoded XML) is the secret stored in Key Vault.
    /// </summary>
    private async Task<string> AcquireSamlAssertionGrantTokenAsync(
        AppApiConfiguration config, string samlAssertion, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.OAuthTokenEndpoint))
            throw new InvalidOperationException(
                "OAuthTokenEndpoint is required for OAuthSamlAssertionGrant auth type.");

        var tokenHttp = _httpClientFactory.CreateClient("AppApiTokenClient");

        var formValues = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer"),
            // RFC 7522 §3: the assertion must be URL-safe base64 encoded.
            new("assertion", Base64UrlEncode(samlAssertion))
        };

        if (!string.IsNullOrWhiteSpace(config.OAuthClientId))
            formValues.Add(new("client_id", config.OAuthClientId));
        if (!string.IsNullOrWhiteSpace(config.OAuthScope))
            formValues.Add(new("scope", config.OAuthScope));

        var tokenResponse = await tokenHttp.PostAsync(
            config.OAuthTokenEndpoint,
            new FormUrlEncodedContent(formValues),
            ct);

        if (!tokenResponse.IsSuccessStatusCode)
        {
            var err = await tokenResponse.Content.ReadAsStringAsync(ct);
            _logger.LogError(
                "SAML assertion grant token request failed ({Status}) for app {AppId}: {Error}",
                tokenResponse.StatusCode, config.RowKey, SanitiseTokenError(err));
            throw new HttpRequestException(
                $"OAuth SAML assertion grant endpoint returned {(int)tokenResponse.StatusCode}.");
        }

        var tokenBody = await tokenResponse.Content.ReadAsStringAsync(ct);
        return ExtractAccessToken(tokenBody);
    }

    // ── Response parsing ───────────────────────────────────────────────────────

    private static IReadOnlyList<RemoteSamlCertInfo> ParseCertificates(string json)
    {
        var root = JsonNode.Parse(json);
        if (root is null) return Array.Empty<RemoteSamlCertInfo>();

        // Support both:
        //   - SAML Sample App format: { "certs": [...] }
        //   - Direct array: [...]
        var certsNode = root["certs"] ?? root["certificates"] ?? root;
        if (certsNode is not JsonArray arr) return Array.Empty<RemoteSamlCertInfo>();

        return arr.Select(node =>
        {
            if (node is null) return null;
            return new RemoteSamlCertInfo
            {
                CertId = (node["certId"] ?? node["id"] ?? node["keyId"])?.ToString() ?? string.Empty,
                Thumbprint = node["thumbprint"]?.ToString() ?? string.Empty,
                Subject = node["subject"]?.ToString() ?? string.Empty,
                Issuer = node["issuer"]?.ToString() ?? string.Empty,
                NotBeforeUtc = TryParseOffset(node["notBeforeUtc"]?.ToString()),
                NotAfterUtc = TryParseOffset(node["notAfterUtc"]?.ToString()),
                State = (node["state"] ?? node["status"])?.ToString() ?? "unknown"
            };
        })
        .Where(c => c is not null)
        .ToList()!;
    }

    private static string ExtractAccessToken(string json)
    {
        var root = JsonNode.Parse(json);
        var token = root?["access_token"]?.ToString();
        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Token endpoint response did not contain access_token.");
        return token;
    }

    // ── Utilities ──────────────────────────────────────────────────────────────

    private static string ResolveRoute(string template, string? connectionId)
    {
        if (string.IsNullOrWhiteSpace(connectionId))
            return template;

        // Reject path-traversal attempts in the connectionId before substitution.
        if (connectionId.Contains("..") || connectionId.Contains('/') || connectionId.Contains('\\'))
            throw new ArgumentException("ConnectionId contains disallowed characters.", nameof(connectionId));

        return template.Replace("{connectionId}", Uri.EscapeDataString(connectionId),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveCertId(string template, string certId)
    {
        if (!template.Contains("{certId}", StringComparison.OrdinalIgnoreCase))
            return template;

        // Reject path-traversal attempts in certId before substitution.
        if (certId.Contains("..") || certId.Contains('/') || certId.Contains('\\'))
            throw new ArgumentException("CertId contains disallowed characters.", nameof(certId));

        return template.Replace("{certId}", Uri.EscapeDataString(certId),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildUrl(string baseUrl, string route)
    {
        // Normalise: trim trailing slash from base, ensure leading slash on route.
        var b = baseUrl.TrimEnd('/');
        var r = route.StartsWith('/') ? route : "/" + route;
        return b + r;
    }

    private static async Task EnsureSuccessAsync(
        HttpResponseMessage response, string operation, string appId)
    {
        if (response.IsSuccessStatusCode) return;

        var body = await response.Content.ReadAsStringAsync();
        throw new HttpRequestException(
            $"{operation} call for app {appId} failed with HTTP {(int)response.StatusCode}: {body}");
    }

    private static DateTimeOffset TryParseOffset(string? value)
    {
        if (DateTimeOffset.TryParse(value, out var dt)) return dt;
        return DateTimeOffset.MinValue;
    }

    /// <summary>
    /// Converts a base64-encoded or plain string to URL-safe base64 (no padding).
    /// If the input is already base64, it is re-encoded to URL-safe form.
    /// </summary>
    private static string Base64UrlEncode(string value)
    {
        // Try to parse as standard base64 first; if it fails treat the raw bytes.
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch
        {
            bytes = Encoding.UTF8.GetBytes(value);
        }
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Returns a sanitised snippet of an OAuth error response — strips out any
    /// credentials or stack-trace-like content before logging.
    /// </summary>
    private static string SanitiseTokenError(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "(empty)";
        const int maxLen = 200;
        // Never log more than maxLen characters; avoid leaking lengthy stack traces.
        var snippet = body.Length > maxLen ? body[..maxLen] + "…" : body;
        // Remove anything that looks like a secret value embedded in the error.
        return System.Text.RegularExpressions.Regex.Replace(
            snippet, @"(client_secret|assertion|password)=[^&\s""']+",
            "$1=<redacted>",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }
}
