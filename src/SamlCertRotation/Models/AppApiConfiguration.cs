using Azure;
using Azure.Data.Tables;

namespace SamlCertRotation.Models;

/// <summary>
/// Identifies which authentication scheme the SAML app's control-plane API uses.
/// </summary>
public enum ApiAuthType
{
    /// <summary>
    /// Option 1: A static API key or long-lived bearer token issued by the app's admin portal,
    /// sent as <c>X-API-Key: &lt;key&gt;</c> or <c>Authorization: Bearer &lt;token&gt;</c>.
    /// </summary>
    ApiKey = 1,

    /// <summary>
    /// Option 2: OAuth 2.0 Client Credentials flow — client exchanges client_id + client_secret
    /// for a short-lived access token via the app's /token endpoint.
    /// </summary>
    OAuthClientCredentials = 2,

    /// <summary>
    /// Option 3: OAuth 2.0 with SAML Assertion Grant (RFC 7522) — a SAML assertion is presented
    /// to an OAuth token endpoint in exchange for an access token.
    /// </summary>
    OAuthSamlAssertionGrant = 3,

    /// <summary>
    /// Option 4: A dedicated service account or static API token (Basic Auth or bearer token),
    /// typical in legacy systems.
    /// </summary>
    ServiceAccountToken = 4
}

/// <summary>
/// Stores the API access configuration for a single SAML application so the rotation service
/// can call back into that application's control-plane API to read its known SAML certificates
/// and promote a specific certificate to active.
///
/// Sensitive material (the actual secret / token value) is NEVER stored here — it lives in
/// Key Vault under the secret name <c>app-api-{RowKey}</c>.
/// This entity records only the non-sensitive parameters needed to construct the request.
///
/// Stored in RotationPolicies table:
///   PartitionKey = "AppApiConfig"
///   RowKey       = service principal object ID
/// </summary>
public class AppApiConfiguration : ITableEntity
{
    // ── ITableEntity ──────────────────────────────────────────────────────────
    public string PartitionKey { get; set; } = "AppApiConfig";

    /// <summary>Service principal object ID.</summary>
    public string RowKey { get; set; } = string.Empty;

    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }

    // ── Identification ────────────────────────────────────────────────────────

    /// <summary>Human-friendly display name, kept in sync at save time.</summary>
    public string AppDisplayName { get; set; } = string.Empty;

    // ── Connectivity ──────────────────────────────────────────────────────────

    /// <summary>
    /// Base URL of the SAML application's control-plane API, e.g.
    /// <c>https://myapp.example.com</c>. Must use HTTPS.
    /// </summary>
    public string ApiBaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Authentication type to use when calling the app's API.
    /// Stored as its integer ordinal; enum parsing in the service layer avoids
    /// silent default-value issues if the value is missing.
    /// </summary>
    public int AuthTypeCode { get; set; } = (int)ApiAuthType.ApiKey;

    /// <summary>Convenience accessor — not persisted separately.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public ApiAuthType AuthType
    {
        get => (ApiAuthType)AuthTypeCode;
        set => AuthTypeCode = (int)value;
    }

    // ── Option 1 / Option 4: API Key / Bearer Token / Service-Account Token ──

    /// <summary>
    /// Header name to use, e.g. <c>X-API-Key</c> or <c>Authorization</c>.
    /// </summary>
    public string? ApiKeyHeaderName { get; set; }

    /// <summary>
    /// Header value prefix, e.g. <c>Bearer </c> or <c>ApiKey </c>.
    /// The secret from Key Vault is appended verbatim. Leave null for a bare value.
    /// </summary>
    public string? ApiKeyHeaderPrefix { get; set; }

    // ── Option 2 / Option 3: OAuth Client Credentials / SAML Assertion Grant ─

    /// <summary>OAuth 2.0 token endpoint URL.</summary>
    public string? OAuthTokenEndpoint { get; set; }

    /// <summary>OAuth client_id (not a secret — safe to store here).</summary>
    public string? OAuthClientId { get; set; }

    /// <summary>
    /// Space-separated OAuth scope(s), e.g. <c>api://myapp/.default</c>.
    /// May be null if the token endpoint does not require a scope parameter.
    /// </summary>
    public string? OAuthScope { get; set; }

    // ── API Route Templates ───────────────────────────────────────────────────

    /// <summary>
    /// Route to GET the available SAML certificates, relative to <see cref="ApiBaseUrl"/>.
    /// May include a <c>{connectionId}</c> placeholder, resolved at runtime.
    /// Defaults to the SAML Sample App convention <c>/v1/idp-connections/{connectionId}</c>.
    /// </summary>
    public string? GetKeysRoute { get; set; }

    /// <summary>
    /// Route template to call when activating a certificate, relative to <see cref="ApiBaseUrl"/>.
    /// May include <c>{connectionId}</c> and/or <c>{certId}</c> placeholders.
    /// Defaults to <c>/v1/idp-connections/{connectionId}/rotation/activate</c>.
    /// </summary>
    public string? ActivateKeyRoute { get; set; }

    /// <summary>
    /// HTTP method used for the activation call. One of: POST, PUT, PATCH.
    /// Defaults to POST.
    /// </summary>
    public string? ActivateHttpMethod { get; set; }

    /// <summary>
    /// Where the certificate ID is placed in the activation request.
    /// <list type="bullet">
    ///   <item><term>body</term><description>Cert ID is embedded in the JSON body via <see cref="ActivateBodyTemplate"/> (default).</description></item>
    ///   <item><term>path</term><description>Cert ID is substituted for <c>{certId}</c> in <see cref="ActivateKeyRoute"/>; no request body is sent.</description></item>
    /// </list>
    /// </summary>
    public string? ActivateCertIdLocation { get; set; }

    /// <summary>
    /// A JSON template for the activation request body. Use <c>{certId}</c> and <c>{reason}</c>
    /// as placeholders; they are replaced at runtime. If null, a sensible default body is used.
    /// Example: <c>{"keyId":"{certId}","comment":"{reason}"}</c>
    /// Only relevant when <see cref="ActivateCertIdLocation"/> is <c>body</c> (or null).
    /// </summary>
    public string? ActivateBodyTemplate { get; set; }

    /// <summary>
    /// The connection / tenant ID expected by the SAML app's control-plane API
    /// (used to fill <c>{connectionId}</c> in route templates).
    /// For the SAML Sample App this is the GUID stored as <c>ControlPlaneConnectionId</c>.
    /// </summary>
    public string? ConnectionId { get; set; }

    // ── Credential expiry tracking ────────────────────────────────────────────

    /// <summary>
    /// Optional expiry date for the credential stored in Key Vault.
    /// For Static Token: entered manually by the admin (the token itself carries no expiry).
    /// For OAuth Client Credentials: can be set manually; the system also reads
    ///   <c>SecretProperties.ExpiresOn</c> from Key Vault metadata at health-check time
    ///   and updates this field automatically.
    /// Null means no expiry is tracked.
    /// </summary>
    public DateTimeOffset? CredentialExpiresOn { get; set; }

    // ── Key Vault location override ───────────────────────────────────────────

    /// <summary>
    /// Optional override for which Key Vault holds this app's API credential.
    /// If null, falls back to the global <c>KeyVaultUri</c> app setting.
    /// Must be an HTTPS URI, e.g. <c>https://my-vault.vault.azure.net/</c>.
    /// The Function App managed identity must have at least <c>Key Vault Secrets User</c>
    /// on this vault.
    /// </summary>
    public string? CredentialKeyVaultUri { get; set; }

    /// <summary>
    /// Optional override for the secret name within <see cref="CredentialKeyVaultUri"/>
    /// (or the global KV if that field is null).
    /// If null, the default naming convention <c>app-api-{objectId}</c> is used.
    /// </summary>
    public string? CredentialKeyVaultSecretName { get; set; }

    // ── Health check state (written by timer function, read-only in UI) ───────

    /// <summary>UTC timestamp of the most recent health-check call.</summary>
    public DateTimeOffset? LastHealthCheckUtc { get; set; }

    /// <summary>
    /// Result of the most recent health-check call.
    /// One of: <c>OK</c>, <c>Unauthorized</c>, <c>Error</c>, <c>NotConfigured</c>.
    /// </summary>
    public string? LastHealthCheckStatus { get; set; }

    /// <summary>Sanitized error message from the most recent failed health check, if any.</summary>
    public string? LastHealthCheckError { get; set; }

    // ── Meta ──────────────────────────────────────────────────────────────────

    /// <summary>UTC timestamp when this configuration was last saved.</summary>
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>UPN or identity of the admin who last updated the configuration.</summary>
    public string? UpdatedBy { get; set; }

    // ── Key Vault ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the effective Key Vault secret name for this app's credential.
    /// Uses <see cref="CredentialKeyVaultSecretName"/> if set; otherwise derives
    /// the default name <c>app-api-{objectId}</c> from the service principal object ID.
    /// </summary>
    public string GetKeyVaultSecretName()
    {
        if (!string.IsNullOrWhiteSpace(CredentialKeyVaultSecretName))
            return CredentialKeyVaultSecretName;

        // Key Vault secret names may contain alphanumerics and dashes only.
        var safe = System.Text.RegularExpressions.Regex.Replace(
            RowKey.ToLowerInvariant(), "[^a-z0-9-]", "-");
        return $"app-api-{safe}";
    }
}
