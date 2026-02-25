using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker.Http;
using HttpRequestData = Microsoft.Azure.Functions.Worker.Http.HttpRequestData;
using HttpResponseData = Microsoft.Azure.Functions.Worker.Http.HttpResponseData;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Helpers;
using SamlCertRotation.Models;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// Base class for dashboard HTTP-triggered functions.
/// Contains shared dependency injection fields, the authentication/authorization
/// pipeline, JSON/error helpers, and common validation utilities.
/// </summary>
public abstract class DashboardFunctionBase
{
    protected readonly ICertificateRotationService _rotationService;
    protected readonly IGraphService _graphService;
    protected readonly IPolicyService _policyService;
    protected readonly IAuditService _auditService;
    protected readonly INotificationService _notificationService;
    protected readonly IReportService _reportService;
    protected readonly IConfiguration _configuration;
    protected readonly ILogger _logger;
    protected readonly string? _tenantId;
    private readonly HashSet<string> _allowedAudiences;
    private readonly HashSet<string> _trustedSwaIssuers;
    private readonly IConfigurationManager<OpenIdConnectConfiguration>? _oidcConfigurationManager;

    protected static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    protected static readonly JsonSerializerOptions JsonDeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Pre-lowered sensitive patterns used by <see cref="SanitizeErrorMessage"/>.
    /// Allocated once to avoid per-call array creation and repeated ToLowerInvariant calls.
    /// </summary>
    private static readonly string[] SensitivePatterns = new[]
    {
        "stack trace", "at system.", "at microsoft.", "at azure.",
        "connection string", "password", "secret", "token",
        "client_id", "client_secret", "tenant",
        "storageconnectionstring", "azurewebjobs",
        "odataerror", "request_", "authorization_",
        "serviceexception", "inner exception",
        "graph.microsoft.com", "serviceprincipalid",
        ".azurewebsites.net", "table storage", "partitionkey"
    };

    protected DashboardFunctionBase(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger logger)
    {
        _rotationService = rotationService;
        _graphService = graphService;
        _policyService = policyService;
        _auditService = auditService;
        _notificationService = notificationService;
        _reportService = reportService;
        _configuration = configuration;
        _logger = logger;

        _tenantId = _configuration["TenantId"];
        _allowedAudiences = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddAudienceIfPresent(_allowedAudiences, _configuration["SWA_AAD_CLIENT_ID"]);
        AddAudienceIfPresent(_allowedAudiences, _configuration["AAD_CLIENT_ID"]);

        var configuredAudiences = _configuration["SWA_ALLOWED_AUDIENCES"];
        if (!string.IsNullOrWhiteSpace(configuredAudiences))
        {
            foreach (var audience in configuredAudiences.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                AddAudienceIfPresent(_allowedAudiences, audience);
            }
        }

        // Build set of trusted SWA issuers for SWA-issued token path
        _trustedSwaIssuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var swaHostname = _configuration["SWA_HOSTNAME"];
        if (!string.IsNullOrWhiteSpace(swaHostname))
        {
            _trustedSwaIssuers.Add($"https://{swaHostname.TrimEnd('/')}/.auth");
        }
        // Also auto-trust the default SWA domain pattern
        var swaDefaultHostname = _configuration["SWA_DEFAULT_HOSTNAME"];
        if (!string.IsNullOrWhiteSpace(swaDefaultHostname))
        {
            _trustedSwaIssuers.Add($"https://{swaDefaultHostname.TrimEnd('/')}/.auth");
        }

        if (!string.IsNullOrWhiteSpace(_tenantId))
        {
            var metadataAddress = $"https://login.microsoftonline.com/{_tenantId}/v2.0/.well-known/openid-configuration";
            _oidcConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
        }
    }

    #region Authentication / Authorization

    /// <summary>
    /// Validates caller identity and role requirements for dashboard endpoints.
    /// Returns a tuple: if authorization fails, ErrorResponse is set; otherwise Identity is set.
    /// This avoids re-parsing the identity in handler methods that need both auth check and user info.
    /// </summary>
    protected async Task<(HttpResponseData? ErrorResponse, RequestIdentity? Identity)> AuthorizeRequestAsync(
        HttpRequestData req, bool requireAdmin = false, bool allowSponsor = false)
    {
        var identity = await ParseClientPrincipalAsync(req);
        if (identity == null || !identity.IsAuthenticated)
        {
            _logger.LogWarning("Unauthorized request to {Method} {Url}", req.Method, req.Url);
            var error = await CreateErrorResponse(req, "Authentication is required.", HttpStatusCode.Unauthorized);
            return (error, null);
        }

        var hasReadAccess = identity.Roles.Contains(DashboardRoles.Admin)
                    || identity.Roles.Contains(DashboardRoles.Reader);
        var isSponsor = identity.Roles.Contains(DashboardRoles.Sponsor);

        if (!hasReadAccess && !(allowSponsor && isSponsor))
        {
            _logger.LogWarning("Forbidden request by user {UserId} to {Method} {Url} - missing required role", identity.UserId ?? "unknown", req.Method, req.Url);
            var error = await CreateErrorResponse(req, "Insufficient permissions.", HttpStatusCode.Forbidden);
            return (error, identity);
        }

        if (requireAdmin && !identity.Roles.Contains(DashboardRoles.Admin))
        {
            _logger.LogWarning("Forbidden request by user {UserId} to {Method} {Url}", identity.UserId ?? "unknown", req.Method, req.Url);
            var error = await CreateErrorResponse(req, "Admin role is required.", HttpStatusCode.Forbidden);
            return (error, identity);
        }

        return (null, identity);
    }

    /// <summary>
    /// Parses the caller identity from request headers/tokens.
    /// Order matters for security: validated AAD token first (signature-verified),
    /// then SWA client principal header, then unsigned SWA JWT (last resort).
    /// </summary>
    private async Task<RequestIdentity?> ParseClientPrincipalAsync(HttpRequestData req)
    {
        // 1. Try validated AAD token first — most secure (signature + issuer verified)
        var tokenIdentity = await ParseClientPrincipalFromValidatedAuthTokenAsync(req);
        if (tokenIdentity != null)
        {
            return tokenIdentity;
        }

        // 2. Try x-ms-client-principal base64 header — set by SWA reverse proxy.
        //    SECURITY NOTE: This header is only trustworthy when requests pass through SWA's
        //    reverse proxy (which strips/overwrites it). We only trust it when at least one
        //    SWA hostname is configured, confirming the deployer has linked this function app to SWA.
        if (_trustedSwaIssuers.Count > 0)
        {
            var encodedPrincipal = AuthHelper.GetHeaderValue(req, "x-ms-client-principal");
            if (!string.IsNullOrWhiteSpace(encodedPrincipal))
            {
                try
                {
                    var json = AuthHelper.DecodePrincipalPayload(encodedPrincipal);
                    if (!string.IsNullOrWhiteSpace(json))
                    {
                        using var document = JsonDocument.Parse(json);
                        var root = document.RootElement;
                        if (root.TryGetProperty("clientPrincipal", out var wrappedPrincipal) && wrappedPrincipal.ValueKind == JsonValueKind.Object)
                        {
                            root = wrappedPrincipal;
                        }

                        var identity = BuildIdentityFromPrincipalRoot(root);
                        if (identity != null)
                        {
                            return identity;
                        }
                    }
                }
                catch
                {
                }
            }
        }
        else
        {
            _logger.LogDebug("Skipping x-ms-client-principal path: no SWA hostname configured (SWA_HOSTNAME / SWA_DEFAULT_HOSTNAME).");
        }

        // 3. Try SWA-issued JWT — unsigned, but only trusted for explicitly configured SWA hostnames.
        // Required for SWA linked backends where x-ms-client-principal is not forwarded.
        var swaTokenIdentity = ParseIdentityFromSwaIssuedToken(req);
        if (swaTokenIdentity != null)
        {
            return swaTokenIdentity;
        }

        return null;
    }

    /// <summary>
    /// Decodes a SWA-issued JWT (issuer = SWA hostname/.auth) without signature validation.
    /// Same trust model as x-ms-client-principal: both are set by SWA's reverse proxy.
    /// Only trusts tokens whose issuer matches a configured/known SWA hostname.
    /// </summary>
    private RequestIdentity? ParseIdentityFromSwaIssuedToken(HttpRequestData req)
    {
        var candidates = GetCandidateAuthTokens(req).ToList();
        if (candidates.Count == 0)
        {
            return null;
        }

        var handler = new JwtSecurityTokenHandler();

        foreach (var (source, token) in candidates)
        {
            JwtSecurityToken? jwt;
            try
            {
                jwt = handler.ReadJwtToken(token);
            }
            catch
            {
                continue;
            }

            var issuer = jwt.Issuer;

            // Check if this is a SWA-issued token by matching issuer against explicitly configured hostnames.
            // No auto-detect: SWA_HOSTNAME must be configured to prevent forged tokens from unknown issuers.
            if (_trustedSwaIssuers.Count == 0)
            {
                _logger.LogWarning("SWA_HOSTNAME is not configured. Cannot authenticate SWA-issued tokens. Set SWA_HOSTNAME in Function App settings.");
                return null;
            }

            var isTrustedSwa = _trustedSwaIssuers.Contains(issuer);

            if (!isTrustedSwa)
            {
                continue;
            }

            // Extract claims from SWA token payload
            var userId = jwt.Claims.FirstOrDefault(c => c.Type == "oid")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value
                         ?? jwt.Claims.FirstOrDefault(c => c.Type == "stable_sid")?.Value;

            var userPrincipalName = jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                                   ?? jwt.Claims.FirstOrDefault(c => c.Type == "upn")?.Value
                                   ?? jwt.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")?.Value
                                   ?? jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;

            var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var claimRoleValues = new List<string>();
            var claimGroupValues = new List<string>();

            // SWA embeds the full client principal (including userRoles) in the "prn" claim as base64 JSON
            var prnClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, "prn", StringComparison.OrdinalIgnoreCase))?.Value;
            if (!string.IsNullOrWhiteSpace(prnClaim))
            {
                try
                {
                    var prnJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(prnClaim));
                    using var prnDoc = JsonDocument.Parse(prnJson);
                    var prnRoot = prnDoc.RootElement;

                    if (string.IsNullOrWhiteSpace(userId))
                    {
                        userId = TryGetString(prnRoot, "userId");
                    }

                    if (string.IsNullOrWhiteSpace(userPrincipalName))
                    {
                        userPrincipalName = TryGetString(prnRoot, "userDetails");
                    }

                    if (prnRoot.TryGetProperty("userRoles", out var prnRoles) && prnRoles.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var roleEl in prnRoles.EnumerateArray())
                        {
                            var role = roleEl.GetString();
                            if (!string.IsNullOrWhiteSpace(role))
                            {
                                roles.Add(role);
                            }
                        }
                    }

                    _logger.LogInformation("Extracted {RoleCount} roles from SWA prn claim: {Roles}", roles.Count, string.Join(", ", roles));

                    if (prnRoot.TryGetProperty("claims", out var prnClaimsArray) && prnClaimsArray.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var claimElement in prnClaimsArray.EnumerateArray())
                        {
                            if (claimElement.ValueKind != JsonValueKind.Object) continue;

                            var ct = TryGetString(claimElement, "typ") ?? TryGetString(claimElement, "type");
                            var cv = TryGetString(claimElement, "val") ?? TryGetString(claimElement, "value");
                            if (string.IsNullOrWhiteSpace(ct) || string.IsNullOrWhiteSpace(cv)) continue;

                            if (string.Equals(ct, "roles", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(ct, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                            {
                                claimRoleValues.Add(cv);
                            }

                            if (string.Equals(ct, "groups", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(ct, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                            {
                                claimGroupValues.Add(cv);
                            }
                        }

                        _logger.LogInformation("Extracted {RoleClaimCount} role claims and {GroupClaimCount} group claims from SWA prn payload",
                            claimRoleValues.Count, claimGroupValues.Count);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to decode prn claim from SWA token");
                }
            }

            // Also check standard JWT role/group claims as fallback
            foreach (var rv in jwt.Claims
                .Where(c => string.Equals(c.Type, "roles", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v)))
            {
                claimRoleValues.Add(rv);
            }

            foreach (var gv in jwt.Claims
                .Where(c => string.Equals(c.Type, "groups", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v)))
            {
                claimGroupValues.Add(gv);
            }

            ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

            if (roles.Count == 0 && !string.IsNullOrWhiteSpace(userId))
            {
                roles.Add("authenticated");
            }

            if (!IsAuthenticatedPrincipal(userId, roles))
            {
                continue;
            }

            _logger.LogInformation("Authenticated request identity from SWA-issued token via {TokenSource}", source);

            return new RequestIdentity
            {
                UserId = userId,
                UserPrincipalName = userPrincipalName,
                IsAuthenticated = true,
                Roles = roles
            };
        }

        return null;
    }

    /// <summary>
    /// Validates forwarded identity token against Entra signing keys/issuer, then extracts identity and role claims.
    /// </summary>
    private async Task<RequestIdentity?> ParseClientPrincipalFromValidatedAuthTokenAsync(HttpRequestData req)
    {
        var candidateTokens = GetCandidateAuthTokens(req).ToList();
        if (candidateTokens.Count == 0)
        {
            return null;
        }

        if (_oidcConfigurationManager == null || string.IsNullOrWhiteSpace(_tenantId))
        {
            _logger.LogWarning("Cannot validate x-ms-auth-token because TenantId is not configured on Function App settings.");
            return null;
        }

        var oidcConfig = await _oidcConfigurationManager.GetConfigurationAsync(CancellationToken.None);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = oidcConfig.SigningKeys,
            ValidateIssuer = true,
            ValidIssuers = new[]
            {
                $"https://login.microsoftonline.com/{_tenantId}/v2.0",
                $"https://sts.windows.net/{_tenantId}/"
            },
            ValidateAudience = _allowedAudiences.Count > 0,
            ValidAudiences = _allowedAudiences,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        var handler = new JwtSecurityTokenHandler();

        foreach (var (source, token) in candidateTokens)
        {
            try
            {
                var principal = handler.ValidateToken(token, validationParameters, out _);

                var userId = principal.FindFirst("oid")?.Value
                             ?? principal.FindFirst("sub")?.Value
                             ?? principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
                             ?? principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

                var userPrincipalName = principal.FindFirst("preferred_username")?.Value
                                       ?? principal.FindFirst("upn")?.Value
                                       ?? principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")?.Value
                                       ?? principal.FindFirst("email")?.Value;

                var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var claimRoleValues = principal.Claims
                    .Where(c =>
                        string.Equals(c.Type, "roles", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                    .Select(c => c.Value)
                    .Where(v => !string.IsNullOrWhiteSpace(v));

                var claimGroupValues = principal.Claims
                    .Where(c =>
                        string.Equals(c.Type, "groups", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(c.Type, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                    .Select(c => c.Value)
                    .Where(v => !string.IsNullOrWhiteSpace(v));

                ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

                if (roles.Count == 0 && !string.IsNullOrWhiteSpace(userId))
                {
                    roles.Add("authenticated");
                }

                if (!IsAuthenticatedPrincipal(userId, roles))
                {
                    continue;
                }

                _logger.LogInformation("Authenticated request identity from token source {TokenSource}", source);

                return new RequestIdentity
                {
                    UserId = userId,
                    UserPrincipalName = userPrincipalName,
                    IsAuthenticated = true,
                    Roles = roles
                };
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogDebug(ex, "Token from source {TokenSource} failed validation.", source);
            }
        }

        _logger.LogWarning("No forwarded token source produced a valid authenticated principal.");
        return null;
    }

    private IEnumerable<(string Source, string Token)> GetCandidateAuthTokens(HttpRequestData req)
    {
        var candidates = new List<(string Source, string Token)>();

        AddCandidate(candidates, "x-ms-auth-token", AuthHelper.GetHeaderValue(req, "x-ms-auth-token"));
        AddCandidate(candidates, "x-ms-token-aad-id-token", AuthHelper.GetHeaderValue(req, "x-ms-token-aad-id-token"));
        AddCandidate(candidates, "x-ms-token-aad-access-token", AuthHelper.GetHeaderValue(req, "x-ms-token-aad-access-token"));
        AddCandidate(candidates, "authorization", AuthHelper.GetHeaderValue(req, "authorization"));

        return candidates;
    }

    private static void AddCandidate(List<(string Source, string Token)> candidates, string source, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return;
        }

        var token = rawValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? rawValue.Substring("Bearer ".Length).Trim()
            : rawValue.Trim();

        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        candidates.Add((source, token));
    }

    private static void AddAudienceIfPresent(HashSet<string> audiences, string? audience)
    {
        if (!string.IsNullOrWhiteSpace(audience))
        {
            audiences.Add(audience.Trim());
        }
    }

    /// <summary>
    /// Builds an internal identity model from SWA principal payload fields and claims.
    /// </summary>
    private RequestIdentity? BuildIdentityFromPrincipalRoot(JsonElement root)
    {
        var userId = TryGetString(root, "userId");
        var userPrincipalName = TryGetString(root, "userDetails");
        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var claimRoleValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var claimGroupValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (root.TryGetProperty("userRoles", out var userRolesElement) && userRolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var roleElement in userRolesElement.EnumerateArray())
            {
                var role = roleElement.GetString();
                if (!string.IsNullOrWhiteSpace(role))
                {
                    roles.Add(role);
                }
            }
        }

        if (root.TryGetProperty("claims", out var claimsElement) && claimsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var claimElement in claimsElement.EnumerateArray())
            {
                if (claimElement.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var claimType = TryGetString(claimElement, "typ") ?? TryGetString(claimElement, "type");
                var claimValue = TryGetString(claimElement, "val") ?? TryGetString(claimElement, "value");

                if (string.IsNullOrWhiteSpace(claimType) || string.IsNullOrWhiteSpace(claimValue))
                {
                    continue;
                }

                if (string.Equals(claimType, "roles", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claimType, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", StringComparison.OrdinalIgnoreCase))
                {
                    claimRoleValues.Add(claimValue);
                }

                if (string.Equals(claimType, "groups", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claimType, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", StringComparison.OrdinalIgnoreCase))
                {
                    claimGroupValues.Add(claimValue);
                }

                if (string.IsNullOrWhiteSpace(userId) &&
                    (string.Equals(claimType, "oid", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "sub", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "nameid", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "http://schemas.microsoft.com/identity/claims/objectidentifier", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", StringComparison.OrdinalIgnoreCase)))
                {
                    userId = claimValue;
                }

                if (string.IsNullOrWhiteSpace(userPrincipalName) &&
                    (string.Equals(claimType, "preferred_username", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "upn", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(claimType, "email", StringComparison.OrdinalIgnoreCase)))
                {
                    userPrincipalName = claimValue;
                }
            }
        }

        ApplyConfiguredRoleMappings(roles, claimRoleValues, claimGroupValues);

        if (roles.Count == 0 && !string.IsNullOrWhiteSpace(userId))
        {
            roles.Add("authenticated");
        }

        if (roles.Count == 0)
        {
            return null;
        }

        return new RequestIdentity
        {
            UserId = userId,
            UserPrincipalName = userPrincipalName,
            IsAuthenticated = IsAuthenticatedPrincipal(userId, roles),
            Roles = roles
        };
    }

    private static bool IsAuthenticatedPrincipal(string? userId, HashSet<string> roles)
    {
        if (string.IsNullOrWhiteSpace(userId)
            && !roles.Contains("authenticated")
            && !roles.Contains(DashboardRoles.Admin)
            && !roles.Contains(DashboardRoles.Reader)
            && !roles.Contains(DashboardRoles.Sponsor))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Maps app-role or group claims to local admin/reader dashboard roles.
    /// </summary>
    private void ApplyConfiguredRoleMappings(HashSet<string> roles, IEnumerable<string> claimRoleValues, IEnumerable<string> claimGroupValues)
    {
        var configuredAdminAppRole = _configuration["SWA_ADMIN_APP_ROLE"];
        var configuredReaderAppRole = _configuration["SWA_READER_APP_ROLE"];
        var configuredAdminGroup = _configuration["SWA_ADMIN_GROUP_ID"];
        var configuredReaderGroup = _configuration["SWA_READER_GROUP_ID"];

        if (string.IsNullOrWhiteSpace(configuredAdminAppRole))
        {
            configuredAdminAppRole = "SamlCertRotation.Admin";
        }

        if (string.IsNullOrWhiteSpace(configuredReaderAppRole))
        {
            configuredReaderAppRole = "SamlCertRotation.Reader";
        }

        var roleSet = claimRoleValues is HashSet<string> roleHash
            ? roleHash
            : new HashSet<string>(claimRoleValues.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);

        var groupSet = claimGroupValues is HashSet<string> groupHash
            ? groupHash
            : new HashSet<string>(claimGroupValues.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);

        var isAdminByClaimRole = !string.IsNullOrWhiteSpace(configuredAdminAppRole) && roleSet.Contains(configuredAdminAppRole);
        var isReaderByClaimRole = !string.IsNullOrWhiteSpace(configuredReaderAppRole) && roleSet.Contains(configuredReaderAppRole);
        var isAdminByClaimGroup = !string.IsNullOrWhiteSpace(configuredAdminGroup) && groupSet.Contains(configuredAdminGroup);
        var isReaderByClaimGroup = !string.IsNullOrWhiteSpace(configuredReaderGroup) && groupSet.Contains(configuredReaderGroup);

        if (isAdminByClaimRole || isAdminByClaimGroup || roles.Contains(DashboardRoles.Admin))
        {
            roles.Add(DashboardRoles.Admin);
            roles.Add(DashboardRoles.Reader);
        }
        else if (isReaderByClaimRole || isReaderByClaimGroup || roles.Contains(DashboardRoles.Reader))
        {
            roles.Add(DashboardRoles.Reader);
        }

        // Sponsor role mapping
        var configuredSponsorAppRole = _configuration["SWA_SPONSOR_APP_ROLE"];
        var configuredSponsorGroup = _configuration["SWA_SPONSOR_GROUP_ID"];

        if (string.IsNullOrWhiteSpace(configuredSponsorAppRole))
        {
            configuredSponsorAppRole = "SamlCertRotation.Sponsor";
        }

        var isSponsorByClaimRole = !string.IsNullOrWhiteSpace(configuredSponsorAppRole) && roleSet.Contains(configuredSponsorAppRole);
        var isSponsorByClaimGroup = !string.IsNullOrWhiteSpace(configuredSponsorGroup) && groupSet.Contains(configuredSponsorGroup);

        if (isSponsorByClaimRole || isSponsorByClaimGroup || roles.Contains(DashboardRoles.Sponsor))
        {
            roles.Add(DashboardRoles.Sponsor);
        }
    }

    #endregion

    #region Helpers

    protected static string? TryGetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    protected static bool IsValidGuid(string value)
    {
        return !string.IsNullOrEmpty(value) && Guid.TryParse(value, out _);
    }

    protected static string GetCertificateStatus(int daysUntilExpiry, int warningThresholdDays, int criticalThresholdDays)
    {
        if (daysUntilExpiry < 0) return "Expired";
        if (daysUntilExpiry <= criticalThresholdDays) return "Critical";
        if (daysUntilExpiry <= warningThresholdDays) return "Warning";
        return "OK";
    }

    protected static string? ValidateAppPolicyValues(AppPolicy policy)
    {
        if (policy.CreateCertDaysBeforeExpiry.HasValue)
        {
            if (policy.CreateCertDaysBeforeExpiry.Value < 1 || policy.CreateCertDaysBeforeExpiry.Value > 365)
                return "CreateCertDaysBeforeExpiry must be between 1 and 365.";
        }

        if (policy.ActivateCertDaysBeforeExpiry.HasValue)
        {
            if (policy.ActivateCertDaysBeforeExpiry.Value < 1 || policy.ActivateCertDaysBeforeExpiry.Value > 365)
                return "ActivateCertDaysBeforeExpiry must be between 1 and 365.";
        }

        if (policy.CreateCertDaysBeforeExpiry.HasValue && policy.ActivateCertDaysBeforeExpiry.HasValue)
        {
            if (policy.ActivateCertDaysBeforeExpiry.Value >= policy.CreateCertDaysBeforeExpiry.Value)
                return "ActivateCertDaysBeforeExpiry must be less than CreateCertDaysBeforeExpiry.";
        }

        return null;
    }

    /// <summary>
    /// Validates email format for sponsor updates.
    /// Rejects display-name forms like "Name &lt;addr@example.com&gt;" that MailAddress would accept.
    /// </summary>
    protected static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new MailAddress(email);
            return string.Equals(addr.Address, email.Trim(), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    protected static bool IsSponsorOf(string? sponsorField, string? userEmail)
    {
        if (string.IsNullOrWhiteSpace(sponsorField) || string.IsNullOrWhiteSpace(userEmail))
        {
            return false;
        }

        var sponsors = sponsorField.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return sponsors.Any(s => string.Equals(s, userEmail, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Returns the caller's UPN (or user ID) from a previously-parsed identity for audit trail attribution.
    /// </summary>
    protected static string? GetPerformedBy(RequestIdentity? identity) => identity?.UserPrincipalName ?? identity?.UserId;

    protected async Task<HttpResponseData> CreateJsonResponse<T>(HttpRequestData req, T data, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(data, JsonOptions));
        return response;
    }

    /// <summary>
    /// Returns a sanitized error payload to avoid exposing sensitive implementation details.
    /// </summary>
    protected async Task<HttpResponseData> CreateErrorResponse(HttpRequestData req, string message, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
    {
        var sanitizedMessage = SanitizeErrorMessage(message);
        var response = req.CreateResponse(statusCode);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(new { error = sanitizedMessage }, JsonOptions));
        return response;
    }

    private static string SanitizeErrorMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return "An error occurred";

        var lowerMessage = message.ToLowerInvariant();

        foreach (var pattern in SensitivePatterns)
        {
            if (lowerMessage.Contains(pattern))
            {
                return "An internal error occurred. Please check logs for details.";
            }
        }

        if (message.Length > 300)
        {
            return message[..300] + "...";
        }

        return message;
    }

    #endregion

    #region Inner Types

    protected sealed class RequestIdentity
    {
        public string? UserId { get; set; }
        public string? UserPrincipalName { get; set; }
        public bool IsAuthenticated { get; set; }
        public HashSet<string> Roles { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    protected sealed class SponsorUpdateRequest
    {
        public string? SponsorEmail { get; set; }
    }

    protected sealed class BulkSponsorUpdate
    {
        public string? ApplicationId { get; set; }
        public string? SponsorEmail { get; set; }
    }

    protected sealed class TestEmailRequest
    {
        public string? Template { get; set; }
        public string? ToEmail { get; set; }
    }

    #endregion
}
