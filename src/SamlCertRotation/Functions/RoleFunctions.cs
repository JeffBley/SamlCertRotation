using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Helpers;
using SamlCertRotation.Models;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SamlCertRotation.Functions;

/// <summary>
/// Function to assign roles based on Azure AD group membership.
/// Called by Static Web Apps to determine user roles.
/// </summary>
public class RoleFunctions
{
    private readonly ILogger<RoleFunctions> _logger;
    private readonly IConfiguration _configuration;

    private static readonly JsonSerializerOptions JsonDeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public RoleFunctions(ILogger<RoleFunctions> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    /// <summary>
    /// Called by SWA to get roles for a user based on their group membership.
    /// </summary>
    [Function("GetRoles")]
    public async Task<HttpResponseData> GetRoles(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "GetRoles")] HttpRequestData req)
    {
        try
        {
            var clientPrincipal = await ResolveClientPrincipalAsync(req);

            if (clientPrincipal == null)
            {
                _logger.LogWarning("No client principal could be resolved for GetRoles request");
                return await CreateJsonResponse(req, new { roles = Array.Empty<string>() });
            }

            _logger.LogInformation("Getting roles for user: {UserId}", clientPrincipal.UserId);

            // Get role mappings from configuration
            var adminGroupId = _configuration["SWA_ADMIN_GROUP_ID"];
            var readerGroupId = _configuration["SWA_READER_GROUP_ID"];
            var sponsorGroupId = _configuration["SWA_SPONSOR_GROUP_ID"];
            var adminAppRole = _configuration["SWA_ADMIN_APP_ROLE"];
            var readerAppRole = _configuration["SWA_READER_APP_ROLE"];
            var sponsorAppRole = _configuration["SWA_SPONSOR_APP_ROLE"];

            if (string.IsNullOrWhiteSpace(adminAppRole))
            {
                adminAppRole = "SamlCertRotation.Admin";
            }

            if (string.IsNullOrWhiteSpace(readerAppRole))
            {
                readerAppRole = "SamlCertRotation.Reader";
            }

            if (string.IsNullOrWhiteSpace(sponsorAppRole))
            {
                sponsorAppRole = "SamlCertRotation.Sponsor";
            }

            var roles = new List<string>();

            // Check role mappings from group and app role claims
            if (clientPrincipal.Claims != null)
            {
                var groupClaims = clientPrincipal.Claims
                    .Where(c => c.ClaimType == "groups" || c.ClaimType == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
                    .Select(c => c.ClaimValue)
                    .Where(v => !string.IsNullOrWhiteSpace(v))
                    .ToList();

                var appRoleClaims = clientPrincipal.Claims
                    .Where(c => c.ClaimType == "roles" || c.ClaimType == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                    .Select(c => c.ClaimValue)
                    .Where(v => !string.IsNullOrWhiteSpace(v))
                    .ToList();

                var isAdminByGroup = !string.IsNullOrWhiteSpace(adminGroupId) &&
                                     groupClaims.Contains(adminGroupId, StringComparer.OrdinalIgnoreCase);
                var isAdminByAppRole = appRoleClaims.Contains(adminAppRole, StringComparer.OrdinalIgnoreCase);
                var isReaderByGroup = !string.IsNullOrWhiteSpace(readerGroupId) &&
                                      groupClaims.Contains(readerGroupId, StringComparer.OrdinalIgnoreCase);
                var isReaderByAppRole = appRoleClaims.Contains(readerAppRole, StringComparer.OrdinalIgnoreCase);
                var isSponsorByGroup = !string.IsNullOrWhiteSpace(sponsorGroupId) &&
                                       groupClaims.Contains(sponsorGroupId, StringComparer.OrdinalIgnoreCase);
                var isSponsorByAppRole = appRoleClaims.Contains(sponsorAppRole, StringComparer.OrdinalIgnoreCase);

                var isAdmin = isAdminByGroup || isAdminByAppRole;
                var isReader = isReaderByGroup || isReaderByAppRole;
                var isSponsor = isSponsorByGroup || isSponsorByAppRole;

                if (isAdmin)
                {
                    roles.Add(DashboardRoles.Admin);
                    _logger.LogInformation("User {UserId} assigned admin role", clientPrincipal.UserId);
                }

                if (isReader || isAdmin)
                {
                    roles.Add(DashboardRoles.Reader);
                }

                if (isSponsor)
                {
                    roles.Add(DashboardRoles.Sponsor);
                    _logger.LogInformation("User {UserId} assigned sponsor role", clientPrincipal.UserId);
                }

                if (!isAdmin && !isReader && !isSponsor)
                {
                    _logger.LogInformation("User {UserId} not mapped to admin/reader/sponsor role. Groups: {Groups}. App roles: {AppRoles}",
                        clientPrincipal.UserId,
                        string.Join(", ", groupClaims),
                        string.Join(", ", appRoleClaims));
                }
            }

            return await CreateJsonResponse(req, new { roles = roles.ToArray() });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting roles");
            return await CreateJsonResponse(req, new { roles = Array.Empty<string>() });
        }
    }

    /// <summary>
    /// Resolves the client principal from request body (SWA roles source payload) or SWA header.
    /// </summary>
    private async Task<ClientPrincipal?> ResolveClientPrincipalAsync(HttpRequestData req)
    {
        var bodyPrincipal = await ParsePrincipalFromBodyAsync(req);
        if (bodyPrincipal != null)
        {
            return bodyPrincipal;
        }

        var headerPrincipal = ParsePrincipalFromClientPrincipalHeader(req);
        if (headerPrincipal != null)
        {
            return headerPrincipal;
        }

        return null;
    }

    /// <summary>
    /// Parses client principal from JSON request body posted by SWA roles source.
    /// </summary>
    private static async Task<ClientPrincipal?> ParsePrincipalFromBodyAsync(HttpRequestData req)
    {
        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(requestBody))
        {
            return null;
        }

        using var payloadDocument = JsonDocument.Parse(requestBody);
        var root = payloadDocument.RootElement;
        var principalElement = root;

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("clientPrincipal", out var wrappedPrincipal) &&
            wrappedPrincipal.ValueKind == JsonValueKind.Object)
        {
            principalElement = wrappedPrincipal;
        }

        return DeserializePrincipal(principalElement.GetRawText());
    }

    /// <summary>
    /// Parses client principal from the x-ms-client-principal header.
    /// </summary>
    private static ClientPrincipal? ParsePrincipalFromClientPrincipalHeader(HttpRequestData req)
    {
        var encodedPrincipal = AuthHelper.GetHeaderValue(req, "x-ms-client-principal");
        if (string.IsNullOrWhiteSpace(encodedPrincipal))
        {
            return null;
        }

        var principalJson = AuthHelper.DecodePrincipalPayload(encodedPrincipal);
        if (string.IsNullOrWhiteSpace(principalJson))
        {
            return null;
        }

        using var document = JsonDocument.Parse(principalJson);
        var root = document.RootElement;
        if (root.TryGetProperty("clientPrincipal", out var wrappedPrincipal) && wrappedPrincipal.ValueKind == JsonValueKind.Object)
        {
            root = wrappedPrincipal;
        }

        return DeserializePrincipal(root.GetRawText());
    }

    /// <summary>
    /// Deserializes SWA principal payload using case-insensitive JSON matching.
    /// </summary>
    private static ClientPrincipal? DeserializePrincipal(string json)
    {
        return JsonSerializer.Deserialize<ClientPrincipal>(json, JsonDeserializeOptions);
    }

    /// <summary>
    /// Writes a JSON response with UTF-8 content type.
    /// </summary>
    private static async Task<HttpResponseData> CreateJsonResponse<T>(HttpRequestData req, T data)
    {
        var response = req.CreateResponse(HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await response.WriteStringAsync(JsonSerializer.Serialize(data));
        return response;
    }
}

public class ClientPrincipal
{
    /// <summary>Identity provider from SWA principal payload.</summary>
    public string? IdentityProvider { get; set; }
    /// <summary>Unique user identifier.</summary>
    public string? UserId { get; set; }
    /// <summary>Display-friendly user details.</summary>
    public string? UserDetails { get; set; }
    /// <summary>Claims emitted by SWA/AAD for authorization mapping.</summary>
    public List<ClientPrincipalClaim>? Claims { get; set; }
}

public class ClientPrincipalClaim
{
    [JsonPropertyName("typ")]
    public string? Typ { get; set; }

    [JsonPropertyName("val")]
    public string? Val { get; set; }

    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("value")]
    public string? Value { get; set; }

    /// <summary>Normalized claim type across short/full field names.</summary>
    public string ClaimType => !string.IsNullOrWhiteSpace(Type) ? Type : Typ ?? string.Empty;
    /// <summary>Normalized claim value across short/full field names.</summary>
    public string ClaimValue => !string.IsNullOrWhiteSpace(Value) ? Value : Val ?? string.Empty;
}
