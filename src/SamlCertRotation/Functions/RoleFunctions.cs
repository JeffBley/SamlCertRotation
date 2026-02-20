using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
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
            var adminAppRole = _configuration["SWA_ADMIN_APP_ROLE"];
            var readerGroupId = _configuration["SWA_READER_GROUP_ID"];
            var readerAppRole = _configuration["SWA_READER_APP_ROLE"];
            
            if (string.IsNullOrEmpty(adminGroupId) && string.IsNullOrEmpty(adminAppRole) &&
                string.IsNullOrEmpty(readerGroupId) && string.IsNullOrEmpty(readerAppRole))
            {
                _logger.LogWarning("No role mappings configured. Set SWA_ADMIN_* and/or SWA_READER_* settings.");
                return await CreateJsonResponse(req, new { roles = Array.Empty<string>() });
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
                var isAdminByAppRole = !string.IsNullOrWhiteSpace(adminAppRole) &&
                                       appRoleClaims.Contains(adminAppRole, StringComparer.OrdinalIgnoreCase);
                var isReaderByGroup = !string.IsNullOrWhiteSpace(readerGroupId) &&
                                      groupClaims.Contains(readerGroupId, StringComparer.OrdinalIgnoreCase);
                var isReaderByAppRole = !string.IsNullOrWhiteSpace(readerAppRole) &&
                                        appRoleClaims.Contains(readerAppRole, StringComparer.OrdinalIgnoreCase);

                var isAdmin = isAdminByGroup || isAdminByAppRole;
                var isReader = isReaderByGroup || isReaderByAppRole;

                if (isAdmin)
                {
                    roles.Add("admin");
                    _logger.LogInformation("User {UserId} assigned admin role", clientPrincipal.UserId);
                }

                if (isReader || isAdmin)
                {
                    roles.Add("reader");
                }

                if (!isAdmin && !isReader)
                {
                    _logger.LogInformation("User {UserId} not mapped to admin/reader role. Groups: {Groups}. App roles: {AppRoles}",
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

        return ParsePrincipalFromAuthToken(req);
    }

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

    private static ClientPrincipal? ParsePrincipalFromClientPrincipalHeader(HttpRequestData req)
    {
        var encodedPrincipal = GetHeaderValue(req, "x-ms-client-principal");
        if (string.IsNullOrWhiteSpace(encodedPrincipal))
        {
            return null;
        }

        var principalJson = DecodePrincipalPayload(encodedPrincipal);
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

    private static ClientPrincipal? ParsePrincipalFromAuthToken(HttpRequestData req)
    {
        var authTokenHeader = GetHeaderValue(req, "x-ms-auth-token");
        if (string.IsNullOrWhiteSpace(authTokenHeader))
        {
            return null;
        }

        var token = authTokenHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authTokenHeader.Substring("Bearer ".Length).Trim()
            : authTokenHeader.Trim();

        var payloadJson = DecodeJwtPayload(token);
        if (string.IsNullOrWhiteSpace(payloadJson))
        {
            return null;
        }

        using var payloadDocument = JsonDocument.Parse(payloadJson);
        var payloadRoot = payloadDocument.RootElement;

        var claims = new List<ClientPrincipalClaim>();
        AddClaimsFromJwtProperty(payloadRoot, "roles", claims);
        AddClaimsFromJwtProperty(payloadRoot, "role", claims);
        AddClaimsFromJwtProperty(payloadRoot, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", claims);
        AddClaimsFromJwtProperty(payloadRoot, "groups", claims);
        AddClaimsFromJwtProperty(payloadRoot, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", claims);

        if (payloadRoot.TryGetProperty("prn", out var prnElement) && prnElement.ValueKind == JsonValueKind.String)
        {
            var prnValue = prnElement.GetString();
            if (!string.IsNullOrWhiteSpace(prnValue))
            {
                var principalJson = DecodePrincipalPayload(prnValue) ?? Uri.UnescapeDataString(prnValue);
                if (!string.IsNullOrWhiteSpace(principalJson))
                {
                    using var principalDocument = JsonDocument.Parse(principalJson);
                    var principalRoot = principalDocument.RootElement;
                    if (principalRoot.TryGetProperty("clientPrincipal", out var wrappedPrincipal) && wrappedPrincipal.ValueKind == JsonValueKind.Object)
                    {
                        principalRoot = wrappedPrincipal;
                    }

                    var principalFromPrn = DeserializePrincipal(principalRoot.GetRawText());
                    if (principalFromPrn != null)
                    {
                        var existingClaims = principalFromPrn.Claims ?? new List<ClientPrincipalClaim>();
                        existingClaims.AddRange(claims);
                        principalFromPrn.Claims = existingClaims;
                        return principalFromPrn;
                    }
                }
            }
        }

        var userId = TryGetString(payloadRoot, "oid")
                     ?? TryGetString(payloadRoot, "sub")
                     ?? TryGetString(payloadRoot, "nameid");

        if (string.IsNullOrWhiteSpace(userId) && claims.Count == 0)
        {
            return null;
        }

        return new ClientPrincipal
        {
            IdentityProvider = "aad",
            UserId = userId,
            Claims = claims
        };
    }

    private static ClientPrincipal? DeserializePrincipal(string json)
    {
        return JsonSerializer.Deserialize<ClientPrincipal>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    private static string? GetHeaderValue(HttpRequestData req, string headerName)
    {
        if (req.Headers.TryGetValues(headerName, out var values))
        {
            var value = values.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        foreach (var header in req.Headers)
        {
            if (!string.Equals(header.Key, headerName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = header.Value?.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static string? DecodePrincipalPayload(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        var decoded = Uri.UnescapeDataString(payload.Trim());
        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(NormalizeBase64(decoded)));
        }
        catch
        {
            if (decoded.StartsWith("{", StringComparison.Ordinal) || decoded.StartsWith("[", StringComparison.Ordinal))
            {
                return decoded;
            }

            return null;
        }
    }

    private static string? DecodeJwtPayload(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            return null;
        }

        var parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(NormalizeBase64(parts[1])));
        }
        catch
        {
            return null;
        }
    }

    private static string NormalizeBase64(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');
        }

        return normalized;
    }

    private static string? TryGetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static void AddClaimsFromJwtProperty(JsonElement payloadRoot, string propertyName, List<ClientPrincipalClaim> destination)
    {
        if (!payloadRoot.TryGetProperty(propertyName, out var element))
        {
            return;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            var value = element.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                destination.Add(new ClientPrincipalClaim { Type = propertyName, Value = value });
            }

            return;
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var value = item.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                destination.Add(new ClientPrincipalClaim { Type = propertyName, Value = value });
            }
        }
    }

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
    public string? IdentityProvider { get; set; }
    public string? UserId { get; set; }
    public string? UserDetails { get; set; }
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

    public string ClaimType => !string.IsNullOrWhiteSpace(Type) ? Type : Typ ?? string.Empty;
    public string ClaimValue => !string.IsNullOrWhiteSpace(Value) ? Value : Val ?? string.Empty;
}
