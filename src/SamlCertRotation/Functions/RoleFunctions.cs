using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text.Json;

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
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "GetRoles")] HttpRequestData req)
    {
        try
        {
            // Read the client principal from the request body
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var clientPrincipal = JsonSerializer.Deserialize<ClientPrincipal>(requestBody, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (clientPrincipal == null)
            {
                _logger.LogWarning("No client principal provided");
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
                    .Where(c => c.Type == "groups" || c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
                    .Select(c => c.Value)
                    .ToList();

                var appRoleClaims = clientPrincipal.Claims
                    .Where(c => c.Type == "roles" || c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                    .Select(c => c.Value)
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
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}
