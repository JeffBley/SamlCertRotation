using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SamlCertRotation.Services;

namespace SamlCertRotation.Functions;

/// <summary>
/// HTTP functions for application listing and dashboard statistics.
/// </summary>
public class AppFunctions : DashboardFunctionBase
{
    public AppFunctions(
        ICertificateRotationService rotationService,
        IGraphService graphService,
        IPolicyService policyService,
        IAuditService auditService,
        INotificationService notificationService,
        IReportService reportService,
        IConfiguration configuration,
        ILogger<AppFunctions> logger)
        : base(rotationService, graphService, policyService, auditService, notificationService, reportService, configuration, logger)
    {
    }

    /// <summary>
    /// Get dashboard statistics.
    /// Supports optional server-side pagination via ?page=1&amp;pageSize=50 query parameters.
    /// When omitted, all apps are returned (backward compatible).
    /// </summary>
    [Function("GetDashboardStats")]
    public async Task<HttpResponseData> GetDashboardStats(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "dashboard/stats")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

        _logger.LogInformation("Getting dashboard stats");

        try
        {
            var stats = await _rotationService.GetDashboardStatsAsync();

            // Support optional server-side pagination for the apps list
            var queryParams = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
            if (int.TryParse(queryParams["page"], out var page) && int.TryParse(queryParams["pageSize"], out var pageSize))
            {
                page = Math.Max(1, page);
                pageSize = Math.Clamp(pageSize, 1, 500);
                var totalApps = stats.Apps.Count;
                var totalPages = (int)Math.Ceiling((double)totalApps / pageSize);

                stats.Apps = stats.Apps
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToList();

                return await CreateJsonResponse(req, new
                {
                    stats.TotalSamlApps,
                    stats.AppsWithAutoRotateOn,
                    stats.AppsWithAutoRotateOff,
                    stats.AppsWithAutoRotateNotify,
                    stats.AppsWithAutoRotateNull,
                    stats.AppsExpiringSoon,
                    stats.ExpiringSoonThresholdDays,
                    stats.AppsExpiringIn60Days,
                    stats.AppsExpiringIn90Days,
                    stats.AppsWithExpiredCerts,
                    stats.GeneratedAt,
                    apps = stats.Apps,
                    pagination = new { page, pageSize, totalApps, totalPages }
                });
            }

            return await CreateJsonResponse(req, stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting dashboard stats");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get all SAML applications
    /// </summary>
    [Function("GetApplications")]
    public async Task<HttpResponseData> GetApplications(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "applications")] HttpRequestData req)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

        _logger.LogInformation("Getting all SAML applications");

        try
        {
            var apps = await _graphService.GetSamlApplicationsAsync();
            return await CreateJsonResponse(req, apps);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting applications");
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get SAML applications where the current user is a sponsor.
    /// Accessible by users with the sponsor, reader, or admin role.
    /// Also returns the sponsorsCanRotateCerts setting so the UI can render action buttons.
    /// </summary>
    [Function("GetMyApplications")]
    public async Task<HttpResponseData> GetMyApplications(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "dashboard/my-apps")] HttpRequestData req)
    {
        // Fix #7: AuthorizeRequestAsync now returns identity, eliminating the second ParseClientPrincipalAsync call
        var (authError, identity) = await AuthorizeRequestAsync(req, allowSponsor: true);
        if (authError != null) return authError;

        var userEmail = identity?.UserPrincipalName;

        if (string.IsNullOrWhiteSpace(userEmail))
        {
            return await CreateErrorResponse(req, "Unable to determine your email address for sponsor matching.", HttpStatusCode.BadRequest);
        }

        _logger.LogInformation("Getting sponsored SAML applications for {UserEmail}", userEmail);

        try
        {
            // Fetch full apps once and reuse for both stats filtering and certificate data
            var fullApps = await _graphService.GetSamlApplicationsAsync();
            var fullAppLookup = fullApps.ToDictionary(a => a.Id, a => a);

            var stats = await _rotationService.GetDashboardStatsAsync(fullApps);
            var myApps = stats.Apps
                .Where(a => IsSponsorOf(a.Sponsor, userEmail))
                .ToList();

            var appsWithCerts = myApps.Select(app =>
            {
                object[] certs = fullAppLookup.TryGetValue(app.Id, out var fullApp)
                    ? fullApp.Certificates.Select(c => (object)new
                    {
                        c.KeyId,
                        c.Thumbprint,
                        c.StartDateTime,
                        c.EndDateTime,
                        c.IsActive,
                        c.DaysUntilExpiry
                    }).ToArray()
                    : Array.Empty<object>();

                return new
                {
                    app.Id,
                    app.AppId,
                    app.DisplayName,
                    app.Sponsor,
                    app.AutoRotateStatus,
                    app.CertExpiryDate,
                    app.DaysUntilExpiry,
                    app.ExpiryCategory,
                    app.PolicyType,
                    app.CreateCertDaysBeforeExpiry,
                    app.ActivateCertDaysBeforeExpiry,
                    Certificates = certs
                };
            }).ToList();

            var sponsorsCanRotateCertsTask = _policyService.GetSponsorsCanRotateCertsEnabledAsync();
            var sponsorsCanUpdatePolicyTask = _policyService.GetSponsorsCanUpdatePolicyEnabledAsync();
            var sponsorsCanEditSponsorsTask = _policyService.GetSponsorsCanEditSponsorsEnabledAsync();

            await Task.WhenAll(sponsorsCanRotateCertsTask, sponsorsCanUpdatePolicyTask, sponsorsCanEditSponsorsTask);

            // Fix #9: Use .Result after Task.WhenAll since tasks are guaranteed complete
            return await CreateJsonResponse(req, new
            {
                apps = appsWithCerts,
                sponsorsCanRotateCerts = sponsorsCanRotateCertsTask.Result,
                sponsorsCanUpdatePolicy = sponsorsCanUpdatePolicyTask.Result,
                sponsorsCanEditSponsors = sponsorsCanEditSponsorsTask.Result
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting sponsored applications for {UserEmail}", userEmail);
            return await CreateErrorResponse(req, ex.Message);
        }
    }

    /// <summary>
    /// Get a specific application
    /// </summary>
    [Function("GetApplication")]
    public async Task<HttpResponseData> GetApplication(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "applications/{id}")] HttpRequestData req,
        string id)
    {
        var (authError, _) = await AuthorizeRequestAsync(req);
        if (authError != null) return authError;

        _logger.LogInformation("Getting application {Id}", id);

        if (!IsValidGuid(id))
        {
            return await CreateErrorResponse(req, "Invalid application ID format", HttpStatusCode.BadRequest);
        }

        try
        {
            var app = await _graphService.GetSamlApplicationAsync(id);
            if (app == null)
            {
                var notFound = req.CreateResponse(HttpStatusCode.NotFound);
                return notFound;
            }
            return await CreateJsonResponse(req, app);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting application {Id}", id);
            return await CreateErrorResponse(req, ex.Message);
        }
    }
}
