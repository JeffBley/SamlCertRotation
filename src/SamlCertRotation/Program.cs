using Azure.Data.Tables;
using Azure.Core;
using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Graph;
using SamlCertRotation.Services;

// Application entry point: configures dependency injection for Functions runtime,
// Graph access, storage clients, and domain services.
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices((context, services) =>
    {
        var configuration = context.Configuration;

        // Configure Application Insights
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        // Register Microsoft Graph client with Managed Identity
        services.AddSingleton<TokenCredential>(sp =>
        {
            var managedIdentityClientId = configuration["AZURE_CLIENT_ID"];
            return new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ManagedIdentityClientId = managedIdentityClientId
            });
        });

        services.AddSingleton(sp =>
        {
            var credential = sp.GetRequiredService<TokenCredential>();
            return new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
        });

        // Register Table Service Client
        services.AddSingleton(sp =>
        {
            var connectionString = ResolveStorageConnectionString(configuration);
            return new TableServiceClient(connectionString);
        });

        // Register Blob Service Client (used for distributed locks)
        services.AddSingleton(sp =>
        {
            var connectionString = ResolveStorageConnectionString(configuration);
            return new BlobServiceClient(connectionString);
        });

        // Register application services
        services.AddSingleton<IGraphService, GraphService>();
        services.AddSingleton<IPolicyService, PolicyService>();
        services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton<IAuditService, AuditService>();
        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<ICertificateRotationService, CertificateRotationService>();

        // Register HttpClient for any external calls
        services.AddHttpClient();
    })
    .Build();

host.Run();

/// <summary>
/// Resolves the storage connection string, falling back to AzureWebJobsStorage if
/// StorageConnectionString is missing or contains an unresolved Key Vault reference.
/// Throws a clear error at startup if neither setting provides a usable value.
/// </summary>
static string ResolveStorageConnectionString(Microsoft.Extensions.Configuration.IConfiguration configuration)
{
    var connectionString = configuration["StorageConnectionString"];

    // If the value is an unresolved Key Vault reference (e.g. firewall blocked resolution),
    // the literal "@Microsoft.KeyVault(...)" string is returned instead of null.
    // Detect this and fall back to AzureWebJobsStorage which is set as a plain value.
    if (string.IsNullOrWhiteSpace(connectionString)
        || connectionString.StartsWith("@Microsoft.KeyVault", StringComparison.OrdinalIgnoreCase))
    {
        connectionString = configuration["AzureWebJobsStorage"];
    }

    if (string.IsNullOrWhiteSpace(connectionString))
    {
        throw new InvalidOperationException(
            "No storage connection string available. Ensure either 'StorageConnectionString' "
            + "(via Key Vault reference) or 'AzureWebJobsStorage' is configured in app settings.");
    }

    return connectionString;
}
