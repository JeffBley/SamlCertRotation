using Azure.Data.Tables;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
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
            var connectionString = configuration["StorageConnectionString"] 
                ?? configuration["AzureWebJobsStorage"];
            return new TableServiceClient(connectionString);
        });

        // Register Blob Service Client (used for distributed locks)
        services.AddSingleton(sp =>
        {
            var connectionString = configuration["StorageConnectionString"]
                ?? configuration["AzureWebJobsStorage"];
            return new BlobServiceClient(connectionString);
        });

        // Register Key Vault Secret Client Factory.
        // Each app's credential may live in a different Key Vault; the factory creates
        // and caches one SecretClient per unique vault URI using the managed identity.
        // The default vault URI comes from the KeyVaultUri app setting.
        services.AddSingleton<SecretClientFactory>();

        // Keep a default SecretClient singleton for code that doesn't need per-app routing.
        services.AddSingleton(sp =>
        {
            var factory = sp.GetRequiredService<SecretClientFactory>();
            return factory.GetClient();
        });

        // Register application services
        services.AddSingleton<IGraphService, GraphService>();
        services.AddSingleton<IPolicyService, PolicyService>();
        services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton<IAuditService, AuditService>();
        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<ICertificateRotationService, CertificateRotationService>();
        services.AddSingleton<IAppApiConfigService, AppApiConfigService>();
        services.AddSingleton<IAppApiClient, AppApiClientService>();

        // Register HttpClient for any external calls
        services.AddHttpClient();
    })
    .Build();

host.Run();
