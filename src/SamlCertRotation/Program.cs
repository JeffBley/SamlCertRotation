using Azure.Data.Tables;
using Azure.Core;
using Azure.Identity;
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

        // Register application services
        services.AddSingleton<IGraphService, GraphService>();
        services.AddSingleton<IPolicyService, PolicyService>();
        services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton<IAuditService, AuditService>();
        services.AddSingleton<ICertificateRotationService, CertificateRotationService>();

        // Register HttpClient for any external calls
        services.AddHttpClient();
    })
    .Build();

host.Run();
