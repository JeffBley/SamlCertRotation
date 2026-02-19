using Azure.Data.Tables;
using Azure.Identity;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Graph;
using SamlCertRotation.Services;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices((context, services) =>
    {
        var configuration = context.Configuration;

        // Configure Application Insights
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        // Register Microsoft Graph client with Managed Identity
        services.AddSingleton(sp =>
        {
            var managedIdentityClientId = configuration["AZURE_CLIENT_ID"];
            var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ManagedIdentityClientId = managedIdentityClientId
            });
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
        services.AddSingleton<ISwaSettingsService, SwaSettingsService>();

        // Register HttpClient for any external calls
        services.AddHttpClient();
    })
    .Build();

host.Run();
