# SAML Certificate Rotation Tool

Automated SAML certificate lifecycle management for Microsoft Entra ID Enterprise Applications with a web-based dashboard for monitoring and manual operations.

## Features

### Automatic Certificate Management
- **Scheduled Certificate Rotation**: Timer-triggered function checks certificates daily and rotates before expiration
- **Custom Security Attribute Control**: Tag applications with `SamlCertRotation.AutoRotate=on/off` to include/exclude from auto-rotation
- **Policy-Based Thresholds**: Configure days before expiry to create new certificates and activate them
- **Configurable Schedule**: Set custom CRON schedule via Function App settings

### Dashboard Capabilities
- **Applications Overview**: View all SAML applications with certificate status, expiration dates, and thumbprints
- **Manual Certificate Operations**: Create new certificates and activate the newest certificate per application
- **Certificate Cleanup**: Identify applications with expired inactive certificates that may need attention
- **Export to CSV**: Export application lists and cleanup reports
- **Policy Management**: Configure global rotation thresholds
- **Audit Logs**: Complete audit trail of all certificate operations
- **Settings**: View rotation schedule and rotate dashboard client secret

### Security & Integration
- **Managed Identity Authentication**: Function App uses managed identity for Microsoft Graph API access
- **Key Vault Integration**: Dashboard client secrets stored in Key Vault and auto-synced to SWA settings
- **Entra ID SSO**: Dashboard protected with Microsoft Entra ID authentication
- **Role-Based Access**: Control dashboard access via Entra ID app assignment
- **Email Notifications**: Logic App integration for certificate operation alerts

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Azure Resources                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐     ┌─────────────────┐     ┌──────────────────────┐  │
│  │  Static Web App  │────▶│  Function App   │────▶│  Microsoft Graph API │  │
│  │   (Dashboard)    │     │  (.NET 8)       │     │  (Entra ID)          │  │
│  └──────────────────┘     └─────────────────┘     └──────────────────────┘  │
│          │                        │                                          │
│          │                        ├──────────────┐                           │
│          │                        ▼              ▼                           │
│          │                ┌─────────────┐  ┌──────────┐                     │
│          │                │   Key Vault │  │ Table    │                     │
│          │                │  (Secrets)  │  │ Storage  │                     │
│          │                └─────────────┘  │(Policies)│                     │
│          │                                 │(Audit)   │                     │
│          │                                 └──────────┘                     │
│          │                                                                   │
│          │                ┌─────────────────────────────┐                   │
│          └───────────────▶│  Managed Identity           │                   │
│                           │  (Graph API Permissions)    │                   │
│                           └─────────────────────────────┘                   │
│                                                                              │
│  ┌──────────────────┐     ┌─────────────────┐                               │
│  │    Logic App     │────▶│  Office 365     │───▶ Email Notifications      │
│  │  (Email Trigger) │     │  Connection     │                               │
│  └──────────────────┘     └─────────────────┘                               │
│                                                                              │
│  ┌──────────────────┐     ┌─────────────────┐                               │
│  │  Log Analytics   │◀────│ App Insights    │                               │
│  │   Workspace      │     │ (Monitoring)    │                               │
│  └──────────────────┘     └─────────────────┘                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed step-by-step instructions.

### Deployment Reliability Note

For Function App deployments, use:

```powershell
func azure functionapp publish <FUNCTION_APP_NAME> --dotnet-isolated
```

Avoid `az functionapp deployment source config-zip` for this project. It can publish artifacts that intermittently fail function indexing, which surfaces as `/api/*` returning `404` after redeploy.

Cloud Shell helper script:

```powershell
pwsh ./scripts/redeploy-functions.ps1 -FunctionAppName <FUNCTION_APP_NAME> -ResourceGroup <RESOURCE_GROUP>
```

### Prerequisites

- Azure Subscription with Owner or Contributor access
- Microsoft Entra ID privileges to:
  - Create app registrations
  - Grant admin consent for Graph API permissions
  - Create Custom Security Attributes
- Azure Cloud Shell (recommended) or local environment with:
  - Azure CLI 2.50+
  - .NET 8 SDK
  - Node.js 18+

### High-Level Deployment Steps

1. Create Custom Security Attribute (`SamlCertRotation.AutoRotate`)
2. Deploy Azure infrastructure via Bicep
3. Grant Microsoft Graph API permissions to managed identity
4. Deploy Function App code
5. Configure dashboard app registration and Entra ID authentication
6. Deploy Static Web App dashboard
7. Configure email notifications (Logic App)
8. Tag SAML applications for auto-rotation

## Function App Endpoints

### Timer-Triggered Functions

| Function | Schedule | Description |
|----------|----------|-------------|
| `CertificateChecker` | Configurable (default: 6 AM UTC) | Checks all SAML apps and rotates certificates as needed |
| `RotateSwaClientSecret` | Daily at 3 AM UTC | Auto-rotates dashboard client secret when near expiry |

### HTTP API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard/stats` | GET | Dashboard statistics (total apps, expiring certs, etc.) |
| `/api/applications` | GET | List all SAML applications with certificate details |
| `/api/applications/{id}` | GET | Get specific application details |
| `/api/applications/{id}/certificate` | POST | Create new certificate for application |
| `/api/applications/{id}/certificate/activate` | POST | Activate the newest certificate |
| `/api/policy` | GET | Get global rotation policy |
| `/api/policy` | PUT | Update global rotation policy |
| `/api/policy/app/{id}` | GET | Get app-specific policy |
| `/api/policy/app/{id}` | PUT | Update app-specific policy |
| `/api/audit` | GET | Get audit logs |
| `/api/audit/app/{id}` | GET | Get audit logs for specific app |
| `/api/settings` | GET | Get settings (including rotation schedule) |
| `/api/settings` | PUT | Update settings |
| `/api/settings/rotate-secret` | POST | Rotate dashboard client secret |
| `/api/admin/trigger-rotation` | POST | Manually trigger rotation check |
| `/api/GetRoles` | GET/POST | Get current user's roles (SWA roles source) |

## Configuration

### Custom Security Attribute

Create in Microsoft Entra Admin Center:
- **Attribute Set**: `SamlCertRotation`
- **Attribute**: `AutoRotate` (String, single value)
- **Allowed Values**: `on`, `off`

### Function App Settings

| Setting | Required | Description |
|---------|----------|-------------|
| `KeyVaultUri` | Yes | Key Vault URI for secrets |
| `SWA_CLIENT_ID` | Yes | Dashboard app registration client ID |
| `RotationSchedule` | No | CRON expression (default: `0 0 6 * * *`) |
| `SubscriptionId` | Yes | Azure Subscription ID (for SWA updates) |
| `SwaResourceGroup` | Yes | Resource group containing SWA |
| `SwaName` | Yes | Static Web App resource name |
| `AZURE_CLIENT_ID` | Auto | Managed identity client ID |

### Policy Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Create Certificate Days | 60 | Days before expiry to create new certificate |
| Activate Certificate Days | 30 | Days before expiry to activate new certificate |

## Project Structure

```
├── src/SamlCertRotation/
│   ├── Functions/
│   │   ├── CertificateCheckerFunction.cs    # Timer-triggered rotation
│   │   ├── ClientSecretRotationFunction.cs  # Dashboard secret rotation
│   │   ├── DashboardFunctions.cs            # HTTP API endpoints
│   │   └── RoleFunctions.cs                 # Role/auth endpoints
│   ├── Services/
│   │   ├── CertificateRotationService.cs    # Certificate operations
│   │   ├── GraphService.cs                  # Microsoft Graph API
│   │   ├── PolicyService.cs                 # Policy storage (Table)
│   │   ├── AuditService.cs                  # Audit logging (Table)
│   │   └── NotificationService.cs           # Email notifications
│   └── Models/                              # Data models
├── dashboard/
│   ├── index.html                           # Single-page dashboard
│   └── staticwebapp.config.json             # SWA auth configuration
├── infrastructure/
│   ├── main.bicep                           # Azure infrastructure
│   └── main.parameters.json                 # Deployment parameters
├── DEPLOYMENT_GUIDE.md                      # Step-by-step deployment
└── README.md                                # This file
```

## Dashboard Features

### Applications Tab
- View all SAML-enabled enterprise applications
- See certificate status: Active, Expiring Soon, Expired
- View thumbprints and expiration dates
- Filter by name, status, or auto-rotate setting
- Create new certificates manually
- Activate newest certificate manually
- Export filtered list to CSV

### Certificate Cleanup Tab
- Identify applications with expired inactive certificates
- Helps maintain clean certificate hygiene
- Export cleanup report to CSV

### Policy Tab
- Configure global rotation thresholds
- Set days before expiry for certificate creation
- Set days before expiry for certificate activation

### Audit Logs Tab
- View all certificate operations
- Filter by application or date range
- Track automatic and manual rotations

### Settings Tab
- View current rotation schedule (CRON format)
- Rotate dashboard client secret (stored in Key Vault)

## Security

- **No stored credentials**: Uses Azure Managed Identity for Graph API
- **Key Vault for secrets**: Dashboard client secret stored securely
- **Entra ID authentication**: Dashboard requires authenticated users
- **App assignment required**: Only assigned users can access dashboard
- **Audit trail**: All operations logged for compliance

## License

MIT
