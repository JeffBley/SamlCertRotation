# Technical Reference

This document contains the detailed operational/reference content that was previously in the root README.

## Function App Endpoints

### Timer-Triggered Functions

| Function | Schedule | Description |
|----------|----------|-------------|
| `CertificateChecker` | Configurable via `RotationSchedule` (default: daily 6 AM UTC) | Checks all SAML apps and rotates certificates as needed |
| `StaleCertCleanupReminder` | Configurable via `StaleCertCleanupSchedule` (default: 1st of month 6 AM UTC) | Sends consolidated reminder emails to sponsors about expired inactive certificates |

### HTTP API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/dashboard/stats` | GET | Reader | Dashboard statistics with optional pagination |
| `/api/dashboard/my-apps` | GET | Sponsor | List SAML apps where the caller is the sponsor |
| `/api/applications` | GET | Reader | List all SAML applications with certificate details |
| `/api/applications/{id}` | GET | Reader | Get specific application details |
| `/api/applications/{id}/certificate` | POST | Admin | Create new certificate for application |
| `/api/applications/{id}/certificate/activate` | POST | Admin | Activate the newest certificate |
| `/api/applications/{id}/resend-reminder` | POST | Admin | Resend sponsor expiration reminder email |
| `/api/applications/{id}/sponsor` | PUT | Admin | Update application sponsor email |
| `/api/applications/bulk-update-sponsors` | POST | Admin | Bulk update sponsor emails via CSV |
| `/api/sponsor/applications/{id}/certificate` | POST | Sponsor | Sponsor: create new certificate (if admin-enabled) |
| `/api/sponsor/applications/{id}/certificate/activate` | POST | Sponsor | Sponsor: activate newest certificate (if admin-enabled) |
| `/api/sponsor/applications/{id}/policy` | PUT | Sponsor | Sponsor: update app policy (if admin-enabled) |
| `/api/sponsor/applications/{id}/sponsor` | PUT | Sponsor | Sponsor: update sponsor email (if admin-enabled) |
| `/api/policy` | GET | Reader | Get global rotation policy |
| `/api/policy` | PUT | Admin | Update global rotation policy |
| `/api/policy/app/{id}` | GET | Reader | Get app-specific or effective policy |
| `/api/policy/app/{id}` | PUT | Admin | Update app-specific policy override |
| `/api/settings` | GET | Reader | Get all settings including session timeout |
| `/api/settings` | PUT | Admin | Update settings |
| `/api/audit` | GET | Reader | Get audit logs (date range or days-back query) |
| `/api/audit/app/{id}` | GET | Reader | Get audit logs for specific app |
| `/api/reports` | GET | Reader | List all run reports |
| `/api/reports/{id}` | GET | Reader | Get specific run report with detailed results |
| `/api/rotation/trigger/prod` | POST | Admin | Trigger production rotation run |
| `/api/rotation/trigger/report-only` | POST | Admin | Trigger report-only rotation run |
| `/api/testing/send-test-email` | POST | Admin | Send test notification email |
| `/api/testing/email-templates` | GET | Admin | Preview all email template HTML |
| `/api/GetRoles` | GET/POST | — | Get current user's roles (SWA rolesSource) |

## Configuration

### Custom Security Attribute

Create in Microsoft Entra Admin Center:
- **Attribute Set**: `SamlCertRotation`
- **Attribute**: `AutoRotate` (String, single value)
- **Allowed Values**: `on`, `off`, `notify`

### Function App Settings

| Setting | Required | Description |
|---------|----------|-------------|
| `KeyVaultUri` | Yes | Key Vault URI for secrets |
| `TenantId` | Yes | Azure AD tenant ID |
| `StorageConnectionString` | Yes | Key Vault reference for Table Storage connection string |
| `LogicAppEmailUrl` | Yes | Key Vault reference for Logic App HTTP trigger URL |
| `AdminNotificationEmails` | No | Comma-separated emails for daily summary (set via Bicep param) |
| `AZURE_CLIENT_ID` | Auto | Managed identity client ID (set by Bicep) |
| `RotationSchedule` | No | CRON expression for cert rotation (default: `0 0 6 * * *`) |
| `StaleCertCleanupSchedule` | No | CRON expression for stale cert reminders (default: `0 0 6 1 * *`) |
| `CustomSecurityAttributeSet` | Yes | Attribute set name (default: `SamlCertRotation`) |
| `CustomSecurityAttributeName` | Yes | Attribute name (default: `AutoRotate`) |
| `DefaultCreateCertDaysBeforeExpiry` | No | Initial create-cert threshold (default: `60`) |
| `DefaultActivateCertDaysBeforeExpiry` | No | Initial activate-cert threshold (default: `30`) |
| `SWA_DEFAULT_HOSTNAME` | Auto | Static Web App default hostname (set by Bicep) |
| `SWA_HOSTNAME` | No | Custom domain hostname (if configured) |

### Policy Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Create Certificate Days | 60 | Days before expiry to create new certificate |
| Activate Certificate Days | 30 | Days before expiry to activate new certificate |
| Notification Emails | — | Comma-separated admin emails for daily summary |
| Sponsors Receive Notifications | Enabled | Whether sponsors receive cert-created/activated/reminder emails |
| 1st/2nd/3rd Sponsor Reminder Days | 30/7/1 | Milestone days for notify app reminders |
| Notify Sponsors on Expiration | Enabled | Send one-time email to sponsor when cert expires |
| Report-Only Mode | Enabled | Log what would happen without making changes |
| Create Certs for Notify Apps | Disabled | Create certificates for AutoRotate=notify apps (without activating) |
| Retention Policy Days | 180 | Days to retain audit log entries before purging |
| Reports Retention Policy Days | 14 | Days to retain run reports before purging |
| Session Timeout Minutes | 15 | Idle timeout for dashboard sessions (0 = disabled) |
| Stale Cert Cleanup Reminders | Enabled | Send monthly reminder emails to sponsors about expired inactive certs |
| Rotation Schedule | `0 0 6 * * *` | CRON schedule for cert rotation (configured in Function App settings) |
| Stale Cert Cleanup Schedule | `0 0 6 1 * *` | CRON schedule for cleanup reminders (configured in Function App settings) |

## Project Structure

```text
├── src/SamlCertRotation/
│   ├── Program.cs                               # DI and host configuration
│   ├── host.json                                # Function host settings
│   ├── SamlCertRotation.csproj                  # Project file (.NET 8)
│   ├── Functions/
│   │   ├── DashboardFunctionBase.cs             # Shared auth pipeline for HTTP functions
│   │   ├── AppFunctions.cs                      # Stats, applications, my-apps endpoints
│   │   ├── PolicyFunctions.cs                   # Global and per-app policy endpoints
│   │   ├── SettingsFunctions.cs                 # Settings get/update endpoints
│   │   ├── AuditFunctions.cs                    # Audit log query endpoints
│   │   ├── ReportFunctions.cs                   # Run report endpoints
│   │   ├── SponsorFunctions.cs                  # Sponsor self-service endpoints
│   │   ├── AdminFunctions.cs                    # Admin actions (certs, triggers, testing)
│   │   ├── CertificateCheckerFunction.cs        # Timer-triggered rotation
│   │   ├── StaleCertCleanupReminderFunction.cs  # Timer-triggered stale cert reminders
│   │   └── RoleFunctions.cs                     # SWA rolesSource endpoint
│   ├── Services/
│   │   ├── CertificateRotationService.cs        # Certificate lifecycle operations
│   │   ├── ICertificateRotationService.cs
│   │   ├── GraphService.cs                      # Microsoft Graph API client
│   │   ├── IGraphService.cs
│   │   ├── PolicyService.cs                     # Policy storage (Table Storage)
│   │   ├── IPolicyService.cs
│   │   ├── AuditService.cs                      # Audit logging (Table Storage)
│   │   ├── IAuditService.cs
│   │   ├── NotificationService.cs               # Email notifications via Logic App
│   │   ├── INotificationService.cs
│   │   ├── ReportService.cs                     # Run reports (GZip compressed)
│   │   └── IReportService.cs
│   ├── Helpers/
│   │   ├── AuthHelper.cs                        # JWT/token validation helpers
│   │   └── UrlHelper.cs                         # URL construction helpers
│   └── Models/                                  # Data models
├── dashboard/
│   ├── index.html                               # Single-page dashboard
│   ├── app.js                                   # Dashboard JavaScript
│   ├── unauthorized.html                        # Access denied page
│   ├── staticwebapp.config.json                 # SWA auth/routes configuration
│   ├── package.json                             # Node.js dependencies
│   └── vite.config.js                           # Vite dev server config
├── infrastructure/
│   ├── main.bicep                               # Azure infrastructure (IaC)
│   └── main.parameters.json                     # Deployment parameters
├── scripts/
│   └── redeploy-functions.ps1                   # Cloud Shell redeploy helper
├── DEPLOYMENT_GUIDE.md                          # Step-by-step deployment
└── README.md                                    # Landing page
```

## Security

- **No stored credentials**: Uses Azure Managed Identity for Graph API access
- **Key Vault for secrets**: Dashboard client secret stored only in Key Vault
- **Entra ID authentication**: Dashboard requires authenticated users
- **Role-gated access**: Only users with admin or reader roles can access API endpoints. Authenticated-only users are denied (403).
- **App assignment required**: Only assigned users can access dashboard
- **Audit trail**: All operations logged with user UPN attribution for compliance
- **XSS prevention**: All user content is escaped before rendering
- **Error sanitization**: Stack traces, connection strings, and secrets are filtered from API error responses
- **Input validation**: GUID format validation on all ID parameters, email format validation on sponsor updates, OData injection prevention on audit queries
- **Security headers**: HSTS, CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, strict Referrer-Policy

## Known Limitations

### Key Vault References for Platform Settings on Consumption Plan

The Function App runs on a **Consumption plan**. The `AzureWebJobsStorage` and `WEBSITE_CONTENTAZUREFILECONNECTIONSTRING` app settings **cannot** use Key Vault references (`@Microsoft.KeyVault(...)`) on this plan. The Azure Functions runtime needs these values to mount the Azure Files content share *before* the app starts, but Key Vault reference resolution happens *during* app startup — creating a chicken-and-egg problem that prevents the SCM (Kudu) site from starting, which blocks all deployments.

These two settings use inline connection strings in `main.bicep`. All other secrets (e.g., `StorageConnectionString` used by application code, `LogicAppEmailUrl`) continue to use Key Vault references.

The fully secure alternative is [identity-based connections](https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference?tabs=blob#configure-an-identity-based-connection) using `AzureWebJobsStorage__accountName` with managed identity RBAC, but this has [limitations on Consumption plan](https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference?tabs=blob#connecting-to-host-storage-with-an-identity) and is not currently implemented.
