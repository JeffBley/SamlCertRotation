# SAML Certificate Rotation Tool

Automated SAML certificate lifecycle management for Microsoft Entra ID Enterprise Applications with a web-based dashboard for monitoring and manual operations.

## Key Features & Capabilities

### 1. Automated SAML Certificate Rotation Engine

- **Two-phase rotation lifecycle**: (1) **Create** a new certificate when the active cert is within `CreateCertDaysBeforeExpiry` (default 30 days), and (2) **Activate** the pending cert when within `ActivateCertDaysBeforeExpiry` (default 14 days). Each threshold is independently configurable.
  - Global Policy defining each threshold can be overwritten per-app.
- **Timer-triggered scanner** runs on a configurable CRON schedule (default: daily 6:00 AM UTC via `RotationSchedule` app setting).
- Each SAML service principal has an `AutoRotate` custom security attribute (in attribute set `SamlCertRotation`) with these modes:
  - **`on`** — Full auto-rotation (create + activate certificates automatically).
  - **`notify`** — Notify-only mode; sends milestone reminders to the app sponsor but does not create/activate certificates.
  - **`off`** — Explicitly excluded from processing.
  - **Not set** — Not configured; excluded from rotation runs.

### 2. Report-Only Mode
- A global **report-only mode** setting enabled by default. When active, the timer-triggered run logs what *would* happen (`Would Create`, `Would Activate`) but makes no actual changes.
- Can be toggled in the Settings tab of the dashboard by admins.
- Manual runs also support explicit report-only or production mode selection.

### 3. Application Sponsor Management
- Each service principal can have one or more **AppSponsor** emails stored as a tag on the service principal: `AppSponsor=email@example.com`.
- Admins can **edit the sponsor** via the Applications tab actions menu or in bulk via uploading a CSV. Prefilled and template CSV's can be downloaded.

### 4. Email Notification System via Logic App
- Email notifications can be sent to app sponsors when the certificates are nearing their expiration, when certificates are automatically created/activated, or when stale certificates require deletion. Multiple configuration options are available.
- Specific emails can be configured to receive daily summaries of the automated runs.
- Emails are sent via an **Azure Logic App** (Office 365 Outlook connector) triggered by HTTP POST from the Function App.

### 5. SAML Certificate Insights
- Overview provides at-a-glance understanding of SAML certificate health and auto-rotate status.
- Applications tab provides app-specific info with sort, filter, and export functions.
- Certificate clean-up tab identifies applications with expired inactive certificates that should be deleted. Admins can click deeplink to go straight to the application in Entra ID or can export list as CSV or JSON.
- Reports for each run available.

### 13. Audit Log System REVIEW
- Every significant action logged to Azure Table Storage with: ServicePrincipalId, AppDisplayName, ActionType, Description, IsSuccess, ErrorMessage, CertificateThumbprint, NewCertificateThumbprint, PerformedBy (user UPN or "System").
- **12 action types**: CertificateCreated, CertificateCreatedReportOnly, CertificateActivated, CertificateActivatedReportOnly, CertificateExpiringSoon, NotificationSent, PolicyUpdated, ScanCompleted, ScanCompletedReportOnly, SponsorUpdated, SponsorExpirationReminderSent, Error.
- **Bulk audit query** with GUID validation to prevent OData injection.

### 7. Audit Log and Reports Retention & Purge
- Configurable retention policy for audit logs (default: 180 days). After each timer run, entries older than the retention period are purged in batched transactions.
- Configurable retention policy for Run Reports (default:14 days). After each timer run, entries older than the retention period are purged in batched transactions.

### 8. Role-Based Access Control (RBAC)
- Three roles available: **Admin**, **Reader**, and **Sponsor**.
- Admins have full read/write permissions in the app.
- Readers can view but cannot take update or write actions.
- Sponsors have special view and can only see information about their own applications. They can take write actions from directly in the app if the admin allows it:
  - Edit sponsor field on their apps (default enabled)
  - Edit policy on their apps - I.e. when to automate creation and activation of new certs (default disabled)
  - Manually trigger creation and activation of new certs (default disabled)



### 9. Additional Dashboard Features
- 

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
│          │                                 │(Reports) │                     │
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

### HTTP API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/dashboard/stats` | GET | Reader | Dashboard statistics with optional pagination |
| `/api/applications` | GET | Reader | List all SAML applications with certificate details |
| `/api/applications/{id}` | GET | Reader | Get specific application details |
| `/api/applications/{id}/certificate` | POST | Admin | Create new certificate for application |
| `/api/applications/{id}/certificate/activate` | POST | Admin | Activate the newest certificate |
| `/api/applications/{id}/resend-reminder` | POST | Admin | Resend sponsor expiration reminder email |
| `/api/applications/{id}/sponsor` | PUT | Admin | Update application sponsor email |
| `/api/policy` | GET | Reader | Get global rotation policy |
| `/api/policy` | PUT | Admin | Update global rotation policy |
| `/api/policy/app/{id}` | GET | Reader | Get app-specific or effective policy |
| `/api/policy/app/{id}` | PUT | Admin | Update app-specific policy override |
| `/api/audit` | GET | Reader | Get audit logs (date range or days-back query) |
| `/api/audit/app/{id}` | GET | Reader | Get audit logs for specific app |
| `/api/settings` | GET | Reader | Get all settings including session timeout |
| `/api/settings` | PUT | Admin | Update settings |
| `/api/admin/trigger-rotation/prod` | POST | Admin | Trigger production rotation run |
| `/api/admin/trigger-rotation/report-only` | POST | Admin | Trigger report-only rotation run |
| `/api/reports` | GET | Reader | List all run reports |
| `/api/reports/{id}` | GET | Reader | Get specific run report with detailed results |
| `/api/applications/bulk-update-sponsors` | POST | Admin | Bulk update sponsor emails |
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
| `RotationSchedule` | No | CRON expression (default: `0 0 6 * * *`) |
| `AZURE_CLIENT_ID` | Auto | Managed identity client ID |

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
| Rotation Schedule | `0 0 6 * * *` | CRON schedule (configured in Function App settings) |

## Project Structure

```
├── src/SamlCertRotation/
│   ├── Functions/
│   │   ├── CertificateCheckerFunction.cs    # Timer-triggered rotation
│   │   ├── DashboardFunctions.cs            # HTTP API endpoints
│   │   └── RoleFunctions.cs                 # Role/auth endpoints
│   ├── Services/
│   │   ├── CertificateRotationService.cs    # Certificate operations
│   │   ├── GraphService.cs                  # Microsoft Graph API
│   │   ├── PolicyService.cs                 # Policy storage (Table)
│   │   ├── AuditService.cs                  # Audit logging (Table)
│   │   ├── NotificationService.cs           # Email notifications
│   │   ├── ReportService.cs                 # Run report storage (GZip compressed)
│   │   └── IReportService.cs                # Report service interface
│   └── Models/                              # Data models
├── dashboard/
│   ├── index.html                           # Single-page dashboard
│   ├── app.js                               # Dashboard JavaScript (extracted)
│   ├── unauthorized.html                    # Access denied page
│   ├── favicon.png                          # Dashboard favicon
│   └── staticwebapp.config.json             # SWA auth configuration
├── infrastructure/
│   ├── main.bicep                           # Azure infrastructure
│   └── main.parameters.json                 # Deployment parameters
├── scripts/
│   └── redeploy-functions.ps1               # Cloud Shell redeploy helper
├── DEPLOYMENT_GUIDE.md                      # Step-by-step deployment
└── README.md                                # This file
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

## License

MIT
