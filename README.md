# SAML Certificate Rotation Tool

Automated SAML certificate lifecycle management for Microsoft Entra ID Enterprise Applications with a web-based dashboard for monitoring and manual operations.

## Features & Capabilities

### 1. Automated SAML Certificate Rotation Engine
- **Timer-triggered scanner** runs on a configurable CRON schedule (default: daily 6:00 AM UTC via `RotationSchedule` app setting).
- **Two-phase rotation lifecycle**: (1) **Create** a new certificate when the active cert is within `CreateCertDaysBeforeExpiry` (default 60 days), and (2) **Activate** the pending cert when within `ActivateCertDaysBeforeExpiry` (default 30 days). Each threshold is independently configurable.
- **Existing pending cert detection**: Before creating, checks whether a newer inactive certificate already exists on the service principal. If so, skips creation and proceeds to activation check.
- Queries Microsoft Graph for all service principals with `preferredSingleSignOnMode='saml'`, pages through all results, maps certificates (using Verify key credentials and X.509 thumbprint computation), and determines active cert by matching `preferredTokenSigningKeyThumbprint`.

### 2. Custom Security Attribute (CSA) — AutoRotate Control
- Each SAML service principal has an `AutoRotate` custom security attribute (in attribute set `SamlCertRotation`) with these modes:
  - **`on`** — Full auto-rotation (create + activate certificates automatically).
  - **`notify`** — Notify-only mode; sends milestone reminders to the app sponsor but does not create/activate certificates.
  - **`off`** — Explicitly excluded from processing.
  - **Not set** — Not configured; excluded from rotation runs.
- CSA values are read via MS Graph SDK first, then a **REST API fallback** is used because Graph often doesn't return CSAs in collection queries.
- Parallel fallback lookups with **SemaphoreSlim(20)** limit concurrency to avoid Graph throttling.

### 3. Report-Only Mode
- A global **report-only mode** setting (persisted in Table Storage, default: enabled). When active, the timer-triggered run logs what *would* happen (`Would Create`, `Would Activate`) but makes no actual changes.
- Can be toggled in the Settings tab of the dashboard by admins.
- Manual runs also support explicit report-only or production mode selection.

### 4. Global & Per-App Rotation Policies
- **Global policy**: `CreateCertDaysBeforeExpiry` and `ActivateCertDaysBeforeExpiry`, persisted in Azure Table Storage.
- **App-specific policy overrides**: Per-service-principal overrides for create/activate thresholds. Null fields fall back to global.
- **Effective policy merging**: App-specific overrides are merged with the global policy at runtime.
- The global policy thresholds also drive certificate **status categorization** (OK/Warning/Critical/Expired) for the dashboard and notifications.

### 5. Application Sponsor Management
- Each service principal can have an **AppSponsor** (email) stored as a tag on the service principal: `AppSponsor=email@example.com`.
- Admins can **edit the sponsor** via the Applications tab actions menu.
- Sponsor email is validated for format (server-side with `MailAddress`, client-side with regex).

### 6. Email Notification System via Logic App
- Emails are sent via an **Azure Logic App** (Office 365 Outlook connector) triggered by HTTP POST from the Function App.
- **Six notification types** (all HTML-formatted with Segoe UI styling):
  - **Certificate Created** — Sent to app sponsor when a new cert is generated (AutoRotate=on only).
  - **Certificate Activated** — Sent to sponsor when a cert is made active. Includes an "Action May Be Required" warning about updating the SAML SP (AutoRotate=on only).
  - **Error** — Sent to all notification recipients when rotation fails.
  - **Daily Summary** — Sent to admin recipients after each timer run with stats and per-app results table.
  - **Notify-Only Reminder** — For AutoRotate=notify apps: milestone-based reminders sent to the sponsor with Entra portal deep-link.
  - **Sponsor Expiration Notification** — Sent once per cert when it actually expires (AutoRotate=on or notify only).
- All user-supplied values are **HTML-encoded** before embedding in email templates.

### 7. Sponsor Notification Settings
- **Sponsors Receive Notifications** toggle (default: enabled). Controls whether sponsors get cert-created/activated/notify-only emails. Only applies to AutoRotate=on or notify apps.
- **Notify Sponsors on Expiration** toggle (default: enabled). Controls whether sponsors receive a one-time notification when their app's certificate actually expires. Only applies to AutoRotate=on or notify apps.
- **Three configurable sponsor reminder milestones** for notify-only apps (default: 30, 7, 1 days before expiry).
- **Milestone deduplication**: Before sending any reminder, the service checks audit log entries against the active cert thumbprint + milestone label to prevent duplicate sends.

### 8. Manual Trigger Runs from Dashboard
- **Report-Only Run** button — triggers an instant rotation scan, returning detailed per-app results without making changes.
- **Prod Run** button — triggers live certificate operations.
- Both require a **confirmation modal** before executing. Results show total processed, successful, skipped, and failed counts.
- Only accessible to admin-role users.

### 9. Manual Certificate Operations
- **Create new SAML certificate** — Per-app action that calls `AddTokenSigningCertificate` Graph API (3-year validity). Creates an inactive cert.
- **Activate newest certificate** — Finds the cert with the most recent `StartDateTime` (the most recently issued cert) and sets it as the active signing key.
- **Resend Reminder Email** — Manually re-sends a sponsor expiration status email for apps in Expired/Critical/Warning status. Blocked for OK-status apps.
- All manual operations are audited with `performedBy` attribution showing the user's UPN.

### 10. Dashboard Statistics & KPI Cards
- Six stat cards: Total SAML Apps, Auto-Rotate ON, Auto-Rotate OFF, Not Configured, Expiring ≤N Days (dynamic threshold), Expired.
- **Server-side pagination** supported via `?page=N&pageSize=N` query parameters.

### 11. Applications Tab — Filtering, Sorting & Actions
- **Search by name** — Free-text filter on application display name.
- **Auto-Rotate multi-select filter** — On, Off, Notify Only, Not Set.
- **Status multi-select filter** — Expired, Critical, Warning, OK.
- **Sponsor filter** — Free-text filter on sponsor email.
- **Sort by** — Name, Days Remaining, Expiry Date (ascending/descending).
- **Per-app actions dropdown** — Create cert, Activate cert, Edit Sponsor, Resend Reminder (admin only).

### 12. Certificate Clean-up Tab
- Identifies applications with **inactive AND expired certificates** that should be removed.
- Shows app name, app ID, and count of expired inactive certs.
- Notes that deletion must be done manually in Azure Portal.
- Exportable as JSON.

### 13. Audit Log System
- Every significant action logged to Azure Table Storage with: ServicePrincipalId, AppDisplayName, ActionType, Description, IsSuccess, ErrorMessage, CertificateThumbprint, NewCertificateThumbprint, PerformedBy (user UPN or "System").
- **12 action types**: CertificateCreated, CertificateCreatedReportOnly, CertificateActivated, CertificateActivatedReportOnly, CertificateExpiringSoon, NotificationSent, PolicyUpdated, ScanCompleted, ScanCompletedReportOnly, SponsorUpdated, SponsorExpirationReminderSent, Error.
- **Bulk audit query** with GUID validation to prevent OData injection.

### 14. Audit Log Tab — Filtering & Sorting
- **Date range picker** (default last 30 days).
- **Action type multi-select filter**.
- **Dynamic column filters** — Add filters on Application, Initiated By, Result, Details.
- **Sort by** — Time, Application, Initiated By, Action, Result (ascending/descending).

### 15. Audit Log Retention & Purge
- **Configurable retention policy** (default: 180 days). After each timer run, entries older than the retention period are purged in batched transactions.

### 16. Role-Based Access Control (RBAC)
- Three roles: **Admin**, **Reader**, **Authenticated**.
- **GetRoles function** (`/api/GetRoles`): Called by SWA `rolesSource`. Maps Entra group IDs and app roles to admin/reader dashboard roles.
  - Admin by group: `SWA_ADMIN_GROUP_ID` config matches a group claim.
  - Admin by app role: `SWA_ADMIN_APP_ROLE` config (default: `SamlCertRotation.Admin`).
  - Reader by group/app role: similarly configurable.
  - Admin users automatically get reader role too.
- **API authorization**: All endpoints require admin or reader role. Write endpoints require admin. Authenticated-only users without admin/reader role are denied access (403 Forbidden).
- **Client-side role enforcement**: Dashboard disables write operations for non-admin users and redirects unauthorized users.

### 17. Triple-Path Authentication
- **Path 1 — Validated AAD Token**: Reads from auth headers, validates signature against OIDC signing keys, issuer, audience, and lifetime.
- **Path 2 — x-ms-client-principal header**: Base64-decoded SWA principal payload.
- **Path 3 — SWA-issued JWT**: Trusted for configured SWA hostnames. Decodes `prn` claim for embedded client principal.
- All paths extract UPN from `preferred_username`/`upn`/`email` claims for audit attribution.

### 18. Session Timeout with Idle Tracking
- **Configurable session timeout** (default: 15 minutes, 0 = disabled).
- Client-side idle tracking: Listens for mouse, keyboard, scroll, and touch events.
- On timeout, shows a **modal prompt** with a 2-minute countdown. "Stay Signed In" resets; countdown expiry signs out.

### 19. Export Capabilities
- **Export Applications** — Downloads currently filtered apps as JSON with filter metadata.
- **Export Cleanup List** — Downloads certificate cleanup list as JSON.

### 20. Security Hardening
- **XSS prevention**: `escapeHtml()`, `toSafeClassToken()`, `toDomIdToken()`, `toJsStringLiteral()` on all rendered user content.
- **Error message sanitization**: API responses filter stack traces, connection strings, passwords, and secrets.
- **OData injection guard**: All service principal IDs validated as GUIDs before building Table Storage queries.
- **GUID validation**: All API endpoints accepting application IDs validate format and return 400 if invalid.
- **Content Security Policy**: `default-src 'self'`, `frame-ancestors 'none'`, etc. via SWA config.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.

### 21. Infrastructure as Code (Bicep)
- Single `main.bicep` template deploys all resources:
  - User-Assigned Managed Identity
  - Key Vault (RBAC auth, soft delete, purge protection)
  - Storage Account (TLS 1.2, no public blob access)
  - Log Analytics Workspace (90-day retention)
  - Application Insights (workspace-based)
  - App Service Plan (Consumption/Y1)
  - Azure Function App (.NET 8 isolated, HTTPS-only, FTPS disabled)
  - Static Web App (Standard tier)
  - Logic App (HTTP trigger → Office 365 Send Email)
  - Office 365 API Connection

### 22. Application Insights & Telemetry
- Function App telemetry with sampling (excludes Request type).
- Log levels: Default=Information, Host.Results=Error, Function=Information, Host.Aggregator=Warning.

### 23. Additional Dashboard Features
- **User identity display** — Logged-in user's UPN shown in header.
- **Sign out** — Clears SWA auth cookie and redirects to login.
- **Unauthorized access page** — Shown when a user lacks admin/reader role.
- **CRON schedule display** — Human-readable formatting in Settings tab with tooltip for how to change.
- **Entra deep-links** — Direct links to Enterprise Application SAML sign-on blade in notification emails.
- **Confirmation modals** — Required before rotation triggers and destructive actions.
- **Status banners** — Success/error messages with auto-dismiss.

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
| 1st/2nd/3rd Sponsor Reminder Days | 30/7/1 | Milestone days for notify-only app reminders |
| Notify Sponsors on Expiration | Enabled | Send one-time email to sponsor when cert expires |
| Report-Only Mode | Enabled | Log what would happen without making changes |
| Retention Policy Days | 180 | Days to retain audit log entries before purging |
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
- **Security headers**: CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, strict Referrer-Policy

## License

MIT
