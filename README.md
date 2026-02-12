# SAML Certificate Rotation Tool

Automated SAML certificate lifecycle management for Microsoft Entra ID Enterprise Applications.

## Features

- **Automatic Certificate Rotation**: Creates and activates new SAML signing certificates before expiration
- **Custom Security Attribute Control**: Tag applications with `AutoRotate=on/off` to control rotation
- **Policy-Based Management**: Configure global and app-specific rotation thresholds
- **Email Notifications**: Alerts for certificate creation, activation, and errors
- **Dashboard**: Visual overview of all SAML applications and their certificate status
- **Audit Logging**: Complete audit trail of all operations

## Architecture

```
Azure Functions (Timer)     →  Microsoft Graph API  →  Entra ID SAML Apps
       ↓                              ↓
Table Storage (Policies)        Email Notifications
       ↓
Static Web App (Dashboard)
```

## Quick Start

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed deployment instructions.

### Prerequisites

- Azure Subscription
- Microsoft Entra ID Global Administrator or Application Administrator
- Azure CLI, .NET 8 SDK, Node.js 18+

### Deploy

```powershell
# 1. Deploy infrastructure
az deployment group create -g rg-saml-cert-rotation -f infrastructure/main.bicep -p infrastructure/main.parameters.json

# 2. Grant Graph API permissions (see deployment guide)

# 3. Deploy Function App
dotnet publish src/SamlCertRotation/SamlCertRotation.csproj -c Release -o ./publish
az functionapp deployment source config-zip --name <func-name> --src ./function-app.zip

# 4. Deploy Dashboard
cd dashboard && npm install && npm run build
swa deploy ./dist --deployment-token <token>
```

## Configuration

### Custom Security Attribute

Create in Entra ID:
- **Attribute Set**: `SamlCertRotation`
- **Attribute**: `AutoRotate` (values: `on`, `off`)

### Policy Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Create Certificate | 60 days before expiry | When to generate new certificate |
| Activate Certificate | 30 days before expiry | When to activate new certificate |

## Project Structure

```
├── src/SamlCertRotation/
│   ├── Functions/           # Timer and HTTP triggers
│   ├── Services/            # Business logic
│   └── Models/              # Data models
├── dashboard/               # Static Web App UI
├── infrastructure/          # Bicep templates
└── DEPLOYMENT_GUIDE.md      # Detailed deployment guide
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard/stats` | GET | Dashboard statistics |
| `/api/applications` | GET | List all SAML apps |
| `/api/policy` | GET/PUT | Global policy |
| `/api/audit` | GET | Audit log entries |
| `/api/admin/trigger-rotation` | POST | Manual trigger |

## License

MIT
