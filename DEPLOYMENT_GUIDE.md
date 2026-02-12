# SAML Certificate Rotation Tool - Deployment Guide

This guide walks you through deploying the SAML Certificate Rotation Tool in your Azure environment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Step 1: Prepare Your Environment](#step-1-prepare-your-environment)
4. [Step 2: Create Custom Security Attributes](#step-2-create-custom-security-attributes)
5. [Step 3: Deploy Azure Infrastructure](#step-3-deploy-azure-infrastructure)
6. [Step 4: Grant Microsoft Graph Permissions](#step-4-grant-microsoft-graph-permissions)
7. [Step 5: Deploy the Function App Code](#step-5-deploy-the-function-app-code)
8. [Step 6: Deploy the Dashboard](#step-6-deploy-the-dashboard)
9. [Step 7: Configure Email Notifications](#step-7-configure-email-notifications)
10. [Step 8: Tag Applications for Auto-Rotation](#step-8-tag-applications-for-auto-rotation)
11. [Step 9: Verify the Deployment](#step-9-verify-the-deployment)
12. [Troubleshooting](#troubleshooting)
13. [Security Considerations](#security-considerations)

---

## Prerequisites

Before you begin, ensure you have:

- [ ] **Azure Subscription** with Owner or Contributor role
- [ ] **Microsoft Entra ID** with one of:
  - Global Administrator role, OR
  - Application Administrator + Attribute Definition Administrator roles
- [ ] **Azure CLI** v2.50+ installed ([Install Azure CLI](https://docs.microsoft.com/cli/azure/install-azure-cli))
- [ ] **.NET 8 SDK** installed ([Download .NET](https://dotnet.microsoft.com/download))
- [ ] **Azure Functions Core Tools** v4.x ([Install](https://docs.microsoft.com/azure/azure-functions/functions-run-local))
- [ ] **Node.js** 18+ (for dashboard) ([Download](https://nodejs.org/))

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Azure Subscription                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │  Azure Functions │     │      Microsoft Entra ID          │  │
│  │  (Timer Trigger) │────▶│  - Enterprise Apps (SAML)        │  │
│  │                  │     │  - Custom Security Attributes    │  │
│  │  • Check certs   │     │  - Service Principals            │  │
│  │  • Create new    │     └──────────────────────────────────┘  │
│  │  • Activate cert │                                           │
│  └────────┬─────────┘                                           │
│           │                                                      │
│           │ Managed Identity                                     │
│           ▼                                                      │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │  Table Storage   │     │    Static Web App (Dashboard)    │  │
│  │  - Policies      │     │    - View stats                  │  │
│  │  - Audit Logs    │◀───▶│    - Configure policies          │  │
│  └──────────────────┘     └──────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Prepare Your Environment

### 1.1 Login to Azure

```powershell
# Login to Azure
az login

# Set your subscription
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"

# Verify you're in the correct subscription
az account show --query "{Name:name, SubscriptionId:id}" -o table
```

### 1.2 Create a Resource Group

```powershell
# Set variables
$resourceGroupName = "rg-saml-cert-rotation"
$location = "eastus"

# Create resource group
az group create --name $resourceGroupName --location $location
```

---

## Step 2: Create Custom Security Attributes

Custom Security Attributes allow you to tag which SAML apps should be auto-rotated.

### 2.1 Navigate to Custom Security Attributes

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Protection** → **Custom security attributes**

### 2.2 Create Attribute Set

1. Click **+ Add attribute set**
2. Enter:
   - **Name**: `SamlCertRotation`
   - **Description**: `Attributes for SAML certificate rotation automation`
   - **Maximum number of attributes**: 10
3. Click **Add**

### 2.3 Create Attribute Definition

1. Select the `SamlCertRotation` attribute set
2. Click **+ Add attribute**
3. Enter:
   - **Attribute name**: `AutoRotate`
   - **Description**: `Enable automatic SAML certificate rotation`
   - **Data type**: String
   - **Allow only predefined values**: Yes
   - **Predefined values**:
     - `on` - Enable automatic rotation
     - `off` - Disable automatic rotation
4. Click **Save**

### 2.4 Alternative: Create via PowerShell

```powershell
# Install Microsoft Graph PowerShell module if not already installed
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect with required scopes
Connect-MgGraph -Scopes "CustomSecAttributeDefinition.ReadWrite.All"

# Create attribute set
$attributeSet = @{
    id = "SamlCertRotation"
    description = "Attributes for SAML certificate rotation automation"
    maxAttributesPerSet = 10
}
New-MgDirectoryAttributeSet -BodyParameter $attributeSet

# Create attribute definition
$attributeDefinition = @{
    attributeSet = "SamlCertRotation"
    name = "AutoRotate"
    description = "Enable automatic SAML certificate rotation"
    type = "String"
    isSearchable = $true
    isCollection = $false
    usePreDefinedValuesOnly = $true
    status = "Available"
    allowedValues = @(
        @{ id = "on"; isActive = $true }
        @{ id = "off"; isActive = $true }
    )
}
New-MgDirectoryCustomSecurityAttributeDefinition -BodyParameter $attributeDefinition
```

---

## Step 3: Deploy Azure Infrastructure

### 3.1 Update Parameters File

Edit `infrastructure/main.parameters.json`:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "baseName": {
      "value": "samlcert"
    },
    "location": {
      "value": "eastus"
    },
    "notificationSenderEmail": {
      "value": "saml-noreply@yourdomain.com"
    },
    "adminNotificationEmails": {
      "value": "admin1@yourdomain.com;admin2@yourdomain.com"
    },
    "customSecurityAttributeSet": {
      "value": "SamlCertRotation"
    },
    "customSecurityAttributeName": {
      "value": "AutoRotate"
    },
    "defaultCreateCertDays": {
      "value": 60
    },
    "defaultActivateCertDays": {
      "value": 30
    }
  }
}
```

### 3.2 Deploy Infrastructure

```powershell
# Navigate to infrastructure folder
cd infrastructure

# Deploy with Bicep
az deployment group create `
    --resource-group $resourceGroupName `
    --template-file main.bicep `
    --parameters main.parameters.json `
    --query "properties.outputs" `
    -o json > deployment-outputs.json

# View outputs
Get-Content deployment-outputs.json | ConvertFrom-Json | Format-List
```

### 3.3 Save Output Values

After deployment, save these values for later steps:

```powershell
# Parse outputs
$outputs = Get-Content deployment-outputs.json | ConvertFrom-Json

$managedIdentityPrincipalId = $outputs.managedIdentityPrincipalId.value
$managedIdentityClientId = $outputs.managedIdentityClientId.value
$functionAppName = $outputs.functionAppName.value
$functionAppUrl = $outputs.functionAppUrl.value
$staticWebAppName = $outputs.staticWebAppName.value
$storageAccountName = $outputs.storageAccountName.value

Write-Host "Managed Identity Principal ID: $managedIdentityPrincipalId"
Write-Host "Function App: $functionAppName"
Write-Host "Function App URL: $functionAppUrl"
Write-Host "Static Web App: $staticWebAppName"
```

---

## Step 4: Grant Microsoft Graph Permissions

The managed identity needs Microsoft Graph API permissions to manage SAML certificates.

### 4.1 Grant Permissions via PowerShell

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All"

# Get the managed identity service principal
$managedIdentitySP = Get-MgServicePrincipal -Filter "id eq '$managedIdentityPrincipalId'"

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" | Select-Object -First 1

# Define required permissions
$requiredPermissions = @(
    "Application.ReadWrite.All",           # Read/write all applications
    "CustomSecAttributeAssignment.Read.All", # Read custom security attributes
    "Mail.Send"                            # Send email notifications
)

# Grant each permission
foreach ($permissionName in $requiredPermissions) {
    $appRole = $graphSP.AppRoles | Where-Object { $_.Value -eq $permissionName }
    
    if ($appRole) {
        $params = @{
            principalId = $managedIdentitySP.Id
            resourceId = $graphSP.Id
            appRoleId = $appRole.Id
        }
        
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentitySP.Id -BodyParameter $params
            Write-Host "Granted: $permissionName" -ForegroundColor Green
        }
        catch {
            Write-Host "Permission may already exist: $permissionName" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Permission not found: $permissionName" -ForegroundColor Red
    }
}
```

### 4.2 Verify Permissions

```powershell
# View assigned permissions
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentitySP.Id | 
    Select-Object AppRoleId, ResourceDisplayName | 
    Format-Table
```

### 4.3 Alternative: Grant via Azure Portal

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **Enterprise applications**
3. Search for your managed identity name (e.g., `samlcert-identity`)
4. Go to **Permissions** → **Grant admin consent**
5. For each permission, use **Add a permission** → **Microsoft Graph** → **Application permissions**:
   - `Application.ReadWrite.All`
   - `CustomSecAttributeAssignment.Read.All`
   - `Mail.Send`
6. Click **Grant admin consent for [tenant]**

---

## Step 5: Deploy the Function App Code

### 5.1 Build the Project

```powershell
# Navigate to project root
cd ..

# Restore packages and build
dotnet restore src/SamlCertRotation/SamlCertRotation.csproj
dotnet build src/SamlCertRotation/SamlCertRotation.csproj --configuration Release

# Publish
dotnet publish src/SamlCertRotation/SamlCertRotation.csproj `
    --configuration Release `
    --output ./publish
```

### 5.2 Deploy to Azure

```powershell
# IMPORTANT: Copy functions.metadata into .azurefunctions folder
Copy-Item "publish/functions.metadata" "publish/.azurefunctions/" -ErrorAction SilentlyContinue

# Create zip using .NET (Compress-Archive doesn't properly include dot-folders)
Remove-Item function-app.zip -Force -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    "$PWD/publish",
    "$PWD/function-app.zip"
)

# Deploy to Function App
az functionapp deployment source config-zip `
    --resource-group $resourceGroupName `
    --name $functionAppName `
    --src ./function-app.zip

# Verify deployment
az functionapp function list `
    --resource-group $resourceGroupName `
    --name $functionAppName `
    --output table
```

### 5.3 Configure Function App Settings (if not set by Bicep)

```powershell
az functionapp config appsettings set `
    --resource-group $resourceGroupName `
    --name $functionAppName `
    --settings `
        "AZURE_CLIENT_ID=$managedIdentityClientId" `
        "NotificationSenderEmail=saml-noreply@yourdomain.com" `
        "AdminNotificationEmails=admin@yourdomain.com"
```

---

## Step 6: Deploy the Dashboard

### 6.1 Get Static Web App Deployment Token

```powershell
# Get deployment token
$deploymentToken = az staticwebapp secrets list `
    --resource-group $resourceGroupName `
    --name $staticWebAppName `
    --query "properties.apiKey" -o tsv
```

### 6.2 Update Dashboard Configuration

Edit `dashboard/staticwebapp.config.json` and replace `<YOUR_TENANT_ID>` with your actual tenant ID.

Also update the API endpoint in `dashboard/index.html`:
```javascript
const API_BASE_URL = 'https://your-function-app.azurewebsites.net';
```

### 6.3 Deploy Dashboard

The simplest method is to deploy via the Azure Portal:

#### Option A: Azure Portal (Recommended)

1. Open [Azure Portal](https://portal.azure.com)
2. Navigate to your Static Web App resource
3. Go to **Deployment Center**
4. Connect to your GitHub repository, or use manual deployment

#### Option B: SWA CLI via npx

If you prefer command-line deployment:

```powershell
cd dashboard

# Prepare dist folder
New-Item -ItemType Directory -Path dist -Force
Copy-Item index.html dist/
Copy-Item staticwebapp.config.json dist/

# Deploy using npx (will show dependency warnings - these are safe to ignore)
npx -y @azure/static-web-apps-cli deploy ./dist `
    --deployment-token $deploymentToken `
    --env production
```

> **Note**: You may see npm warnings about deprecated packages. These come from the
> SWA CLI's dependencies and are safe to ignore - they don't affect functionality.

### 6.4 Configure Static Web App Authentication

Authentication is already configured via `staticwebapp.config.json`. The dashboard requires
users to authenticate with Azure AD before accessing any content.

To customize authentication:

1. Go to Azure Portal → Your Static Web App → **Authentication**
2. Add or modify the **Microsoft** identity provider
3. Configure callback URLs as needed

---

## Step 7: Configure Email Notifications

### 7.1 Option A: Use a Shared Mailbox

1. Create a shared mailbox in Microsoft 365 Admin Center (e.g., `saml-rotation@yourdomain.com`)
2. Grant the managed identity **Send As** permission:

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Grant Send As permission to the managed identity
Add-RecipientPermission "saml-rotation@yourdomain.com" `
    -Trustee $managedIdentityClientId `
    -AccessRights SendAs
```

### 7.2 Option B: Use Application Mail.Send

The `Mail.Send` application permission allows sending mail as any user. For production:

1. Consider using a dedicated service account
2. Implement mail filtering policies
3. Monitor sent emails

### 7.3 Update Function App Setting

```powershell
az functionapp config appsettings set `
    --resource-group $resourceGroupName `
    --name $functionAppName `
    --settings "NotificationSenderEmail=saml-rotation@yourdomain.com"
```

---

## Step 8: Tag Applications for Auto-Rotation

### 8.1 Tag via Entra Admin Center

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **Enterprise applications**
3. Select a SAML application
4. Go to **Properties** → **Custom security attributes**
5. Click **Add assignment**
6. Select:
   - Attribute set: `SamlCertRotation`
   - Attribute name: `AutoRotate`
   - Assigned values: `on`
7. Click **Save**

### 8.2 Tag via PowerShell

```powershell
# Get the service principal
$appDisplayName = "Your SAML App Name"
$sp = Get-MgServicePrincipal -Filter "displayName eq '$appDisplayName'"

# Set custom security attribute
$customAttributes = @{
    customSecurityAttributes = @{
        SamlCertRotation = @{
            "@odata.type" = "#Microsoft.DirectoryServices.CustomSecurityAttributeValue"
            AutoRotate = "on"
        }
    }
}

Update-MgServicePrincipal -ServicePrincipalId $sp.Id -BodyParameter $customAttributes
```

### 8.3 Bulk Tag Multiple Applications

```powershell
# Tag multiple apps
$appsToTag = @(
    "Salesforce",
    "ServiceNow",
    "Workday"
)

foreach ($appName in $appsToTag) {
    $sp = Get-MgServicePrincipal -Filter "displayName eq '$appName' and preferredSingleSignOnMode eq 'saml'"
    
    if ($sp) {
        $customAttributes = @{
            customSecurityAttributes = @{
                SamlCertRotation = @{
                    "@odata.type" = "#Microsoft.DirectoryServices.CustomSecurityAttributeValue"
                    AutoRotate = "on"
                }
            }
        }
        Update-MgServicePrincipal -ServicePrincipalId $sp.Id -BodyParameter $customAttributes
        Write-Host "Tagged: $appName" -ForegroundColor Green
    }
    else {
        Write-Host "Not found: $appName" -ForegroundColor Yellow
    }
}
```

---

## Step 9: Verify the Deployment

### 9.1 Test the Function App

```powershell
# Get Function App key
$functionKey = az functionapp keys list `
    --resource-group $resourceGroupName `
    --name $functionAppName `
    --query "functionKeys.default" -o tsv

# Test dashboard stats endpoint
$response = Invoke-RestMethod `
    -Uri "$functionAppUrl/api/dashboard/stats?code=$functionKey" `
    -Method GET
$response | ConvertTo-Json -Depth 5
```

### 9.2 Manually Trigger Rotation

```powershell
# Trigger manual rotation
Invoke-RestMethod `
    -Uri "$functionAppUrl/api/admin/trigger-rotation?code=$functionKey" `
    -Method POST | ConvertTo-Json -Depth 5
```

### 9.3 Check Function Logs

```powershell
# View function logs (last 30 minutes)
az functionapp logs tail `
    --resource-group $resourceGroupName `
    --name $functionAppName
```

### 9.4 Access the Dashboard

Navigate to your Static Web App URL:
```
https://<staticwebappname>.azurestaticapps.net
```

---

## Troubleshooting

### Issue: npm permission errors (EACCES) when deploying dashboard

**Cause**: Insufficient permissions for global npm installs

**Solution**: Use `npx` with the `-y` flag instead of global installs:
```powershell
npx -y @azure/static-web-apps-cli deploy ./dist --deployment-token $deploymentToken --env production
```
Or deploy via Azure Portal (see Step 6.3 Option A).

### Issue: SWA CLI "folder not found" error

**Cause**: The dist folder wasn't created before deployment

**Solution**:
```powershell
New-Item -ItemType Directory -Path dist -Force
Copy-Item index.html dist/
Copy-Item staticwebapp.config.json dist/
```

### Issue: npm warnings about deprecated packages

**Cause**: These come from the SWA CLI's own dependencies

**Solution**: Safe to ignore - they don't affect functionality.

### Issue: "Insufficient privileges" errors

**Cause**: Managed identity missing Graph API permissions

**Solution**:
1. Verify permissions in Entra admin center
2. Re-run the permission grant script
3. Wait 5-10 minutes for propagation

### Issue: Certificates not being created

**Cause**: Custom security attribute not set correctly

**Solution**:
```powershell
# Verify CSA on an app
$sp = Get-MgServicePrincipal -ServicePrincipalId "<app-object-id>" -Property "customSecurityAttributes"
$sp.CustomSecurityAttributes | ConvertTo-Json -Depth 5
```

### Issue: Emails not being sent

**Cause**: Mail.Send permission or sender configuration issue

**Solution**:
1. Verify `Mail.Send` permission granted
2. Check sender email exists and is valid
3. Review Function App logs for error details

### Issue: Function timer not triggering

**Cause**: Function not deployed or scaled to zero

**Solution**:
1. Verify function is listed: `az functionapp function list --name $functionAppName --resource-group $resourceGroupName`
2. Check Application Insights for invocations
3. Manually trigger to test

### Issue: Dashboard not loading data

**Cause**: CORS or authentication configuration

**Solution**:
1. Verify Function App CORS settings include Static Web App URL
2. Check browser console for errors
3. Verify API key in dashboard configuration

---

## Security Considerations

### Principle of Least Privilege

The solution requires significant Entra ID permissions. Consider:

1. **Limit scope**: If possible, use `Application.ReadWrite.OwnedBy` instead of `Application.ReadWrite.All`
2. **Conditional Access**: Require compliant device for admin access
3. **Monitoring**: Enable Azure AD audit logs for all Graph API operations

### Network Security

1. Enable **Private Endpoints** for Storage Account (Premium tier required)
2. Configure **Function App access restrictions** to limit inbound traffic
3. Use **API Management** as a gateway for additional security

### Credential Management

1. **Never store secrets in code** - All secrets use MSI or Key Vault
2. **Rotate Function keys** periodically
3. **Review audit logs** regularly

### Compliance

1. **Audit trail**: All operations logged to Table Storage
2. **Email notifications**: Document recipients and retention
3. **Change management**: Document all CSA assignments

---

## Maintenance

### Regular Tasks

| Task | Frequency | Description |
|------|-----------|-------------|
| Review audit logs | Weekly | Check for failures or anomalies |
| Verify upcoming expirations | Monthly | Dashboard review |
| Test notifications | Quarterly | Send test email |
| Review permissions | Quarterly | Remove unused assignments |
| Update dependencies | As needed | Security patches |

### Updating the Solution

```powershell
# Pull latest changes
git pull

# Rebuild and deploy
dotnet publish src/SamlCertRotation/SamlCertRotation.csproj -c Release -o ./publish
Copy-Item "publish/functions.metadata" "publish/.azurefunctions/" -ErrorAction SilentlyContinue
Remove-Item function-app.zip -Force -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory("$PWD/publish", "$PWD/function-app.zip")
az functionapp deployment source config-zip --resource-group $resourceGroupName --name $functionAppName --src ./function-app.zip
```

---

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review Function App logs in Application Insights
3. Check Microsoft Graph API documentation for permission changes

---

## Appendix: Default Policy Settings

| Setting | Default Value | Description |
|---------|---------------|-------------|
| `CreateCertDaysBeforeExpiry` | 60 | Days before expiry to generate new cert |
| `ActivateCertDaysBeforeExpiry` | 30 | Days before expiry to make new cert active |
| Timer Schedule | 6:00 AM UTC daily | When the checker runs |

These can be modified via the dashboard or by updating Table Storage directly.
