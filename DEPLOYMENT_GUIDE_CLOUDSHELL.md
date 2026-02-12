# SAML Certificate Rotation Tool - Azure Cloud Shell Deployment Guide (PowerShell)

This guide walks you through deploying the SAML Certificate Rotation Tool using **Azure Cloud Shell** with **PowerShell**.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Upload Project to Cloud Shell](#step-1-upload-project-to-cloud-shell)
3. [Step 2: Prepare Your Environment](#step-2-prepare-your-environment)
4. [Step 3: Create Custom Security Attributes](#step-3-create-custom-security-attributes)
5. [Step 4: Deploy Azure Infrastructure](#step-4-deploy-azure-infrastructure)
6. [Step 5: Grant Microsoft Graph Permissions](#step-5-grant-microsoft-graph-permissions)
7. [Step 6: Deploy the Function App Code](#step-6-deploy-the-function-app-code)
8. [Step 7: Deploy the Dashboard](#step-7-deploy-the-dashboard)
9. [Step 8: Configure Dashboard Access Control](#step-8-configure-dashboard-access-control)
10. [Step 9: Configure Email Notifications](#step-9-configure-email-notifications)
11. [Step 10: Tag Applications for Auto-Rotation](#step-10-tag-applications-for-auto-rotation)
12. [Step 11: Verify the Deployment](#step-11-verify-the-deployment)
13. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- [ ] **Azure Subscription** with Owner or Contributor role
- [ ] **Microsoft Entra ID** with one of:
  - Global Administrator role, OR
  - Application Administrator + Attribute Definition Administrator roles
- [ ] Access to **Azure Cloud Shell** (https://shell.azure.com) - **Select PowerShell mode**

> **Note**: Azure Cloud Shell already has Azure CLI, .NET SDK, PowerShell, and Node.js pre-installed.

---

## Step 1: Upload Project to Cloud Shell

### Option A: Clone from Git Repository (Recommended)

```powershell
# Clone the repository
git clone https://github.com/JeffBley/SamlCertRotation.git
Set-Location SamlCertRotation
```

### Option B: Upload ZIP File

1. On your local machine, zip the entire project folder
2. In Cloud Shell, click the **Upload/Download files** button (up/down arrow icon)
3. Select **Upload** and choose your zip file
4. Extract in Cloud Shell:

```powershell
# Create project directory
New-Item -ItemType Directory -Path "$HOME/SamlCertRotation" -Force
Set-Location "$HOME/SamlCertRotation"

# Unzip (file will be in your home directory after upload)
Expand-Archive -Path "$HOME/SamlCertRotation.zip" -DestinationPath . -Force
```

### Option C: Upload Individual Files via Cloud Shell Editor

1. In Cloud Shell, click the **Editor** button (curly braces icon `{}`)
2. Create the folder structure manually
3. Copy/paste file contents from your local machine

### Verify Files Are Present

```powershell
# Navigate to project root and verify structure
Set-Location "$HOME/SamlCertRotation"
Get-ChildItem

# You should see:
# - infrastructure/
# - src/
# - dashboard/
# - DEPLOYMENT_GUIDE.md
```

---

## Step 2: Prepare Your Environment

### 2.1 Verify Azure CLI Login

Cloud Shell is automatically authenticated. Verify your subscription:

```powershell
# Check current subscription
az account show --query "{Name:name, SubscriptionId:id}" -o table

# If you need to change subscription:
az account list --output table
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
```

### 2.2 Set Environment Variables

```powershell
# Set variables (modify as needed)
$RESOURCE_GROUP = "rg-saml-cert-rotation"
$LOCATION = "eastus"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION
```

---

## Step 3: Create Custom Security Attributes

Custom Security Attributes allow you to tag which SAML apps should be auto-rotated.

### Via Microsoft Entra Admin Center (Recommended)

1. Open a new browser tab and go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Protection** → **Custom security attributes**
3. Click **+ Add attribute set**:
   - **Name**: `SamlCertRotation`
   - **Description**: `Attributes for SAML certificate rotation automation`
   - **Maximum number of attributes**: 10
4. Click **Add**
5. Select the `SamlCertRotation` attribute set
6. Click **+ Add attribute**:
   - **Attribute name**: `AutoRotate`
   - **Description**: `Enable automatic SAML certificate rotation`
   - **Data type**: String
   - **Allow only predefined values**: Yes
   - **Predefined values**: `on`, `off`
7. Click **Save**

---

## Step 4: Deploy Azure Infrastructure

### 4.1 Update Parameters File

Edit the parameters file with your values:

```powershell
Set-Location "$HOME/SamlCertRotation/infrastructure"

# Open in Cloud Shell editor
code main.parameters.json
```

Update these values:
- `notificationSenderEmail`: Your notification sender email
- `adminNotificationEmails`: Admin emails (semicolon-separated)

Save the file (Ctrl+S) and close the editor.

### 4.2 Deploy Infrastructure with Bicep

```powershell
# Make sure you're in the infrastructure directory
Set-Location "$HOME/SamlCertRotation/infrastructure"

# Deploy the infrastructure
az deployment group create `
    --resource-group $RESOURCE_GROUP `
    --template-file main.bicep `
    --parameters main.parameters.json `
    --query "properties.outputs" `
    -o json | Out-File -FilePath deployment-outputs.json -Encoding utf8

# View the outputs
Get-Content deployment-outputs.json | ConvertFrom-Json | Format-List
```

### 4.3 Save Output Values as Variables

```powershell
# Parse outputs and set as variables
$outputs = Get-Content deployment-outputs.json | ConvertFrom-Json

$MANAGED_IDENTITY_PRINCIPAL_ID = $outputs.managedIdentityPrincipalId.value
$MANAGED_IDENTITY_CLIENT_ID = $outputs.managedIdentityClientId.value
$MANAGED_IDENTITY_NAME = $outputs.managedIdentityName.value
$FUNCTION_APP_NAME = $outputs.functionAppName.value
$FUNCTION_APP_URL = $outputs.functionAppUrl.value
$STATIC_WEB_APP_NAME = $outputs.staticWebAppName.value
$STORAGE_ACCOUNT_NAME = $outputs.storageAccountName.value

# Verify variables are set
Write-Host "Managed Identity Principal ID: $MANAGED_IDENTITY_PRINCIPAL_ID"
Write-Host "Managed Identity Name: $MANAGED_IDENTITY_NAME"
Write-Host "Function App: $FUNCTION_APP_NAME"
Write-Host "Function App URL: $FUNCTION_APP_URL"
Write-Host "Static Web App: $STATIC_WEB_APP_NAME"
```

> **Important**: Save these values! If your Cloud Shell session times out, you'll need to re-run the variable assignment commands or retrieve values from the Azure Portal.

---

## Step 5: Grant Microsoft Graph Permissions

The managed identity needs Microsoft Graph API permissions.

### 5.1 Grant Permissions via Azure Portal (Easiest)

1. Go to [Azure Portal](https://portal.azure.com)
2. Search for **Enterprise applications**
3. Change the **Application type** filter to **Managed Identities**
4. Search for your managed identity name (the value from `$MANAGED_IDENTITY_NAME`)
5. Click on the managed identity
6. Go to **Permissions** in the left menu
7. Click **Grant admin consent for [your tenant]** if available

If permissions aren't listed, use PowerShell below:

### 5.2 Grant Permissions via PowerShell

```powershell
# Install Microsoft Graph module if needed
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Connect to Microsoft Graph (will open browser for auth)
Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"

# Get the managed identity service principal
$managedIdentitySP = Get-MgServicePrincipal -ServicePrincipalId $MANAGED_IDENTITY_PRINCIPAL_ID

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" | Select-Object -First 1

# Define required permissions
$requiredPermissions = @(
    "Application.ReadWrite.All",
    "CustomSecAttributeAssignment.Read.All",
    "Mail.Send"
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
            Write-Host "Permission may already exist or error: $permissionName" -ForegroundColor Yellow
        }
    }
}
```

### 5.3 Verify Permissions in Portal

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **Enterprise applications**
3. Filter by **Managed Identities** and find your identity
4. Go to **Permissions** and verify these are listed:
   - `Application.ReadWrite.All`
   - `CustomSecAttributeAssignment.Read.All`
   - `Mail.Send`

---

## Step 6: Deploy the Function App Code

### 6.1 Build the Project

```powershell
# Navigate to project root
Set-Location "$HOME/SamlCertRotation"

# Restore and build
dotnet restore src/SamlCertRotation/SamlCertRotation.csproj
dotnet build src/SamlCertRotation/SamlCertRotation.csproj --configuration Release

# Publish
dotnet publish src/SamlCertRotation/SamlCertRotation.csproj `
    --configuration Release `
    --output ./publish
```

### 6.2 Create Deployment Package

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
```

### 6.3 Deploy to Azure Function App

```powershell
# Deploy the zip package
az functionapp deployment source config-zip `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --src function-app.zip

# Verify deployment - list functions
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --output table
```

You should see `CertificateChecker` and several `Dashboard*` functions listed.

---

## Step 7: Deploy the Dashboard

### 7.1 Get Static Web App Deployment Token

```powershell
# Get deployment token
$SWA_TOKEN = az staticwebapp secrets list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.apiKey" -o tsv

Write-Host "Deployment token retrieved"
```

### 7.2 Update Dashboard Configuration

```powershell
Set-Location "$HOME/SamlCertRotation/dashboard"

# Get your tenant ID
$TENANT_ID = az account show --query tenantId -o tsv

# Update the staticwebapp.config.json with your tenant ID
$configContent = Get-Content staticwebapp.config.json -Raw
$configContent = $configContent -replace '<YOUR_TENANT_ID>', $TENANT_ID
Set-Content -Path staticwebapp.config.json -Value $configContent

# Update the API endpoint in index.html
$htmlContent = Get-Content index.html -Raw
$htmlContent = $htmlContent -replace "const API_BASE_URL = ''", "const API_BASE_URL = '$FUNCTION_APP_URL'"
Set-Content -Path index.html -Value $htmlContent
```

### 7.3 Deploy Dashboard

The simplest method is to deploy via the Azure Portal:

#### Option A: Azure Portal (Recommended)

1. Open [Azure Portal](https://portal.azure.com)
2. Navigate to your Static Web App: `$STATIC_WEB_APP_NAME`
3. Go to **Overview** → Click the **URL** to open the app
4. Go to **Settings** → **Configuration** to verify settings
5. For manual upload, go to the **Deployment Center**

**Note**: For Static Web Apps with a simple HTML file, you can also use GitHub Actions:
- Push your dashboard folder to a GitHub repo
- Connect the Static Web App to the repo via Deployment Center

#### Option B: SWA CLI via npx

If you prefer command-line deployment:

```powershell
# Prepare dashboard files
New-Item -ItemType Directory -Path dist -Force
Copy-Item index.html dist/
Copy-Item unauthorized.html dist/
Copy-Item staticwebapp.config.json dist/

# Deploy using npx (will show dependency warnings - these are safe to ignore)
npx -y @azure/static-web-apps-cli deploy ./dist `
    --deployment-token $SWA_TOKEN `
    --env production
```

> **Note**: You may see npm warnings about deprecated packages. These come from the
> SWA CLI's dependencies and are safe to ignore - they don't affect functionality.

### 7.4 Get Dashboard URL

```powershell
# Get the Static Web App URL
$dashboardUrl = az staticwebapp show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "defaultHostname" -o tsv

Write-Host "Dashboard URL: https://$dashboardUrl"
```

---

## Step 8: Configure Dashboard Access Control

The dashboard uses Azure AD authentication with Enterprise Application assignment to control access. Only users or groups assigned to the Enterprise Application can access the dashboard.

### 8.1 Create an App Registration

```powershell
# Get Static Web App hostname
$SWA_HOSTNAME = az staticwebapp show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "defaultHostname" -o tsv

# Create app registration for SWA authentication
$APP_NAME = "SAML Certificate Rotation Dashboard"

$APP_JSON = az ad app create `
    --display-name $APP_NAME `
    --sign-in-audience AzureADMyOrg `
    --web-redirect-uris "https://$SWA_HOSTNAME/.auth/login/aad/callback" `
    --enable-id-token-issuance true `
    --query "{appId:appId, id:id}" -o json

$APP = $APP_JSON | ConvertFrom-Json
$CLIENT_ID = $APP.appId
$APP_OBJECT_ID = $APP.id

Write-Host "Client ID: $CLIENT_ID"
Write-Host "App Object ID: $APP_OBJECT_ID"
```

### 8.2 Create Client Secret

```powershell
# Create client secret (valid for 2 years)
$CLIENT_SECRET = az ad app credential reset `
    --id $CLIENT_ID `
    --display-name "SWA Auth Secret" `
    --years 2 `
    --query "password" -o tsv

Write-Host "Client Secret: $CLIENT_SECRET"
Write-Host "IMPORTANT: Save this secret securely - it cannot be retrieved later!"
```

### 8.3 Create Service Principal (Enterprise App)

```powershell
# Create service principal for the app
az ad sp create --id $CLIENT_ID

# Get the Service Principal ID
$SP_ID = az ad sp list --filter "appId eq '$CLIENT_ID'" --query "[0].id" -o tsv
Write-Host "Service Principal ID: $SP_ID"
```

### 8.4 Configure User/Group Assignment

This step restricts dashboard access to specific users or groups.

```powershell
# Enable "Assignment required" on the Enterprise Application
az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" `
    --body '{"appRoleAssignmentRequired": true}'

Write-Host "Assignment required enabled"
```

Now assign users or groups to the application. Choose one of the following options:

**Option A: Assign a Security Group** (Recommended)

```powershell
# Get the security group ID (create one first if needed)
$GROUP_ID = az ad group show --group "Saml Rotation Dashboard Access" --query id -o tsv

# Assign the group to the Enterprise Application
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" `
    --body "{\"principalId\":\"$GROUP_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}"

Write-Host "Group assigned to Enterprise Application"
```

**Option B: Assign Individual User**

```powershell
# Get your user ID
$USER_ID = az ad signed-in-user show --query id -o tsv

# Assign yourself to the Enterprise Application
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" `
    --body "{\"principalId\":\"$USER_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}"

Write-Host "User assigned to Enterprise Application"
```

### 8.5 Configure Static Web App Settings

```powershell
# Get your tenant ID
$TENANT_ID = az account show --query "tenantId" -o tsv

# Configure SWA with the app registration credentials
az staticwebapp appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --setting-names "AAD_CLIENT_ID=$CLIENT_ID" "AAD_CLIENT_SECRET=$CLIENT_SECRET"

Write-Host "SWA app settings configured"
```

### 8.6 Disable Easy Auth on Function App

The Function App must NOT have Easy Auth enabled since API authentication is handled through the SWA backend link.

```powershell
# Disable Easy Auth on the Function App
az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-03-01" `
    --body '{"properties":{"platform":{"enabled":false},"globalValidation":{"unauthenticatedClientAction":"AllowAnonymous"}}}'

Write-Host "Easy Auth disabled on Function App"
```

### 8.7 Link Function App to Static Web App

```powershell
# Get the Function App resource ID
$FUNCTION_APP_ID = az functionapp show `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "id" -o tsv

# Get the Static Web App location
$SWA_LOCATION = az staticwebapp show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "location" -o tsv

# Link the Function App as the API backend
az staticwebapp backends link `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --backend-resource-id $FUNCTION_APP_ID `
    --backend-region $SWA_LOCATION

Write-Host "Function App linked as SWA backend"
```

### 8.8 Save Access Control Configuration

```powershell
# Save configuration for reference
$accessControlConfig = @{
    clientId = $CLIENT_ID
    servicePrincipalId = $SP_ID
    tenantId = $TENANT_ID
    swaHostname = $SWA_HOSTNAME
} | ConvertTo-Json

Set-Content -Path "$HOME/SamlCertRotation/infrastructure/access-control-config.json" -Value $accessControlConfig

Write-Host "Access control configuration saved to access-control-config.json"
```

### Summary of Access Control Settings

| Setting | Location | Value |
|---------|----------|-------|
| `AAD_CLIENT_ID` | SWA App Settings | App Registration Client ID |
| `AAD_CLIENT_SECRET` | SWA App Settings | App Registration Secret |
| `appRoleAssignmentRequired` | Enterprise Application | `true` |
| Tenant ID | staticwebapp.config.json | Your Azure AD Tenant ID |
| Easy Auth | Function App | Disabled |

> **Note**: Only users or groups assigned to the Enterprise Application can access the dashboard. Users not assigned will see "Access Denied" from Azure AD before reaching the application.

---

## Step 9: Configure Email Notifications

Email notifications are sent via a Logic App with Office 365 Outlook connector. This approach requires no Mail.Send Graph permission on the managed identity.

### 9.1 Get Logic App Name

```powershell
# Get the Logic App name from deployment outputs
$LOGIC_APP_NAME = $outputs.logicAppName.value
Write-Host "Logic App: $LOGIC_APP_NAME"
```

### 9.2 Configure Logic App with Office 365 Connector

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your resource group: `$RESOURCE_GROUP`
3. Find and open the Logic App (named like `samlcert-email-*`)
4. Click **Logic app designer**

### 9.3 Add Office 365 Send Email Action

1. In the designer, you'll see the **When a HTTP request is received** trigger
2. Click **+ New step**
3. Search for **Office 365 Outlook**
4. Select **Send an email (V2)**
5. Sign in with a user account that will send the emails (e.g., a shared mailbox delegate or service account)
6. Configure the action:
   - **To**: Click in the field → **Add dynamic content** → Select `to`
   - **Subject**: Click in the field → **Add dynamic content** → Select `subject`
   - **Body**: Click in the field → **Add dynamic content** → Select `body`
7. Delete the existing **Response** action (we'll add it after the email)
8. Click **+ New step** → Search for **Response**
9. Configure the Response:
   - **Status Code**: `200`
   - **Body**: `{"status": "sent"}`
10. Click **Save**

### 9.4 Get Logic App Callback URL

```powershell
# Get the Logic App HTTP trigger URL
$LOGIC_APP_URL = az rest --method post `
    --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Logic/workflows/$LOGIC_APP_NAME/triggers/manual/listCallbackUrl?api-version=2016-10-01" `
    --query "value" -o tsv

Write-Host "Logic App URL retrieved (contains SAS token - keep secure)"
```

### 9.5 Configure Function App with Logic App URL

```powershell
# Store the Logic App URL in Function App settings
az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "LogicAppEmailUrl=$LOGIC_APP_URL"

Write-Host "Function App configured to use Logic App for email notifications"
```

### 9.6 Test Email Notifications (Optional)

```powershell
# Test sending an email
$testPayload = @{
    to = "your-email@yourdomain.com"
    subject = "Test - SAML Certificate Rotation"
    body = "<html><body><h1>Test Email</h1><p>If you received this, email notifications are working!</p></body></html>"
} | ConvertTo-Json

Invoke-RestMethod -Uri $LOGIC_APP_URL -Method Post -Body $testPayload -ContentType "application/json"
```

---

## Step 10: Tag Applications for Auto-Rotation

### Via Entra Admin Center

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

### Via PowerShell

```powershell
# Connect to Graph (if not already connected)
Connect-MgGraph -Scopes "Application.ReadWrite.All", "CustomSecAttributeAssignment.ReadWrite.All"

# Set attribute on a specific app (replace with your app display name)
$appDisplayName = "Your SAML App Name"
$sp = Get-MgServicePrincipal -Filter "displayName eq '$appDisplayName'"

$customAttributes = @{
    customSecurityAttributes = @{
        SamlCertRotation = @{
            "@odata.type" = "#Microsoft.DirectoryServices.CustomSecurityAttributeValue"
            AutoRotate = "on"
        }
    }
}

Update-MgServicePrincipal -ServicePrincipalId $sp.Id -BodyParameter $customAttributes
Write-Host "Tagged: $appDisplayName"
```

---

## Step 11: Verify the Deployment

### 11.1 Test the Function App API

```powershell
# Get Function App key
$FUNCTION_KEY = az functionapp keys list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "functionKeys.default" -o tsv

# Test dashboard stats endpoint
$response = Invoke-RestMethod -Uri "$FUNCTION_APP_URL/api/dashboard/stats?code=$FUNCTION_KEY" -Method Get
$response | ConvertTo-Json -Depth 5
```

### 11.2 Manually Trigger Rotation

```powershell
# Trigger manual rotation
$response = Invoke-RestMethod -Uri "$FUNCTION_APP_URL/api/admin/trigger-rotation?code=$FUNCTION_KEY" -Method Post
$response | ConvertTo-Json -Depth 5
```

### 11.3 View Function Logs

```powershell
# Stream logs (Ctrl+C to stop)
az functionapp log tail `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME
```

### 11.4 Access the Dashboard

Open your browser and navigate to:
```
https://<your-static-web-app-name>.azurestaticapps.net
```

---

## Troubleshooting

### Git merge conflicts when pulling updates

If you've modified files locally and need to pull updates:

```powershell
# Discard local changes and pull latest
git checkout -- .
git pull

# Or if you want to keep your changes, stash them first
git stash
git pull
git stash pop
```

### npm permission errors (EACCES)

If you see "permission denied" when running npm commands:

```powershell
# Don't use global installs in Cloud Shell. Instead use npx with -y flag:
npx -y @azure/static-web-apps-cli deploy ./dist --deployment-token $SWA_TOKEN --env production

# Or deploy via Azure Portal instead (see Step 7.3 Option A)
```

### SWA CLI "folder not found" error

Make sure to create the dist folder before deploying:

```powershell
Set-Location "$HOME/SamlCertRotation/dashboard"
New-Item -ItemType Directory -Path dist -Force
Copy-Item index.html dist/
Copy-Item staticwebapp.config.json dist/
```

### npm warnings about deprecated packages

Warnings like "inflight@1.0.6 deprecated" come from the SWA CLI's dependencies.
These are safe to ignore - they don't affect functionality.

### "Permission denied" or "Insufficient privileges"

- Verify Graph API permissions were granted to the managed identity
- Check that admin consent was provided
- Wait 5-10 minutes for permissions to propagate

### Variables lost after session timeout

Cloud Shell sessions timeout after ~20 minutes of inactivity. Re-run:

```powershell
Set-Location "$HOME/SamlCertRotation/infrastructure"
$RESOURCE_GROUP = "rg-saml-cert-rotation"
$outputs = Get-Content deployment-outputs.json | ConvertFrom-Json
$FUNCTION_APP_NAME = $outputs.functionAppName.value
$FUNCTION_APP_URL = $outputs.functionAppUrl.value
$STATIC_WEB_APP_NAME = $outputs.staticWebAppName.value
$MANAGED_IDENTITY_PRINCIPAL_ID = $outputs.managedIdentityPrincipalId.value
```

### Function not triggering

```powershell
# Check if functions are deployed
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --output table

# Check application settings
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --output table
```

### Dashboard shows no data

1. Verify CORS is configured on the Function App to allow your Static Web App URL
2. Check browser console (F12) for errors
3. Verify the API_BASE_URL in index.html is correct

---

## Quick Reference: Key Commands

```powershell
# Re-set variables after session timeout
Set-Location "$HOME/SamlCertRotation/infrastructure"
$RESOURCE_GROUP = "rg-saml-cert-rotation"
$outputs = Get-Content deployment-outputs.json | ConvertFrom-Json
$FUNCTION_APP_NAME = $outputs.functionAppName.value
$FUNCTION_APP_URL = $outputs.functionAppUrl.value
$STATIC_WEB_APP_NAME = $outputs.staticWebAppName.value
$MANAGED_IDENTITY_PRINCIPAL_ID = $outputs.managedIdentityPrincipalId.value

# Test API
$FUNCTION_KEY = az functionapp keys list --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME --query "functionKeys.default" -o tsv
Invoke-RestMethod -Uri "$FUNCTION_APP_URL/api/dashboard/stats?code=$FUNCTION_KEY" | ConvertTo-Json

# View logs
az functionapp log tail --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
```

---

## Next Steps

1. Monitor the dashboard for certificate expiration status
2. Review audit logs periodically
3. Adjust rotation policies as needed via the dashboard
4. Tag additional SAML applications with `AutoRotate=on` as desired
