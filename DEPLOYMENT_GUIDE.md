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
8. [Step 7: Configure Dashboard Access Control](#step-7-configure-dashboard-access-control)
9. [Step 8: Deploy the Dashboard](#step-8-deploy-the-dashboard)
10. [Step 9: Configure Email Notifications](#step-9-configure-email-notifications)
11. [Step 10: Tag Applications for Auto-Rotation](#step-10-tag-applications-for-auto-rotation)
12. [Step 11: Verify the Deployment](#step-11-verify-the-deployment)
13. [Troubleshooting](#troubleshooting)
14. [Cleanup / Teardown](#cleanup--teardown)

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
$KEY_VAULT_NAME = $outputs.keyVaultName.value
$KEY_VAULT_URI = $outputs.keyVaultUri.value
$LOG_ANALYTICS_NAME = $outputs.logAnalyticsWorkspaceName.value
$LOGIC_APP_NAME = $outputs.logicAppName.value

# Verify variables are set
Write-Host "Managed Identity Principal ID: $MANAGED_IDENTITY_PRINCIPAL_ID"
Write-Host "Managed Identity Client ID: $MANAGED_IDENTITY_CLIENT_ID"
Write-Host "Managed Identity Name: $MANAGED_IDENTITY_NAME"
Write-Host "Function App: $FUNCTION_APP_NAME"
Write-Host "Function App URL: $FUNCTION_APP_URL"
Write-Host "Static Web App: $STATIC_WEB_APP_NAME"
Write-Host "Storage Account: $STORAGE_ACCOUNT_NAME"
Write-Host "Key Vault: $KEY_VAULT_NAME"
Write-Host "Key Vault URI: $KEY_VAULT_URI"
Write-Host "Log Analytics Workspace: $LOG_ANALYTICS_NAME"
Write-Host "Logic App: $LOGIC_APP_NAME"
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
    "CustomSecAttributeAssignment.Read.All"
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

# Verify deployment - list function names
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[].{Name:name}" `
    --output table
```

You should see functions listed including `CertificateChecker`, `GetDashboardStats`, `GetRoles`, `RotateSwaClientSecret`, etc.

---

## Step 7: Configure Dashboard Access Control

The dashboard uses Azure AD authentication with Enterprise Application assignment to control access. Only users or groups assigned to the Enterprise Application can access the dashboard.

### 7.1 Create an App Registration

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

### 7.2 Create Client Secret

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

### 7.3 Create Service Principal (Enterprise App)

```powershell
# Create service principal for the app
az ad sp create --id $CLIENT_ID

# Get the Service Principal ID
$SP_ID = az ad sp list --filter "appId eq '$CLIENT_ID'" --query "[0].id" -o tsv
Write-Host "Service Principal ID: $SP_ID"

# Add the integrated app tag (shows as "Integrated Application" in Azure Portal)
az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" `
    --body '{"tags": ["WindowsAzureActiveDirectoryIntegratedApp"]}'

Write-Host "Service Principal created with integrated app tag"
```

### 7.4 Configure User/Group Assignment

This step restricts dashboard access to specific users or groups. **You must assign at least one user or group** for authentication to work.

```powershell
# Enable "Assignment required" on the Enterprise Application
az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" `
    --body '{"appRoleAssignmentRequired": true}'

Write-Host "Assignment required enabled"
```

Now assign users or groups to the application. **Choose at least one option below:**

**Option A: Assign a Security Group** (Recommended for production)

```powershell
# First, create a security group if one doesn't exist
# az ad group create --display-name "SAML Dashboard Users" --mail-nickname "saml-dashboard-users"

# Get the security group ID
$GROUP_ID = az ad group show --group "SAML Dashboard Users" --query id -o tsv

# Assign the group to the Enterprise Application
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" `
    --body "{\"principalId\":\"$GROUP_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}"

Write-Host "Group assigned to Enterprise Application"
```

**Option B: Assign Individual User** (Quick setup for testing)

```powershell
# Get your user ID
$USER_ID = az ad signed-in-user show --query id -o tsv

# Assign yourself to the Enterprise Application
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" `
    --body "{\"principalId\":\"$USER_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}"

Write-Host "User assigned to Enterprise Application"
```

> **Important**: Users who are not assigned to the Enterprise Application will receive an "Access Denied" error when trying to access the dashboard. You can also manage assignments in the Azure Portal under **Enterprise Applications** → **Users and groups**.

### 7.5 Store Client Secret in Key Vault

The client secret is stored in Azure Key Vault for security. The managed identity has permissions to rotate
it automatically when it's within 30 days of expiration.

```powershell
# Get Key Vault name from deployment outputs
$KEY_VAULT_NAME = $outputs.keyVaultName.value

# Get your user object ID
$USER_OBJECT_ID = az ad signed-in-user show --query id -o tsv

# Grant yourself Key Vault Secrets Officer role
az role assignment create `
    --role "Key Vault Secrets Officer" `
    --assignee $USER_OBJECT_ID `
    --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME"

Write-Host "Waiting 30 seconds for role assignment to propagate..."
Start-Sleep -Seconds 30

# Store the client secret in Key Vault
az keyvault secret set `
    --vault-name $KEY_VAULT_NAME `
    --name "SwaClientSecret" `
    --value $CLIENT_SECRET `
    --expires (Get-Date).AddYears(2).ToString("yyyy-MM-ddTHH:mm:ssZ") `
    --tags "AppClientId=$CLIENT_ID" "CreatedBy=ManualDeployment"

Write-Host "Client secret stored in Key Vault as 'SwaClientSecret'"
```

### 7.6 Configure Static Web App and Function App Settings

```powershell
# Get your tenant ID
$TENANT_ID = az account show --query "tenantId" -o tsv

# Configure SWA with the app registration credentials
# Note: SWA custom auth requires the actual secret value, not Key Vault references
az staticwebapp appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --setting-names "AAD_CLIENT_ID=$CLIENT_ID" "AAD_CLIENT_SECRET=$CLIENT_SECRET"

# Verify settings were applied (the 'set' command may show null due to redaction)
az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties" -o json

# Configure the Function App with the SWA client ID for auto-rotation
az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "SWA_CLIENT_ID=$CLIENT_ID"

Write-Host "App settings configured"
Write-Host ""
Write-Host "NOTE: The client secret is also stored in Key Vault for backup/rotation purposes."
```

> **Important**: The `az staticwebapp appsettings set` command may display `null` for values due to security redaction. Use the `list` command to verify the settings were applied correctly.

### 7.7 Disable Easy Auth on Function App

The Function App must NOT have Easy Auth enabled since API authentication is handled through the SWA backend link.

```powershell
# Disable Easy Auth on the Function App
az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-03-01" `
    --body '{"properties":{"platform":{"enabled":false},"globalValidation":{"unauthenticatedClientAction":"AllowAnonymous"}}}'

Write-Host "Easy Auth disabled on Function App"
```

### 7.8 Link Function App to Static Web App

```powershell
# Get the Function App resource ID
$FUNCTION_APP_ID = az functionapp show `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "id" -o tsv

# Get the Function App region (must match for backend linking)
$FUNC_LOCATION = az functionapp show `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "location" -o tsv

# Link the Function App as the API backend
az staticwebapp backends link `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --backend-resource-id $FUNCTION_APP_ID `
    --backend-region $FUNC_LOCATION

Write-Host "Function App linked as SWA backend"
```

### 7.9 Save Access Control Configuration

```powershell
# Save configuration for reference
$accessControlConfig = @{
    clientId = $CLIENT_ID
    servicePrincipalId = $SP_ID
    tenantId = $TENANT_ID
    swaHostname = $SWA_HOSTNAME
    keyVaultName = $KEY_VAULT_NAME
} | ConvertTo-Json

Set-Content -Path "$HOME/SamlCertRotation/infrastructure/access-control-config.json" -Value $accessControlConfig

Write-Host "Access control configuration saved to access-control-config.json"
```

### Summary of Access Control Settings

| Setting | Location | Value |
|---------|----------|-------|
| `AAD_CLIENT_ID` | SWA App Settings | App Registration Client ID |
| `AAD_CLIENT_SECRET` | SWA App Settings | Key Vault Reference |
| `SwaClientSecret` | Key Vault | The actual client secret |
| `SWA_CLIENT_ID` | Function App Settings | App Registration Client ID (for auto-rotation) |
| `KeyVaultUri` | Function App Settings | Key Vault URI (set by Bicep) |
| `appRoleAssignmentRequired` | Enterprise Application | `true` |
| Easy Auth | Function App | Disabled |
| Tenant ID | staticwebapp.config.json | Your Azure AD Tenant ID |

> **Note**: Only users or groups assigned to the Enterprise Application can access the dashboard. Users not assigned will see "Access Denied" from Azure AD before reaching the application.

> **Auto-Rotation**: The `RotateSwaClientSecret` function runs daily and will automatically create a new
> client secret and store it in Key Vault when the current secret is within 30 days of expiration.

---

## Step 8: Deploy the Dashboard

### 8.1 Get Static Web App Deployment Token

```powershell
# Get deployment token
$SWA_TOKEN = az staticwebapp secrets list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.apiKey" -o tsv

Write-Host "Deployment token retrieved"
```

### 8.2 Update Dashboard Configuration

```powershell
Set-Location "$HOME/SamlCertRotation/dashboard"

# Update the staticwebapp.config.json with your tenant ID (if not done in Step 7)
$configContent = Get-Content staticwebapp.config.json -Raw
$configContent = $configContent -replace '<YOUR_TENANT_ID>', $TENANT_ID
Set-Content -Path staticwebapp.config.json -Value $configContent

# NOTE: API_BASE_URL in index.html should remain empty - the SWA backend link handles API routing
```

### 8.3 Deploy Dashboard

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

### 8.4 Get Dashboard URL

```powershell
# Get the Static Web App URL
$dashboardUrl = az staticwebapp show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "defaultHostname" -o tsv

Write-Host "Dashboard URL: https://$dashboardUrl"
```

---

## Step 9: Configure Email Notifications

The tool uses a Logic App with an Office 365 connector to send email notifications.
This approach requires no Mail.Send Graph permission on the managed identity.

### 9.1 Configure Logic App with Office 365 Connector

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your resource group: `$RESOURCE_GROUP`
3. Find and open the Logic App: `$LOGIC_APP_NAME`
4. Click **Logic app designer**

### 9.2 Configure the Logic App Email Connection

The Logic App was deployed with a **Send an email (V2)** action pre-configured. You need to authorize the email connection:

1. In the designer, click on the **Send an email (V2)** tile
2. Under **Parameters**, click **Change connection**
3. Click **Add new**
4. Sign in with the account whose email address will send the notifications (e.g., a shared mailbox or service account)
5. Click **Save** at the top of the designer

> **Note**: The account you sign in with will be the "From" address for all notification emails. Consider using a shared mailbox like `saml-notifications@yourdomain.com`.

### 9.3 Get Logic App Callback URL

```powershell
# Get the Logic App HTTP trigger URL
$LOGIC_APP_URL = az rest --method post `
    --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Logic/workflows/$LOGIC_APP_NAME/triggers/manual/listCallbackUrl?api-version=2016-10-01" `
    --query "value" -o tsv

Write-Host "Logic App URL: $LOGIC_APP_URL"
```

### 9.4 Configure Function App with Logic App URL

```powershell
# Store the Logic App URL in Function App settings
az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "LogicAppEmailUrl=$LOGIC_APP_URL"

Write-Host "Function App configured to use Logic App for email notifications"
```

### 9.5 Test Email Notifications

You can test the Logic App directly:

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


### Dashboard shows 404 Not Found

This means the deployment didn't succeed or files weren't deployed correctly:

```powershell
# 1. Verify dist folder has the correct files
Set-Location "$HOME/SamlCertRotation/dashboard"
Get-ChildItem dist/

# Should show: index.html, staticwebapp.config.json, unauthorized.html

# 2. Verify deployment token is set
Write-Host "Token set: $([bool]$SWA_TOKEN)"

# 3. If token is missing, get it again
$SWA_TOKEN = az staticwebapp secrets list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.apiKey" -o tsv

# 4. Re-deploy
npx -y @azure/static-web-apps-cli deploy ./dist `
    --deployment-token $SWA_TOKEN `
    --env production

# 5. Wait 1-2 minutes and refresh the browser
```

If you still see 404, check the Azure Portal:
1. Go to your Static Web App resource
2. Click **Environment** in the left menu
3. Verify there's a deployment under "Production"
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
$KEY_VAULT_NAME = $outputs.keyVaultName.value
```

### Recover CLIENT_ID and CLIENT_SECRET

If you lose these variables during Step 7:

```powershell
# Recover CLIENT_ID from the app registration
$APP_NAME = "SAML Certificate Rotation Dashboard"
$CLIENT_ID = az ad app list --filter "displayName eq '$APP_NAME'" --query "[0].appId" -o tsv
Write-Host "CLIENT_ID: $CLIENT_ID"

# Recover CLIENT_SECRET from Key Vault (if Step 7.5 was completed)
$CLIENT_SECRET = az keyvault secret show --vault-name $KEY_VAULT_NAME --name "SwaClientSecret" --query "value" -o tsv
Write-Host "CLIENT_SECRET length: $($CLIENT_SECRET.Length)"

# If the secret is not in Key Vault, generate a new one:
# $CLIENT_SECRET = az ad app credential reset --id $CLIENT_ID --display-name "SWA Auth Secret" --years 2 --query "password" -o tsv
```

### Function not triggering

```powershell
# Check if functions are deployed
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[].{Name:name}" `
    --output table

# Check application settings
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[].{Name:name, Value:value}" `
    --output table
```

### Dashboard shows no data

1. Check browser console (F12) for errors
2. Verify the SWA backend link was configured (Step 7.8)
3. Check that Easy Auth is disabled on the Function App (Step 7.5)
4. Ensure API_BASE_URL in index.html is empty (SWA backend handles routing)

### Dashboard shows "Unexpected token '<'" error

This typically means the API is returning HTML instead of JSON. Common causes:

1. **Easy Auth is enabled on Function App** - Disable it via Step 7.5
2. **SWA backend link not configured** - Run Step 7.8
3. **Missing exclude patterns in staticwebapp.config.json** - Ensure `/api/*` is in exclude list

### Dashboard shows "Access Denied" / User shows as "anonymous"

1. **Enterprise App assignment not configured** - Run Step 7.3 through 7.4
2. **User not assigned to the Enterprise App** - Add user/group via Azure Portal
3. **SWA app settings not configured** - Run Step 7.7

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
$KEY_VAULT_NAME = $outputs.keyVaultName.value

# Test API
$FUNCTION_KEY = az functionapp keys list --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME --query "functionKeys.default" -o tsv
Invoke-RestMethod -Uri "$FUNCTION_APP_URL/api/dashboard/stats?code=$FUNCTION_KEY" | ConvertTo-Json

# View logs
az functionapp log tail --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
```

---

## Cleanup / Teardown

To completely remove the SAML Certificate Rotation Tool, follow these steps.

### Step 1: Delete the Resource Group

This removes all Azure resources (Function App, Storage, Key Vault, Static Web App, etc.):

```powershell
# Delete the entire resource group and all resources within it
az group delete --name $RESOURCE_GROUP --yes --no-wait

Write-Host "Resource group deletion initiated (runs in background)"
```

### Step 2: Delete Entra ID Objects

These objects exist at the tenant level and must be deleted separately:

```powershell
# Load saved configuration (if available)
$configPath = "$HOME/SamlCertRotation/infrastructure/access-control-config.json"
if (Test-Path $configPath) {
    $config = Get-Content $configPath | ConvertFrom-Json
    $CLIENT_ID = $config.clientId
    $ADMIN_GROUP_ID = $config.adminGroupId
}

# Delete the App Registration (also deletes the Service Principal)
if ($CLIENT_ID) {
    az ad app delete --id $CLIENT_ID
    Write-Host "Deleted App Registration: $CLIENT_ID"
}

# Delete the Security Group (optional - you may want to keep this)
if ($ADMIN_GROUP_ID) {
    az ad group delete --group $ADMIN_GROUP_ID
    Write-Host "Deleted Security Group: $ADMIN_GROUP_ID"
}
```

### Step 3: Delete Custom Security Attributes (Optional)

Custom Security Attributes can only be deactivated, not deleted, via the portal:

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Protection** → **Custom security attributes**
3. Select the `SamlCertRotation` attribute set
4. Select the `AutoRotate` attribute → **Deactivate**

> **Note**: Deactivating the attribute won't affect your SAML applications, but the attribute
> values will no longer be readable until reactivated.

### Step 4: Remove Graph API Role Assignments (Optional)

If you want to clean up the managed identity's Graph permissions (the identity is deleted with
the resource group, but the role assignments may persist briefly):

```powershell
# These are automatically cleaned up when the managed identity is deleted,
# but you can manually verify by checking the Enterprise Applications in Entra ID
```

### What Gets Deleted

| Resource | Location | Deleted By |
|----------|----------|------------|
| Function App | Resource Group | `az group delete` |
| Storage Account | Resource Group | `az group delete` |
| Key Vault | Resource Group | `az group delete` (soft-delete for 90 days) |
| Static Web App | Resource Group | `az group delete` |
| Logic App | Resource Group | `az group delete` |
| Log Analytics Workspace | Resource Group | `az group delete` |
| App Insights | Resource Group | `az group delete` |
| Managed Identity | Resource Group | `az group delete` |
| App Registration | Entra ID (Tenant) | `az ad app delete` |
| Service Principal | Entra ID (Tenant) | Deleted with App Registration |
| Security Group | Entra ID (Tenant) | `az ad group delete` |
| Custom Security Attributes | Entra ID (Tenant) | Manual deactivation only |

---

## Next Steps

1. Monitor the dashboard for certificate expiration status
2. Review audit logs periodically
3. Adjust rotation policies as needed via the dashboard
4. Tag additional SAML applications with `AutoRotate=on` as desired
