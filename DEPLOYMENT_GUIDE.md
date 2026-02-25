# SAML Certificate Rotation Tool - Azure Cloud Shell Deployment Guide (PowerShell)

This guide walks you through deploying the SAML Certificate Rotation Tool using **Azure Cloud Shell** with **PowerShell**.

## Table of Contents

[Prerequisites](#prerequisites) <br />
[Step 1: Prepare Your Environment](#step-1-prepare-your-environment) <br />
[Step 2: Create Custom Security Attributes](#step-2-create-custom-security-attributes) <br />
[Step 3: Deploy Azure Infrastructure](#step-3-deploy-azure-infrastructure) <br />
[Step 4: Grant Microsoft Graph Permissions](#step-4-grant-microsoft-graph-permissions) <br />
[Step 5: Deploy the Function App Code](#step-5-deploy-the-function-app-code) <br />
[Step 6: Configure Dashboard Access Control](#step-6-configure-dashboard-access-control) <br />
[Step 7: Deploy the Dashboard](#step-7-deploy-the-dashboard) <br />
[Step 8: Configure Email Notifications](#step-8-configure-email-notifications) <br />
[Step 9: Tag Applications for Auto-Rotation](#step-9-tag-applications-for-auto-rotation) <br />
[Step 10: Verify the Deployment](#step-10-verify-the-deployment) <br />
[Post-Deployment Steps](#post-deployment-steps)

---

## Prerequisites

- [ ] **Azure Subscription** with Owner or Contributor role
- [ ] **Microsoft Entra ID** with one of:
  - Global Administrator role, OR
  - Application Administrator + Attribute Definition Administrator roles
- [ ] Access to **Azure Cloud Shell** (https://shell.azure.com) - **Select PowerShell mode**

> **Note**: Azure Cloud Shell already has Azure CLI, .NET SDK, PowerShell, and Node.js pre-installed.

> **Important**: If you plan to use the built-in `code` editor (Step 3.1), switch to **Classic Cloud Shell** before running any commands. In Cloud Shell, go to **Settings** → **Go to Classic version**. If you prefer `nano` or `vi`, the new Cloud Shell works fine throughout this guide.

---

## Step 1: Prepare Your Environment
Navigate to https://portal.azure.com/#cloudshell/
- Ensure you're in PowerShell


### 1.1 Clone from Git Repository
```powershell
# Go back to home
Set-Location $HOME

# Clone the repository
git clone https://github.com/JeffBley/SamlCertRotation.git SamlCertRotation
Set-Location SamlCertRotation
git checkout main
```

### 1.2 Verify Files Are Present

```powershell
# Navigate to project root and verify structure
Set-Location "$HOME/SamlCertRotation"
Get-ChildItem
```
You should see:
- dashboard
- infrastructure
- src
- DEPLOYMENT_GUIDE.md
- README.md
- SamlCertRotation.sln


### 1.3 Sync to the Latest Repository Version (Required)

Cloud Shell storage persists between sessions. Always sync to the latest code before building or deploying to avoid stale UI/API regressions.

```powershell
Set-Location "$HOME/SamlCertRotation"
git fetch origin
git pull origin main
```

### 1.4 Verify Deployment Info

Cloud Shell is automatically authenticated. Verify your subscription:

```powershell
# Check current subscription
az account show --query "{Name:name, SubscriptionId:id}" -o table
```
```powershell
# If you need to change subscription:
az account list --output table
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
```

### 1.5 Create Resource Group

```powershell
# Set variables (modify as needed)
$RESOURCE_GROUP = "rg-saml-cert-rotation"
$LOCATION = "eastus"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION
```

### 1.6 Save Session Variables

Cloud Shell variables are lost when switching between Classic/New mode or on session timeout. Save them to a persistent file so every later step can recover automatically.

```powershell
# Persist session variables (re-run this after changing values)
@"
# Saved by Step 1.6 — sourced automatically by later steps
`$RESOURCE_GROUP = "$RESOURCE_GROUP"
`$LOCATION = "$LOCATION"
"@ | Set-Content -Path "$HOME/SamlCertRotation/infrastructure/session-vars.ps1" -Encoding utf8

Write-Host "Session variables saved to session-vars.ps1"
```

> **Tip**: If you ever switch Cloud Shell modes or return after a timeout, simply run:  
> `. $HOME/SamlCertRotation/infrastructure/session-vars.ps1`  
> to restore all variables. The remaining steps do this automatically.

---

## Step 2: Create Custom Security Attributes

Custom Security Attributes allow you to tag which SAML apps should be auto-rotated.

### Via Microsoft Entra Admin Center

1. Open a new browser tab and go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Protection** → **Custom security attributes**
3. Click **+ Add attribute set**:
   - **Name**: Enter a name like `SamlCertRotation`
   - **Description**: `Attributes for SAML certificate rotation automation`
   - **Maximum number of attributes**: 10
4. Click **Add**
5. Select the `SamlCertRotation` attribute set
6. Click **+ Add attribute**:
   - **Attribute name**: Enter a name like `AutoRotate`
   - **Description**: `Enable automatic SAML certificate rotation`
   - **Data type**: String
   - **Allow only predefined values**: Yes
    - **Predefined values**: `on`, `notify`, `off`
7. Click **Save**

---

## Step 3: Deploy Azure Infrastructure

### 3.1 Update Parameters File

Edit the parameters file with your values:

```powershell
Set-Location "$HOME/SamlCertRotation/infrastructure"

# Open in the Cloud Shell editor (Classic) or nano (New Cloud Shell)
# Use whichever editor is available in your shell:
code main.parameters.json   # Classic Cloud Shell
# nano main.parameters.json  # New Cloud Shell / Linux
```

Update these values:
- `tenantId`: Your Azure AD Tenant ID (run `az account show --query tenantId -o tsv` to get it)
- `adminNotificationEmails`: Admin emails (semicolon-separated)
- `customSecurityAttributeSet`: The Attribute Set you created in Step 2
- `customSecurityAttributeName`: The Attribute Name you created in Step 2
- `swaLocation`: The Azure region for the Static Web App dashboard (default: `eastus2`). SWA supports limited regions: `centralus`, `eastus2`, `eastasia`, `westeurope`, `westus2`. Choose a region closest to your users.

Save the file (`Ctrl+S` then `Ctrl+Q` in Classic; `Ctrl+O` then `Ctrl+X` in nano).

### 3.2 Deploy Infrastructure with Bicep

```powershell
# Make sure you're in the infrastructure directory
Set-Location "$HOME/SamlCertRotation/infrastructure"

# Restore session variables (safe to re-run; handles Classic/New switch or session timeout)
if (Test-Path "$HOME/SamlCertRotation/infrastructure/session-vars.ps1") {
    . "$HOME/SamlCertRotation/infrastructure/session-vars.ps1"
    Write-Host "Restored session variables (RESOURCE_GROUP=$RESOURCE_GROUP)"
} elseif (-not $RESOURCE_GROUP) {
    # Fallback: set inline if session-vars.ps1 was never created
    $RESOURCE_GROUP = "rg-saml-cert-rotation"
    Write-Host "Using default RESOURCE_GROUP=$RESOURCE_GROUP"
}

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

### 3.3 Save Output Values as Variables (Re-runnable)

```powershell
# Re-run this block anytime (including after Cloud Shell session timeout or shell switch).
Set-Location "$HOME/SamlCertRotation/infrastructure"

# Ensure resource group is set
if (Test-Path "./session-vars.ps1") { . "./session-vars.ps1" }
if (-not $RESOURCE_GROUP) { $RESOURCE_GROUP = "rg-saml-cert-rotation" }

# Load deployment outputs — try local file first, fall back to Azure
$outputs = $null
if (Test-Path "deployment-outputs.json") {
    $raw = Get-Content "deployment-outputs.json" -Raw
    if ($raw.Trim() -notin "", "null") { $outputs = $raw | ConvertFrom-Json }
}
if (-not $outputs) {
    $outputs = az deployment group list `
        --resource-group $RESOURCE_GROUP `
        --query "[?properties.provisioningState=='Succeeded' && properties.outputs.functionAppName != null] | sort_by(@, &properties.timestamp) | [-1].properties.outputs" `
        -o json | ConvertFrom-Json

    if (-not $outputs) { throw "No successful deployment found in '$RESOURCE_GROUP'. Run Step 3.2 first." }
}

# Read tenant ID from parameters file so it survives session timeouts
$TENANT_ID = (Get-Content "$HOME/SamlCertRotation/infrastructure/main.parameters.json" -Raw | ConvertFrom-Json).parameters.tenantId.value
if ([string]::IsNullOrWhiteSpace($TENANT_ID) -or $TENANT_ID -like "<insert*") {
    throw "Set parameters.tenantId.value in infrastructure/main.parameters.json before running this step."
}

# Persist all variables for session recovery
@"
`$RESOURCE_GROUP = "$RESOURCE_GROUP"
`$LOCATION = "$LOCATION"
`$TENANT_ID = "$TENANT_ID"
`$MANAGED_IDENTITY_PRINCIPAL_ID = "$($outputs.managedIdentityPrincipalId.value)"
`$MANAGED_IDENTITY_CLIENT_ID = "$($outputs.managedIdentityClientId.value)"
`$MANAGED_IDENTITY_NAME = "$($outputs.managedIdentityName.value)"
`$FUNCTION_APP_NAME = "$($outputs.functionAppName.value)"
`$FUNCTION_APP_URL = "$($outputs.functionAppUrl.value)"
`$STATIC_WEB_APP_NAME = "$($outputs.staticWebAppName.value)"
`$STORAGE_ACCOUNT_NAME = "$($outputs.storageAccountName.value)"
`$KEY_VAULT_NAME = "$($outputs.keyVaultName.value)"
`$KEY_VAULT_URI = "$($outputs.keyVaultUri.value)"
`$LOG_ANALYTICS_NAME = "$($outputs.logAnalyticsWorkspaceName.value)"
`$LOGIC_APP_NAME = "$($outputs.logicAppName.value)"
"@ | Set-Content -Path "./session-vars.ps1" -Encoding utf8

# Load and display saved variables
. "./session-vars.ps1"
Get-Content "./session-vars.ps1"

# Display for easy copy-paste into Step 4.1
Write-Host "`nMANAGED_IDENTITY_PRINCIPAL_ID: $MANAGED_IDENTITY_PRINCIPAL_ID" -ForegroundColor green
```

---

## Step 4: Grant Microsoft Graph Permissions

The managed identity needs Microsoft Graph API permissions.

### 4.1 Grant Permissions via PowerShell
Switch to Windows PowerShell or Powershell 7+ and run the following:

```powershell
# Set variable
$MANAGED_IDENTITY_PRINCIPAL_ID = "<Insert MANAGED_IDENTITY_PRINCIPAL_ID from Step 3.3>"

# Install Microsoft Graph module if not already installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Connect to Microsoft Graph (will open browser for auth)
Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"

# Get the managed identity service principal
$managedIdentitySP = Get-MgServicePrincipal -ServicePrincipalId $MANAGED_IDENTITY_PRINCIPAL_ID

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" | Select-Object -First 1

# Define required permissions
$requiredPermissions = @(
    "Application.ReadWrite.All"
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

### 4.2 Assign Attribute Assignment Reader Role

The managed identity needs the **Attribute Assignment Reader** role to read custom security attribute values. This is a separate role from the Graph API permission.

Switch back to the **Cloud Shell** and run the following:

```powershell
# Restore session variables (in case you switched Cloud Shell modes)
. "$HOME/SamlCertRotation/infrastructure/session-vars.ps1"

# Assign the Attribute Assignment Reader role to the managed identity
# This grants read access to custom security attributes on all objects

az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
    --headers "Content-Type=application/json" `
    --body "{`"principalId`":`"$MANAGED_IDENTITY_PRINCIPAL_ID`",`"roleDefinitionId`":`"ffd52fa5-98dc-465c-991d-fc073eb59f8f`",`"directoryScopeId`":`"/`"}"
```

---

## Step 5: Deploy the Function App Code

### 5.1 Build the Project

```powershell
# Navigate to project root
Set-Location "$HOME/SamlCertRotation"

# Restore session variables (safe to re-run after shell switch or timeout)
. "$HOME/SamlCertRotation/infrastructure/session-vars.ps1"

# Restore and build
dotnet restore src/SamlCertRotation/SamlCertRotation.csproj
dotnet build src/SamlCertRotation/SamlCertRotation.csproj --configuration Release

# Publish
dotnet publish src/SamlCertRotation/SamlCertRotation.csproj `
    --configuration Release `
    --output ./publish
```

### 5.2 Deploy to Azure Function App

```powershell
# IMPORTANT: Publish from the project directory using Functions Core Tools.
# This avoids intermittent 404 regressions caused by config-zip package indexing issues.
Set-Location "$HOME/SamlCertRotation/src/SamlCertRotation"

# Ensure Functions Core Tools is available in Cloud Shell
func --version

# Deploy with explicit runtime
func azure functionapp publish $FUNCTION_APP_NAME --dotnet-isolated
```

### 5.3 Verify Function Indexing and Route Health

```powershell
# Verify deployment - functions must be listed
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[].name" `
    --output table

# Quick route check (401/403 is expected without SWA auth context; 404 is not)
$FUNCTION_HOST = az functionapp show `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "defaultHostName" -o tsv

try {
    Invoke-WebRequest "https://$FUNCTION_HOST/api/dashboard/stats" -UseBasicParsing
} catch {
    $_.Exception.Response.StatusCode.value__
}
```

You should see functions listed including `CertificateChecker`, `GetDashboardStats`, `GetRoles`, etc. The route check should return `401` (authentication required). A `404` indicates deployment or routing issues.


---

## Step 6: Configure Dashboard Access Control

The dashboard uses Azure AD authentication with Enterprise Application assignment to control access. Only users or groups assigned to the Enterprise Application can access the dashboard.

### 6.1 Create an App Registration

```powershell
#Set Variables
$APP_NAME = "SAML Certificate Rotation Dashboard"

# Restore session variables (safe to re-run after shell switch or timeout)
. "$HOME/SamlCertRotation/infrastructure/session-vars.ps1"

# Get Static Web App hostname
$SWA_HOSTNAME = az staticwebapp show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "defaultHostname" -o tsv

# Create app registration for SWA authentication
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

### 6.2 Configure App Roles in the App Registration

Configure the three app roles used by dashboard authorization.

```powershell
# Define the three app roles
$appRoles = @(
    @{
        id          = [guid]::NewGuid().ToString()
        displayName = "SAML Cert Rotation Admin"
        description = "Full dashboard access"
        value       = "SamlCertRotation.Admin"
        allowedMemberTypes = @("User")
        isEnabled   = $true
    },
    @{
        id          = [guid]::NewGuid().ToString()
        displayName = "SAML Cert Rotation Reader"
        description = "Read-only dashboard access"
        value       = "SamlCertRotation.Reader"
        allowedMemberTypes = @("User")
        isEnabled   = $true
    },
    @{
        id          = [guid]::NewGuid().ToString()
        displayName = "SAML Cert Rotation Sponsor"
        description = "Sponsor access — view and manage own sponsored apps"
        value       = "SamlCertRotation.Sponsor"
        allowedMemberTypes = @("User")
        isEnabled   = $true
    }
)

$body = @{ appRoles = $appRoles } | ConvertTo-Json -Depth 4 -Compress

az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" `
    --headers "Content-Type=application/json" `
    --body $body

Write-Host "App roles configured successfully" -ForegroundColor Green
```

### 6.3 Create Service Principal (Enterprise App)
This will create the Enterprise App that will control who has access to the app's portal.

```powershell
# Create service principal for the app
az ad sp create --id $CLIENT_ID

# Get the Service Principal ID
$SP_ID = az ad sp list --filter "appId eq '$CLIENT_ID'" --query "[0].id" -o tsv
Write-Host "Service Principal ID: $SP_ID"

# Add the enterprise app tag (app will show up as "Enterprise Application" in the Entra Portal)
az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" `
    --body '{"tags": ["WindowsAzureActiveDirectoryIntegratedApp"]}'

# Enable "Assignment required" on the Enterprise Application
az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" `
    --body '{"appRoleAssignmentRequired": true}'
```

### 6.4 Grant Admin Consent for Microsoft Graph Permissions (Optional)

Grant admin consent for the delegated Microsoft Graph `openid` permission used during SWA authentication. This avoids users seeing a consent prompt on first sign-in.

```powershell
# Grant admin consent for the openid delegated permission
# Microsoft Graph well-known AppId: 00000003-0000-0000-c000-000000000000
$GRAPH_SP_ID = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].id" -o tsv

$body = @{
    clientId = $SP_ID
    consentType = "AllPrincipals"
    resourceId = $GRAPH_SP_ID
    scope = "openid"
} | ConvertTo-Json -Compress

try {
    az rest --method POST --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" --headers "Content-Type=application/json" --body $body
    Write-Host "Granted admin consent: openid" -ForegroundColor Green
} catch {
    Write-Host "Already granted or error: openid" -ForegroundColor Yellow
}
```

> **Note**: If you skip this step, users will be prompted to consent to these permissions on their first sign-in. This is harmless but may confuse users.

### 6.5 Configure User/Group Assignment

Now assign users or groups to the application in the Entra Portal (assumes your group already exists):

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **Enterprise applications**
3. Open your enterprise app (`SAML Certificate Rotation Dashboard`)
4. Go to **Users and groups** → **Add user/group**
5. Under **Users and groups**, select the existing user or group you want to grant access
6. Under **Select a role**, choose one:
   - `SAML Cert Rotation Admin` (`SamlCertRotation.Admin`) for full access
   - `SAML Cert Rotation Reader` (`SamlCertRotation.Reader`) for read-only access
   - `SAML Cert Rotation Sponsor` (`SamlCertRotation.Sponsor`) for sponsor access (view/manage own apps)
7. Click **Assign**

> **Important**: Users who are not assigned to the Enterprise Application will receive an "Access Denied" error when trying to access the dashboard.

### 6.6 Create Client Secret

```powershell
# Create client secret (valid for 2 years)
$CLIENT_SECRET = az ad app credential reset `
    --id $CLIENT_ID `
    --display-name "SWA Auth Secret" `
    --years 2 `
    --query "password" -o tsv

Write-Host "Client secret generated successfully. Length: $($CLIENT_SECRET.Length)"
Write-Host "Client Secret: $CLIENT_SECRET" -ForegroundColor Red
Write-Host "IMPORTANT: Save this secret securely - it cannot be retrieved later!" -ForegroundColor Red
```

### 6.7 Store Client Secret in Key Vault

Store the dashboard client secret in Azure Key Vault. This project does not auto-rotate dashboard secrets.

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
    --name "SamlDashboardClientSecret" `
    --value $CLIENT_SECRET `
    --expires (Get-Date).AddYears(2).ToString("yyyy-MM-ddTHH:mm:ssZ") `
    --tags "AppClientId=$CLIENT_ID" "CreatedBy=ManualDeployment"
```

> **Important**: Keep the secret name consistent across Key Vault and SWA app settings. In this guide the required name is `SamlDashboardClientSecret`.

### 6.8 Enable Static Web App Managed Identity and Key Vault Access

The Static Web App must use a managed identity with Key Vault read access before Key Vault references will resolve.

```powershell
# Enable system-assigned managed identity on the Static Web App
az staticwebapp identity assign `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME

# Grant Static Web App managed identity permission to read Key Vault secrets
$KV_ID = az keyvault show --name $KEY_VAULT_NAME --query id -o tsv
$SWA_PRINCIPAL_ID = az staticwebapp identity show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query principalId -o tsv

az role assignment create `
    --assignee-object-id $SWA_PRINCIPAL_ID `
    --assignee-principal-type ServicePrincipal `
    --role "Key Vault Secrets User" `
    --scope $KV_ID

Write-Host "Waiting 60 seconds for RBAC propagation..."
Start-Sleep -Seconds 60
```

### 6.9 Configure Static Web App and Function App Settings

```powershell
# Read tenant ID from infrastructure/main.parameters.json
$TENANT_ID = (Get-Content "$HOME/SamlCertRotation/infrastructure/main.parameters.json" -Raw | ConvertFrom-Json).parameters.tenantId.value

if ([string]::IsNullOrWhiteSpace($TENANT_ID) -or $TENANT_ID -like "<insert*") {
    throw "Set parameters.tenantId.value in infrastructure/main.parameters.json before running this step."
}

# Configure SWA with app registration client ID and Key Vault secret reference
# Requires SWA Standard plan with managed identity enabled and Key Vault access granted
az staticwebapp appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --setting-names "AAD_CLIENT_ID=$CLIENT_ID" "AAD_CLIENT_SECRET=@Microsoft.KeyVault(VaultName=$KEY_VAULT_NAME;SecretName=SamlDashboardClientSecret)"

# Verify settings were applied (the 'set' command may show null due to redaction)
az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties" -o json

Write-Host "App settings configured"
Write-Host "NOTE: Dashboard secret remains in Key Vault; SWA reads it via Key Vault reference."
Write-Host "NOTE: staticwebapp.config.json tenant replacement is performed in Step 7.2."

# Configure Function App role mapping used by GetRoles
az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "SWA_ADMIN_APP_ROLE=SamlCertRotation.Admin" "SWA_READER_APP_ROLE=SamlCertRotation.Reader" "SWA_SPONSOR_APP_ROLE=SamlCertRotation.Sponsor"

# Verify role mapping settings exist on Function App
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[?name=='SWA_ADMIN_APP_ROLE' || name=='SWA_READER_APP_ROLE' || name=='SWA_SPONSOR_APP_ROLE'].[name,value]" -o table

# Verify the Key Vault reference is set
az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.{AAD_CLIENT_ID:AAD_CLIENT_ID,AAD_CLIENT_SECRET:AAD_CLIENT_SECRET}" -o json
```

### 6.10 Link Function App to Static Web App

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
```

### 6.11 Disable Easy Auth on Function App

The `backends link` command above enables Easy Auth on the Function App. We need to **disable it** because authentication is handled by the Static Web App, not the Function App.

> **Important**: This step MUST run AFTER 6.10 (backend linking), otherwise the link command will re-enable Easy Auth.

```powershell
# Disable Easy Auth on the Function App
$SUBSCRIPTION_ID = az account show --query id -o tsv

az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-09-01" `
    --body '{"properties":{"platform":{"enabled":false},"globalValidation":{"unauthenticatedClientAction":"AllowAnonymous"}}}'

# Verify Easy Auth is disabled (should return "false")
$easyAuthStatus = az rest --method GET `
    --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-09-01" `
    --query "properties.platform.enabled" -o tsv

if ($easyAuthStatus -eq "false") {
    Write-Host "Easy Auth disabled successfully" -ForegroundColor Green
} else {
    Write-Host "WARNING: Easy Auth is still enabled ($easyAuthStatus). API calls will fail." -ForegroundColor Red
}
```

### 6.12 Save Access Control Configuration

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
```

### Summary of Access Control Settings

| Setting | Location | Value |
|---------|----------|-------|
| `AAD_CLIENT_ID` | SWA App Settings | App Registration Client ID |
| `AAD_CLIENT_SECRET` | SWA App Settings | Key Vault reference string (`@Microsoft.KeyVault(...)`) |
| `SamlDashboardClientSecret` | Key Vault | Primary storage for the client secret |
| `KeyVaultUri` | Function App Settings | Key Vault URI (set by Bicep) |
| `SWA_DEFAULT_HOSTNAME` | Function App Settings | SWA default hostname (set by Bicep) |
| `SWA_HOSTNAME` | Function App Settings | *(Optional)* Custom domain hostname, if configured |
| `SWA_ADMIN_APP_ROLE` | Function App Settings | App role value for admin access (default: `SamlCertRotation.Admin`) |
| `SWA_READER_APP_ROLE` | Function App Settings | App role value for reader access (default: `SamlCertRotation.Reader`) |
| `SWA_SPONSOR_APP_ROLE` | Function App Settings | App role value for sponsor access (default: `SamlCertRotation.Sponsor`) |
| `RotationSchedule` | Function App Settings | CRON expression for rotation checks (default: `0 0 6 * * *` = 6 AM UTC daily) |
| `appRoleAssignmentRequired` | Enterprise Application | `true` |
| Easy Auth | Function App | Disabled (Step 6.11) |
| `tenantId` | infrastructure/main.parameters.json | Your Azure AD Tenant ID |
| Tenant ID | staticwebapp.config.json (`__TENANT_ID__`) | Replaced during Step 7.2 |

> **SWA Token Trust**: When SWA forwards requests to the linked Function App backend, it includes a JWT in the `x-ms-auth-token` header. This token is issued by SWA itself (issuer = `https://<swa-hostname>/.auth`), **not** by Entra ID. The Function App trusts this token using the `SWA_DEFAULT_HOSTNAME` setting (set automatically by Bicep). If you add a custom domain, also set `SWA_HOSTNAME` to the custom domain so token validation works for both.

> **Note**: Only users or groups assigned to the Enterprise Application can access the dashboard. Users not assigned will see "Access Denied" from Azure AD before reaching the application.

> **Rotation Schedule**: You can customize when automatic certificate rotation runs by setting the `RotationSchedule` app setting in the Function App. The value must be a valid NCRONTAB expression. Common examples:
> - `0 0 6 * * *` - Daily at 6:00 AM UTC (default)
> - `0 0 */12 * * *` - Every 12 hours
> - `0 0 6 * * 1` - Every Monday at 6:00 AM UTC

> **Manual secret management**: This solution does not rotate dashboard client secrets automatically. Rotate in Entra ID on your schedule, update `SamlDashboardClientSecret` in Key Vault, and keep the SWA app setting as a Key Vault reference.

---

## Step 7: Deploy the Dashboard

### 7.1 Get Static Web App Deployment Token

```powershell
# Restore session variables (safe to re-run after shell switch or timeout)
. "$HOME/SamlCertRotation/infrastructure/session-vars.ps1"

# Get deployment token
$SWA_TOKEN = az staticwebapp secrets list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.apiKey" -o tsv
```

### 7.2 Update Dashboard Configuration

```powershell
Set-Location "$HOME/SamlCertRotation/dashboard"

# Ensure $TENANT_ID is available (recover from session timeout if needed)
if ([string]::IsNullOrWhiteSpace($TENANT_ID)) {
    $TENANT_ID = (Get-Content "$HOME/SamlCertRotation/infrastructure/main.parameters.json" -Raw | ConvertFrom-Json).parameters.tenantId.value
}
if ([string]::IsNullOrWhiteSpace($TENANT_ID) -or $TENANT_ID -like "<insert*") {
    throw "TENANT_ID is not set. Update infrastructure/main.parameters.json and re-run Step 3.3, or set `$TENANT_ID manually."
}

# Update staticwebapp.config.json with tenant ID
$configContent = Get-Content staticwebapp.config.json -Raw
$configContent = $configContent -replace '__TENANT_ID__', $TENANT_ID
Set-Content -Path staticwebapp.config.json -Value $configContent

# Verify replacement succeeded
$check = Select-String -Path staticwebapp.config.json -Pattern '__TENANT_ID__'
if ($check) {
    throw "staticwebapp.config.json still contains __TENANT_ID__ placeholder. Replacement failed."
}
Write-Host "Tenant ID set to $TENANT_ID in staticwebapp.config.json" -ForegroundColor Green
```
**NOTE**: API_BASE_URL in app.js should remain empty - the SWA backend link handles API routing


### 7.3 Deploy Dashboard

Use SWA CLI via `npx` for deployment:

```powershell
# Prepare dashboard files
New-Item -ItemType Directory -Path dist -Force
Copy-Item index.html dist/
Copy-Item app.js dist/
Copy-Item unauthorized.html dist/
Copy-Item favicon.png dist/
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

## Step 8: Configure Email Notifications

The tool uses a Logic App with an Office 365 connector to send email notifications.

### 8.1 Configure Logic App with Office 365 Connector

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your resource group: `$RESOURCE_GROUP`
3. Find and open the Logic App: `$LOGIC_APP_NAME` (There should only be one Logic App)
4. Click **Logic app designer**

### 8.2 Configure the Logic App Email Connection

The Logic App was deployed with a **Send an email (V2)** action pre-configured. You need to authorize the email connection:

1. In the designer, click on the **Send an email (V2)** tile
2. Under **Parameters**, click **Change connection**
3. Click **Add new**
4. Sign in with the account whose email address will send the notifications (e.g., a shared mailbox or service account)
5. Click **Save** at the top of the designer

> **Note**: The account you sign in with will be the "From" address for all notification emails. Consider using a shared mailbox like `saml-notifications@yourdomain.com`.

---

## Step 9: Tag Applications for Auto-Rotation

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **Enterprise applications**
3. Select a SAML application
4. Go to **Properties** → **Custom security attributes**
5. Click **Add assignment**
6. Select:
   - Attribute set: `SamlCertRotation`
   - Attribute name: `AutoRotate`
   - Assigned values: `on` `off` or `notify`
7. Click **Save**

You may repeat this on several applications to verify expected behavior.

---

## Step 10: Verify the Deployment

### 10.1 Verify Dashboard Access

1. Open the dashboard URL in your browser
2. Sign in with an account that is assigned to the Enterprise Application
3. Verify you can see the dashboard with application statistics

### 10.2 Verify SWA Role Enrichment

After sign-in, verify SWA is enriching roles via the auth metadata endpoint:

1. Open `https://<your-static-web-app-name>.azurestaticapps.net/.auth/me`
2. Confirm the `userRoles` array includes `admin` and/or `reader` in addition to `anonymous` and `authenticated`

---

# Post-Deployment Steps

## Considerations

Now that deployment is complete, review the following items and address them according to your organization's policies.

### 1. Customize the Static Web App Name

The Static Web App is created with an auto-generated hostname (e.g., `happy-island-01f529a0f.azurestaticapps.net`). Most organizations prefer a branded custom domain.

**Action**: If you want a custom domain, see [Configure a Custom Domain](#configure-a-custom-domain) below. This requires updates in multiple places.

### 2. Rotation Schedule

The automatic certificate rotation check runs daily at **6:00 AM UTC** by default. Depending on your environment, you may want to adjust the frequency.

**Action**: If the default schedule doesn't suit your needs, see [Customize the Rotation Schedule](#customize-the-rotation-schedule) below.

### 3. Key Vault Secrets Inventory

The Key Vault contains two secrets that require periodic attention:

| Secret Name | Purpose | Expiration | Auto-Rotated? |
|-------------|---------|------------|---------------|
| `SamlDashboardClientSecret` | Entra ID client secret for dashboard sign-in (SWA auth) | 2 years from creation | No |
| `LogicAppEmailUrl` | Logic App HTTP trigger callback URL (contains SAS token) | Does not expire, but is regenerated if the Logic App is redeployed | No |

**Action**: Establish a rotation cadence for the dashboard client secret (recommended: 90-180 days). See [Rotate the Dashboard Client Secret](#rotate-the-dashboard-client-secret) below for instructions.

> **NOTE:** The **LogicAppEmailUrl** Key Vault secret will be updated automatically when you redeploy the Bicep template. The secret is defined declaratively in main.bicep:105-114 using listCallbackUrl() on the Logic App trigger. Each time you run `az deployment group create` with this template, Bicep evaluates listCallbackUrl() at deploy time — if the Logic App was regenerated and has a new SAS token, the new URL will be written to the LogicAppEmailUrl secret in Key Vault, creating a new secret version. <br > <br > If you regenerate the Logic App trigger URL outside of a Bicep deployment (e.g., via the portal's "Regenerate access keys"), the Key Vault secret will not update until you re-run the Bicep deployment or update the Key Vault value manually.

### 4. Key Vault Access

During deployment, your user account was granted **Key Vault Secrets Officer** on the Key Vault (Step 6.7) so you could store the dashboard client secret. This is more access than the deploying user typically needs long-term.

**Action**: Consider removing or downgrading your personal Key Vault role assignment after deployment is complete. See [Remove Deployer Key Vault Access](#remove-deployer-key-vault-access) below for instructions.

### 5. Logic App Email Sender

The Logic App sends emails from whichever account was authorized in Step 8.2. If you used a personal account, consider switching to a shared mailbox.

**Action**: Re-authorize the Logic App email connector with a shared mailbox (e.g., `saml-notifications@yourdomain.com`). This can be changed at any time via the Logic App designer without redeployment. 

---

### Configure a Custom Domain

By default, your dashboard URL is auto-generated (e.g., `happy-island-01f529a0f.azurestaticapps.net`). To use a custom domain like `saml-dashboard.yourcompany.com`, you need to update **three** places:

#### 1. Add the custom domain to the Static Web App

**1.1. Validate domain ownership (TXT record)**

1. Navigate to Azure Portal → Static Web App → **Settings** → **Custom domains** 
2. Click **Add**.
3. Select **Custom domain on other DNS**
4. Enter your domain name (e.g., `saml.domain.com`) and click **Next**.
5. Set **Hostname record type** to **TXT**.
6. Click **Generate code**.
7. In your DNS provider, add a **TXT** record:
   - **Name/Host**: `saml` (or the subdomain portion of your domain)
   - **Value**: the validation code generated by Azure
8. Click **Verify** in Azure. DNS propagation may take a few minutes.

**1.2. Route traffic to the Static Web App (CNAME record)**

After validation succeeds, add a **CNAME** record in your DNS provider:

| Type | Name/Host | Value |
|------|-----------|-------|
| CNAME | `saml` | `<original-swa-name>.azurestaticapps.net` |

Replace `<original-swa-name>` with your Static Web App's auto-generated hostname.

#### 2. Update the App Registration redirect URI

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com) → **App registrations** → `SAML Certificate Rotation Dashboard`
2. Click **Authentication**
3. Click **Add Redirect URIs**
4. Select **Web** 
5. Add `https://saml-dashboard.yourcompany.com/.auth/login/aad/callback` and click **Configure**

Keep the original `azurestaticapps.net` redirect URI as a fallback

#### 3. Update Function App settings and CORS

The Function App must trust the custom domain as an additional SWA token issuer, and the domain must be added to CORS. Run the following in **Cloud Shell**:

```powershell
# Set your custom domain
$CUSTOM_DOMAIN = "<saml-dashboard.yourcompany.com>" # Example: "samldashboard.contoso.com"

# Restore session variables (clone repo first if this is a fresh shell)
if (-not (Test-Path "$HOME/SamlCertRotation")) {
    git clone https://github.com/JeffBley/SamlCertRotation.git "$HOME/SamlCertRotation"
}
Set-Location "$HOME/SamlCertRotation/infrastructure"
. ./session-vars.ps1

Write-Host "Function App: $FUNCTION_APP_NAME"

# Add custom domain as a trusted SWA token issuer
az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "SWA_HOSTNAME=$CUSTOM_DOMAIN"

# Add custom domain to CORS (keeps existing origins)
az functionapp cors add `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --allowed-origins "https://$CUSTOM_DOMAIN"

# Verify both settings
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[?name=='SWA_HOSTNAME'].[name,value]" -o table

az functionapp cors show `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "allowedOrigins" -o table
```

The `SWA_HOSTNAME` setting is read by [DashboardFunctions.cs](src/SamlCertRotation/Functions/DashboardFunctions.cs) to build a trusted issuer (`https://saml-dashboard.yourcompany.com/.auth`). No code changes are needed — the setting is already supported.

> **Documentation**: [Set up a custom domain in Azure Static Web Apps](https://learn.microsoft.com/en-us/azure/static-web-apps/custom-domain)

---

### Customize the Rotation Schedule

The automatic certificate rotation check runs daily at 6:00 AM UTC by default. To change this:

1. Go to your **Function App** → **Settings** → **Environment variables**
2. Add or update the `RotationSchedule` setting with a CRON expression:
   - `0 0 6 * * *` - Daily at 6:00 AM UTC (default)
   - `0 0 */12 * * *` - Every 12 hours
   - `0 0 6 * * 1` - Every Monday at 6:00 AM UTC
3. **Restart the Function App** for changes to take effect

Or via CLI:

```powershell
# Restore session variables (clone repo first if this is a fresh shell)
if (-not (Test-Path "$HOME/SamlCertRotation")) {
    git clone https://github.com/JeffBley/SamlCertRotation.git "$HOME/SamlCertRotation"
}
Set-Location "$HOME/SamlCertRotation/infrastructure"
. ./session-vars.ps1

az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "RotationSchedule=0 0 */12 * * *"

az functionapp restart --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
```

> **No code changes required.** The `RotationSchedule` setting is read directly by the Function App at startup.

---

### Rotate the Dashboard Client Secret

The dashboard client secret (`SamlDashboardClientSecret`) does not auto-rotate. Use this runbook to rotate it. This script is self-contained and works from a fresh Cloud Shell session.

```powershell
# Restore session variables (clone repo first if this is a fresh shell)
if (-not (Test-Path "$HOME/SamlCertRotation")) {
    git clone https://github.com/JeffBley/SamlCertRotation.git "$HOME/SamlCertRotation"
}
Set-Location "$HOME/SamlCertRotation/infrastructure"
. ./session-vars.ps1

Write-Host "Function App:   $FUNCTION_APP_NAME"
Write-Host "Static Web App: $STATIC_WEB_APP_NAME"
Write-Host "Key Vault:      $KEY_VAULT_NAME"

# 1) Get dashboard app registration client ID from SWA settings
$CLIENT_ID = az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.AAD_CLIENT_ID" -o tsv

Write-Host "Dashboard App Client ID: $CLIENT_ID"

# 2) Add a new Entra client secret (keeps existing credentials valid during rollover)
$NEW_SECRET_JSON = az ad app credential reset `
    --id $CLIENT_ID `
    --display-name "SWA Auth Secret" `
    --years 2 `
    --append `
    --query "{password:password, keyId:keyId}" -o json | ConvertFrom-Json

$NEW_CLIENT_SECRET = $NEW_SECRET_JSON.password
$NEW_KEY_ID = $NEW_SECRET_JSON.keyId

Write-Host "New credential created (Key ID: $NEW_KEY_ID)"

# 3) Store the new secret in Key Vault under the expected name
az keyvault secret set `
    --vault-name $KEY_VAULT_NAME `
    --name "SamlDashboardClientSecret" `
    --value $NEW_CLIENT_SECRET `
    --expires (Get-Date).AddYears(2).ToString("yyyy-MM-ddTHH:mm:ssZ") `
    --tags "CreatedBy=ManualRotation"

# 4) Force SWA to re-resolve the Key Vault reference (flush cached secret)
az staticwebapp appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --setting-names "AAD_CLIENT_SECRET=@Microsoft.KeyVault(VaultName=$KEY_VAULT_NAME;SecretName=SamlDashboardClientSecret)"

Write-Host "Waiting 30 seconds for SWA to pick up the new secret..."
Start-Sleep -Seconds 30

# 5) Verify SWA still points to Key Vault reference (not plaintext)
az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.AAD_CLIENT_SECRET" -o tsv
```
Expected result for step 5:
`AAD_CLIENT_SECRET` should be an `@Microsoft.KeyVault(...)` reference string — not a plaintext secret value. <br > <br>
Optional #6
```
# 6) Remove old credentials from app registration (keep only the one we just created)
$ALL_CREDS = az ad app credential list --id $CLIENT_ID -o json | ConvertFrom-Json
$OLD_CREDS = $ALL_CREDS | Where-Object { $_.keyId -ne $NEW_KEY_ID }

foreach ($cred in $OLD_CREDS) {
    az ad app credential delete --id $CLIENT_ID --key-id $cred.keyId
    Write-Host "Removed old credential: $($cred.keyId) ($($cred.displayName))"
}

Write-Host "Rotation complete. Old credentials removed."
```



Recommended cadence:
- Rotate every 90-180 days, or per your security policy.

> **No code changes required.** The SWA references the secret via Key Vault, so updating the Key Vault secret is all that's needed.

#### Rollback to a Previous Secret

If the new secret causes authentication issues, you can restore the previous Key Vault secret version:

```powershell
# List recent versions of the secret
az keyvault secret list-versions `
    --vault-name $KEY_VAULT_NAME `
    --name "SamlDashboardClientSecret" `
    --query "reverse(sort_by(@, &attributes.created))[0:5].{Version:id, Created:attributes.created, Enabled:attributes.enabled}" `
    -o table

# Copy the previous version's full ID from the table above and restore it
$PREVIOUS_VERSION_ID = "<paste-full-secret-id-from-table>"  # e.g., https://myvault.vault.azure.net/secrets/SamlDashboardClientSecret/abc123

$OLD_SECRET_VALUE = az keyvault secret show `
    --id $PREVIOUS_VERSION_ID `
    --query "value" -o tsv

az keyvault secret set `
    --vault-name $KEY_VAULT_NAME `
    --name "SamlDashboardClientSecret" `
    --value $OLD_SECRET_VALUE `
    --tags "CreatedBy=Rollback"

# Force SWA to pick up the restored secret
az staticwebapp appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --setting-names "AAD_CLIENT_SECRET=@Microsoft.KeyVault(VaultName=$KEY_VAULT_NAME;SecretName=SamlDashboardClientSecret)"

Write-Host "Rollback complete. Verify sign-in works before removing the newer credential from the app registration."
```

> **Important**: This only works if the old credential still exists in the Entra app registration. If step 6 above already removed it, you must create a new secret instead.

---

### Remove Deployer Key Vault Access

During Step 6.7, the deploying user was granted **Key Vault Secrets Officer**. To remove it after deployment:

```powershell
# Restore session variables (clone repo first if this is a fresh shell)
if (-not (Test-Path "$HOME/SamlCertRotation")) {
    git clone https://github.com/JeffBley/SamlCertRotation.git "$HOME/SamlCertRotation"
}
Set-Location "$HOME/SamlCertRotation/infrastructure"
. ./session-vars.ps1

$USER_OBJECT_ID = az ad signed-in-user show --query id -o tsv

az role assignment delete `
    --role "Key Vault Secrets Officer" `
    --assignee $USER_OBJECT_ID `
    --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME"
```

> **Note**: You will need to re-grant this role if you later need to rotate the dashboard client secret manually.