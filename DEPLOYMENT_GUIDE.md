# SAML Certificate Rotation Tool - Azure Cloud Shell Deployment Guide (PowerShell)

This guide walks you through deploying the SAML Certificate Rotation Tool using **Azure Cloud Shell** with **PowerShell**.

## Table of Contents

[Prerequisites](#prerequisites) <br />
[Step 1: Upload Project to Cloud Shell](#step-1-upload-project-to-cloud-shell) <br />
[Step 2: Prepare Your Environment](#step-2-prepare-your-environment) <br />
[Step 3: Create Custom Security Attributes](#step-3-create-custom-security-attributes) <br />
[Step 4: Deploy Azure Infrastructure](#step-4-deploy-azure-infrastructure) <br />
[Step 5: Grant Microsoft Graph Permissions](#step-5-grant-microsoft-graph-permissions) <br />
[Step 6: Deploy the Function App Code](#step-6-deploy-the-function-app-code) <br />
[Step 7: Configure Dashboard Access Control](#step-7-configure-dashboard-access-control) <br />
[Step 8: Deploy the Dashboard](#step-8-deploy-the-dashboard) <br />
[Step 9: Configure Email Notifications](#step-9-configure-email-notifications) <br />
[Step 10: Tag Applications for Auto-Rotation](#step-10-tag-applications-for-auto-rotation) <br />
[Step 11: Verify the Deployment](#step-11-verify-the-deployment) <br />
[Next Steps](#next-steps) <br />
[Troubleshooting](#troubleshooting) <br /> 
[Cleanup / Teardown](#cleanup--teardown)

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
Navigate to https://portal.azure.com/#cloudshell/
- Ensure you're in PowerShell
- Under **Settings** select **Go to Classic version** (Recommended)


### Clone from Git Repository
```powershell
# Clone the repository
git clone https://github.com/JeffBley/SamlCertRotation.git
Set-Location SamlCertRotation
```

### Verify Files Are Present

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


### Sync to the Latest Repository Version (Required)

Cloud Shell storage persists between sessions. Always sync to the latest code before building or deploying to avoid stale UI/API regressions.

```powershell
Set-Location "$HOME/SamlCertRotation"
git fetch origin
git pull origin main
```

---

## Step 2: Prepare Your Environment

### 2.1 Verify Azure CLI Login

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

### 2.2 Create Resource Group

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

## Step 4: Deploy Azure Infrastructure

### 4.1 Update Parameters File

Edit the parameters file with your values:

```powershell
Set-Location "$HOME/SamlCertRotation/infrastructure"

# Open in Cloud Shell editor
code main.parameters.json
```

Update these values:
- `tenantId`: Your Azure AD Tenant ID (run `az account show --query tenantId -o tsv` to get it)
- `adminNotificationEmails`: Admin emails (semicolon-separated)
- `customSecurityAttributeSet`: The Attribute Set you created in step 3
- `customSecurityAttributeName`: The Attribute Name you created in step 3

Save the file (Ctrl+S), then close the editor (Ctrl+Q).

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

> **Note**: If `Get-Content` showed no results, you most likely lost the variables set in Step 2.2. Ensure `$RESOURCE_GROUP` is populated and try 4.2 again.

### 4.3 Save Output Values as Variables (Re-runnable)

```powershell
# Re-run this block anytime (including after Cloud Shell session timeout)
# If deployment-outputs.json is missing/empty, it will pull outputs from the latest deployment.

Set-Location "$HOME/SamlCertRotation/infrastructure"

# Ensure resource group variable exists (set this to your RG if different)
if (-not $RESOURCE_GROUP) {
    $RESOURCE_GROUP = "rg-saml-cert-rotation"
}

$outputsPath = "deployment-outputs.json"
$outputs = $null

# Try loading outputs from file first
if (Test-Path $outputsPath) {
    $raw = Get-Content $outputsPath -Raw
    if (-not [string]::IsNullOrWhiteSpace($raw) -and $raw.Trim() -ne "null") {
        $outputs = $raw | ConvertFrom-Json
    }
}

# If file not usable, fetch outputs from latest deployment in the resource group
if (-not $outputs) {
    $latestDeploymentName = az deployment group list `
        --resource-group $RESOURCE_GROUP `
        --query "[?properties.provisioningState=='Succeeded'] | sort_by(@, &properties.timestamp) | [-1].name" `
        -o tsv

    if (-not $latestDeploymentName) {
        throw "No successful deployment found in resource group '$RESOURCE_GROUP'. Run Step 4.2 first."
    }

    $outputs = az deployment group show `
        --resource-group $RESOURCE_GROUP `
        --name $latestDeploymentName `
        --query "properties.outputs" `
        -o json | ConvertFrom-Json

    if (-not $outputs) {
        throw "Deployment outputs were empty for deployment '$latestDeploymentName'. Re-run Step 4.2."
    }

    # Rehydrate local file for future runs
    $outputs | ConvertTo-Json -Depth 20 | Out-File -FilePath $outputsPath -Encoding utf8
}

# Set variables
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

# Save this value for step 5.1
"MANAGED_IDENTITY_PRINCIPAL_ID: $MANAGED_IDENTITY_PRINCIPAL_ID"
```

---

## Step 5: Grant Microsoft Graph Permissions

The managed identity needs Microsoft Graph API permissions.

### 5.1 Grant Permissions via PowerShell
Switch to Windows PowerShell or Powershell 7+ and run the following:

```powershell
# Set variable
$MANAGED_IDENTITY_PRINCIPAL_ID = "<Insert MANAGED_IDENTITY_PRINCIPAL_ID from step 4.3>"

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

### 5.2 Assign Attribute Assignment Reader Role

The managed identity needs the **Attribute Assignment Reader** role to read custom security attribute values. This is a separate role from the Graph API permission.

> **Why both?** Microsoft requires two layers of authorization for custom security attributes:
> 1. Graph API permission (`CustomSecAttributeAssignment.Read.All`) - allows calling the API
> 2. Directory role (Attribute Assignment Reader) - allows reading the actual values

Switch back to the **Cloud Shell** and run the following:

```powershell
# Assign the Attribute Assignment Reader role to the managed identity
# This grants read access to custom security attributes on all objects

az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
    --headers "Content-Type=application/json" `
    --body "{`"principalId`":`"$MANAGED_IDENTITY_PRINCIPAL_ID`",`"roleDefinitionId`":`"ffd52fa5-98dc-465c-991d-fc073eb59f8f`",`"directoryScopeId`":`"/`"}"
```

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

### 6.2 Deploy to Azure Function App (Recommended, Reliable)

```powershell
# IMPORTANT: Publish from the project directory using Functions Core Tools.
# This avoids intermittent 404 regressions caused by config-zip package indexing issues.
Set-Location "$HOME/SamlCertRotation/src/SamlCertRotation"

# Ensure Functions Core Tools is available in Cloud Shell
func --version

# Deploy with explicit runtime
func azure functionapp publish $FUNCTION_APP_NAME --dotnet-isolated
```

### 6.3 Verify Function Indexing and Route Health

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

You should see functions listed including `CertificateChecker`, `GetDashboardStats`, `GetRoles`, etc. The route check should return `401` (authentication required). If you see `200`, Easy Auth is likely still enabled on the Function App — Step 7.11 disables it. A `404` indicates deployment or routing issues.


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

### 7.2 Configure App Roles in the App Registration

Configure the two app roles used by dashboard authorization.

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **App registrations**
3. Open the app registration created in Step 7.1 (`SAML Certificate Rotation Dashboard`)
4. Open **App roles** → **Create app role** and add:
    - **Display name**: `SAML Cert Rotation Admin`
    - **Allowed member types**: `Users/Groups`
    - **Value**: `SamlCertRotation.Admin`
    - **Description**: `Full dashboard access`
5. Create a second role:
    - **Display name**: `SAML Cert Rotation Reader`
    - **Allowed member types**: `Users/Groups`
    - **Value**: `SamlCertRotation.Reader`
    - **Description**: `Read-only dashboard access`

### 7.3 Create Service Principal (Enterprise App)
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
```

This step restricts dashboard access to specific users or groups. 

```powershell
# Enable "Assignment required" on the Enterprise Application
az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" `
    --body '{"appRoleAssignmentRequired": true}'
```

### 7.4 Grant Admin Consent for Microsoft Graph Permissions (Optional)

Grant admin consent for delegated Microsoft Graph permissions (`openid`, `profile`, `email`) used during SWA authentication. This avoids users seeing a consent prompt on first sign-in.

```powershell
# Grant admin consent for openid, profile, and email delegated permissions
# Microsoft Graph well-known AppId: 00000003-0000-0000-c000-000000000000
$GRAPH_SP_ID = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].id" -o tsv

# Permission IDs for openid, profile, email
$PERMISSIONS = @(
    @{ Id = "37f7f235-527c-4136-accd-4a02d197296e"; Name = "openid" },
    @{ Id = "14dad69e-099b-42c9-810b-d002981feec1"; Name = "profile" },
    @{ Id = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"; Name = "email" }
)

foreach ($perm in $PERMISSIONS) {
    $body = @{
        clientId = $SP_ID
        consentType = "AllPrincipals"
        resourceId = $GRAPH_SP_ID
        scope = $perm.Name
    } | ConvertTo-Json -Compress

    try {
        az rest --method POST --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" --headers "Content-Type=application/json" --body $body
        Write-Host "Granted admin consent: $($perm.Name)" -ForegroundColor Green
    } catch {
        Write-Host "Already granted or error: $($perm.Name)" -ForegroundColor Yellow
    }
}
```

> **Note**: If you skip this step, users will be prompted to consent to these permissions on their first sign-in. This is harmless but may confuse users.

### 7.5 Configure User/Group Assignment

Now assign users or groups to the application in the Entra Portal (assumes your group already exists):

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Applications** → **Enterprise applications**
3. Open your enterprise app (`SAML Certificate Rotation Dashboard`)
4. Go to **Users and groups** → **Add user/group**
5. Under **Users and groups**, select the existing user or group you want to grant access
6. Under **Select a role**, choose one:
   - `SAML Cert Rotation Admin` (`SamlCertRotation.Admin`) for full access
   - `SAML Cert Rotation Reader` (`SamlCertRotation.Reader`) for read-only access
7. Click **Assign**

> **Important**: Users who are not assigned to the Enterprise Application will receive an "Access Denied" error when trying to access the dashboard.

### 7.6 Create Client Secret

```powershell
# Create client secret (valid for 2 years)
$CLIENT_SECRET = az ad app credential reset `
    --id $CLIENT_ID `
    --display-name "SWA Auth Secret" `
    --years 2 `
    --query "password" -o tsv

Write-Host "Client secret generated successfully. Length: $($CLIENT_SECRET.Length)"
Write-Host "Client Secret: $CLIENT_SECRET"
Write-Host "IMPORTANT: Save this secret securely - it cannot be retrieved later!" -ForegroundColor Red
```

### 7.7 Store Client Secret in Key Vault

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

### 7.8 Enable Static Web App Managed Identity and Key Vault Access

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

### 7.9 Configure Static Web App and Function App Settings

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
Write-Host "NOTE: staticwebapp.config.json tenant replacement is performed in Step 8.2."

# Configure Function App role mapping used by GetRoles
az functionapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --settings "SWA_ADMIN_APP_ROLE=SamlCertRotation.Admin" "SWA_READER_APP_ROLE=SamlCertRotation.Reader"

# Verify role mapping settings exist on Function App
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[?name=='SWA_ADMIN_APP_ROLE' || name=='SWA_READER_APP_ROLE'].[name,value]" -o table
```

> **Important**: The `az staticwebapp appsettings set` command may display `null` for values due to security redaction. Use the `list` command to verify the settings were applied correctly.

```powershell
# Validation gate: these must be set before proceeding
az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.{AAD_CLIENT_ID:AAD_CLIENT_ID,AAD_CLIENT_SECRET:AAD_CLIENT_SECRET}" -o json
```

### 7.10 Link Function App to Static Web App

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

### 7.11 Disable Easy Auth on Function App

The `backends link` command above enables Easy Auth on the Function App. We need to **disable it** because authentication is handled by the Static Web App, not the Function App.

> **Important**: This step MUST run AFTER 7.10 (backend linking), otherwise the link command will re-enable Easy Auth.

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

### 7.12 Save Access Control Configuration

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
| `RotationSchedule` | Function App Settings | CRON expression for rotation checks (default: `0 0 6 * * *` = 6 AM UTC daily) |
| `appRoleAssignmentRequired` | Enterprise Application | `true` |
| Easy Auth | Function App | Disabled (Step 7.11) |
| `tenantId` | infrastructure/main.parameters.json | Your Azure AD Tenant ID |
| Tenant ID | staticwebapp.config.json (`__TENANT_ID__`) | Replaced during Step 8.2 |

> **SWA Token Trust**: When SWA forwards requests to the linked Function App backend, it includes a JWT in the `x-ms-auth-token` header. This token is issued by SWA itself (issuer = `https://<swa-hostname>/.auth`), **not** by Entra ID. The Function App trusts this token using the `SWA_DEFAULT_HOSTNAME` setting (set automatically by Bicep). If you add a custom domain, also set `SWA_HOSTNAME` to the custom domain so token validation works for both.

> **Note**: Only users or groups assigned to the Enterprise Application can access the dashboard. Users not assigned will see "Access Denied" from Azure AD before reaching the application.

> **Rotation Schedule**: You can customize when automatic certificate rotation runs by setting the `RotationSchedule` app setting in the Function App. The value must be a valid NCRONTAB expression. Common examples:
> - `0 0 6 * * *` - Daily at 6:00 AM UTC (default)
> - `0 0 */12 * * *` - Every 12 hours
> - `0 0 6 * * 1` - Every Monday at 6:00 AM UTC

> **Manual secret management**: This solution does not rotate dashboard client secrets automatically. Rotate in Entra ID on your schedule, update `SamlDashboardClientSecret` in Key Vault, and keep the SWA app setting as a Key Vault reference.

---

## Step 8: Deploy the Dashboard

### 8.1 Get Static Web App Deployment Token

```powershell
# Get deployment token
$SWA_TOKEN = az staticwebapp secrets list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.apiKey" -o tsv
```

### 8.2 Update Dashboard Configuration

```powershell
Set-Location "$HOME/SamlCertRotation/dashboard"

# Update staticwebapp.config.json with tenant ID from Step 7.9
$configContent = Get-Content staticwebapp.config.json -Raw
$configContent = $configContent -replace '__TENANT_ID__', $TENANT_ID
Set-Content -Path staticwebapp.config.json -Value $configContent
```
**NOTE**: API_BASE_URL in app.js should remain empty - the SWA backend link handles API routing


### 8.3 Deploy Dashboard

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

### 9.1 Configure Logic App with Office 365 Connector

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your resource group: `$RESOURCE_GROUP`
3. Find and open the Logic App: `$LOGIC_APP_NAME` (There should only be one Logic App)
4. Click **Logic app designer**

### 9.2 Configure the Logic App Email Connection

The Logic App was deployed with a **Send an email (V2)** action pre-configured. You need to authorize the email connection:

1. In the designer, click on the **Send an email (V2)** tile
2. Under **Parameters**, click **Change connection**
3. Click **Add new**
4. Sign in with the account whose email address will send the notifications (e.g., a shared mailbox or service account)
5. Click **Save** at the top of the designer

> **Note**: The account you sign in with will be the "From" address for all notification emails. Consider using a shared mailbox like `saml-notifications@yourdomain.com`.

### 9.3 Verify Logic App URL in Key Vault (Automatic)

The Bicep deployment automatically retrieves the Logic App callback URL (which contains a SAS token) and stores it as a Key Vault secret. The Function App reads it via a `@Microsoft.KeyVault()` reference — no manual configuration is needed.

To verify the secret was created:

```powershell
# Verify the Logic App URL secret exists in Key Vault
az keyvault secret show `
    --vault-name $KEY_VAULT_NAME `
    --name "LogicAppEmailUrl" `
    --query "{name:name, created:attributes.created}" -o table
```

To verify the Function App is using the Key Vault reference (not a plain-text URL):

```powershell
# Should return an @Microsoft.KeyVault(...) reference, NOT a plain-text URL
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[?name=='LogicAppEmailUrl'].value" -o tsv
```

> **Important**: Do NOT manually set `LogicAppEmailUrl` via `az functionapp config appsettings set`.
> This would overwrite the Key Vault reference with a plain-text URL containing a SAS token.

If you need to retrieve the Logic App URL for testing (Step 9.5), run:

```powershell
$LOGIC_APP_URL = az rest --method post `
    --uri "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Logic/workflows/$LOGIC_APP_NAME/triggers/manual/listCallbackUrl?api-version=2016-10-01" `
    --query "value" -o tsv
```

### 9.5 Test Email Notifications

You can test the Logic App directly:

> **Note**: Update the `to` field below with your actual email address to receive the test email.

```powershell
# Test sending an email (update the "to" address!)
$testPayload = @{
    to = "your-email@yourdomain.com"
    subject = "Test - SAML Certificate Rotation"
    body = "<html><body><h1>Test Email</h1><p>If you received this, email notifications are working!</p></body></html>"
} | ConvertTo-Json

Invoke-RestMethod -Uri $LOGIC_APP_URL -Method Post -Body $testPayload -ContentType "application/json"
```

---

## Step 10: Tag Applications for Auto-Rotation

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

---

## Step 11: Verify the Deployment

### 11.1 Verify Dashboard Access

1. Open the dashboard URL in your browser
2. Sign in with an account that is assigned to the Enterprise Application
3. Verify you can see the dashboard with application statistics

### 11.2 Verify SWA Role Enrichment

After sign-in, verify SWA is enriching roles via the auth metadata endpoint:

1. Open `https://<your-static-web-app-name>.azurestaticapps.net/.auth/me`
2. Confirm the `userRoles` array includes `admin` and/or `reader` in addition to `anonymous` and `authenticated`

## Next Steps

Now that deployment is complete, consider these optional enhancements:

### Manual Dashboard Secret Rotation Runbook

Use this runbook whenever you need to rotate the Microsoft Entra client secret for dashboard sign-in.

```powershell
# Prerequisites (from earlier steps)
# $RESOURCE_GROUP
# $STATIC_WEB_APP_NAME
# $KEY_VAULT_NAME

# 1) Get dashboard app registration client ID from SWA settings
$CLIENT_ID = az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.AAD_CLIENT_ID" -o tsv

Write-Host "Dashboard App Client ID: $CLIENT_ID"

# 2) Create a new Entra client secret (valid 2 years)
$NEW_CLIENT_SECRET = az ad app credential reset `
    --id $CLIENT_ID `
    --display-name "SWA Auth Secret" `
    --years 2 `
    --query "password" -o tsv

# 3) Store the new secret in Key Vault under the expected name
az keyvault secret set `
    --vault-name $KEY_VAULT_NAME `
    --name "SamlDashboardClientSecret" `
    --value $NEW_CLIENT_SECRET `
    --expires (Get-Date).AddYears(2).ToString("yyyy-MM-ddTHH:mm:ssZ") `
    --tags "CreatedBy=ManualRotation"

# 4) Verify SWA still points to Key Vault reference (not plaintext)
az staticwebapp appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.AAD_CLIENT_SECRET" -o tsv
```

Expected result for step 4:
- `AAD_CLIENT_SECRET` should be an `@Microsoft.KeyVault(...)` reference string.
- It should not be a plaintext secret value.

Recommended cadence:
- Rotate every 90-180 days, or per your security policy.
- Keep the previous secret briefly during cutover, then remove old credentials from the app registration after validation.

### Configure a Custom Domain

By default, your dashboard URL is auto-generated (e.g., `happy-island-01f529a0f.azurestaticapps.net`). To use a custom domain like `saml-dashboard.yourcompany.com`:

1. **Add the custom domain in Azure Portal:**
   - Go to your Static Web App → **Custom domains**
   - Click **Add**
   - Enter your domain (e.g., `saml-dashboard.yourcompany.com`)
   - Add the required DNS records (CNAME or TXT validation)
   - Azure provides a free SSL certificate automatically

2. **Or use Azure CLI:**
   ```bash
   az staticwebapp hostname set \
     --name <your-static-web-app-name> \
     --resource-group <your-resource-group> \
     --hostname saml-dashboard.yourcompany.com
   ```

3. **Update your App Registration:**
   - Go to **Microsoft Entra ID** → **App registrations** → your dashboard app
   - Click **Authentication**
   - Add a new redirect URI: `https://saml-dashboard.yourcompany.com/.auth/login/aad/callback`

> **Documentation:** [Set up a custom domain in Azure Static Web Apps](https://learn.microsoft.com/en-us/azure/static-web-apps/custom-domain)

### Customize the Rotation Schedule

The automatic certificate rotation check runs daily at 6:00 AM UTC by default. To change this:

1. Go to your **Function App** → **Settings** → **Environment variables**
2. Add or update the `RotationSchedule` setting with a CRON expression:
   - `0 0 6 * * *` - Daily at 6:00 AM UTC (default)
   - `0 0 */12 * * *` - Every 12 hours
   - `0 0 6 * * 1` - Every Monday at 6:00 AM UTC
3. **Restart the Function App** for changes to take effect

### Review Audit Logs

The dashboard records all certificate operations. Use the **Audit Logs** tab to:
- Track who rotated certificates and when
- Monitor automatic rotation events
- Troubleshoot failed operations

---

## Troubleshooting


### Dashboard shows 404 Not Found

This means the deployment didn't succeed or files weren't deployed correctly:

```powershell
# 1. Verify dist folder has the correct files
Set-Location "$HOME/SamlCertRotation/dashboard"
Get-ChildItem dist/

# Should show: index.html, app.js, staticwebapp.config.json, unauthorized.html, favicon.png

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
### 11.5 Access the Dashboard

Open your browser and navigate to:
```
https://<your-static-web-app-name>.azurestaticapps.net
```

---

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

# If CLI still fails, verify your deployment token and rerun Step 8.3
```

### SWA CLI "folder not found" error

Make sure to create the dist folder before deploying:

```powershell
Set-Location "$HOME/SamlCertRotation/dashboard"
New-Item -ItemType Directory -Path dist -Force
Copy-Item index.html dist/
Copy-Item app.js dist/
Copy-Item unauthorized.html dist/
Copy-Item favicon.png dist/
Copy-Item staticwebapp.config.json dist/
```

### npm warnings about deprecated packages

Warnings like "inflight@1.0.6 deprecated" come from the SWA CLI's dependencies.
These are safe to ignore - they don't affect functionality.

### Dashboard is missing expected controls or filters after deploy

This usually indicates stale source in Cloud Shell or a partial deployment.

```powershell
# 1) Sync Cloud Shell repo to the latest committed code
Set-Location "$HOME/SamlCertRotation"
git fetch origin
git pull origin main

# 2) Force redeploy Function App
Set-Location "$HOME/SamlCertRotation/src/SamlCertRotation"
func azure functionapp publish $FUNCTION_APP_NAME --dotnet-isolated --force

# 3) Rebuild and redeploy dashboard static content
Set-Location "$HOME/SamlCertRotation/dashboard"
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path dist -Force | Out-Null
Copy-Item index.html dist/
Copy-Item app.js dist/
Copy-Item unauthorized.html dist/
Copy-Item favicon.png dist/
Copy-Item staticwebapp.config.json dist/

$SWA_TOKEN = az staticwebapp secrets list `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    --query "properties.apiKey" -o tsv

npx -y @azure/static-web-apps-cli deploy ./dist `
    --deployment-token $SWA_TOKEN `
    --env production

# 4) Validate latest content is served
$SWA_HOST = az staticwebapp show --resource-group $RESOURCE_GROUP --name $STATIC_WEB_APP_NAME --query "defaultHostname" -o tsv
(Invoke-WebRequest "https://$SWA_HOST/index.html" -UseBasicParsing).Content | Select-String "Notify|Run - Report-only|Notification Settings|Reports|Testing|Overview"
```

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

### PowerShell parameter-file syntax (`az deployment`)

In Cloud Shell PowerShell, pass parameter files as a quoted literal to avoid `@` parsing errors:

```powershell
az deployment group what-if `
    --resource-group $RESOURCE_GROUP `
    --template-file main.bicep `
    --parameters "@main.parameters.json"
```

### Recover CLIENT_ID and Key Vault secret

If you lose these variables during Step 7:

```powershell
# Recover CLIENT_ID from the app registration
$APP_NAME = "SAML Certificate Rotation Dashboard"
$CLIENT_ID = az ad app list --filter "displayName eq '$APP_NAME'" --query "[0].appId" -o tsv
Write-Host "CLIENT_ID: $CLIENT_ID"

# Verify secret exists in Key Vault (value is redacted in command output)
az keyvault secret show --vault-name $KEY_VAULT_NAME --name "SamlDashboardClientSecret" --query "{name:name, expires:attributes.expires}" -o table

# If the secret is not in Key Vault, generate and store a new one:
# $NEW_CLIENT_SECRET = az ad app credential reset --id $CLIENT_ID --display-name "SWA Auth Secret" --years 2 --query "password" -o tsv
# az keyvault secret set --vault-name $KEY_VAULT_NAME --name "SamlDashboardClientSecret" --value $NEW_CLIENT_SECRET
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

### API returns 404 after redeploy

This usually means functions were not indexed in the host after deployment.

```powershell
# 1) Confirm function indexing
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[].name" -o table

# 2) If empty, re-publish with Functions Core Tools (do NOT use config-zip)
Set-Location "$HOME/SamlCertRotation/src/SamlCertRotation"
func azure functionapp publish $FUNCTION_APP_NAME --dotnet-isolated --force

# 3) Refresh host triggers
# func publish already syncs triggers in Cloud Shell
az functionapp restart --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
```

> **Important**: Avoid `az functionapp deployment source config-zip` for this project. Use `func azure functionapp publish --dotnet-isolated` to prevent recurring 404 regressions.

### 6.5 Repeatable One-Command Redeploy (Recommended for Ongoing Updates)

```powershell
Set-Location "$HOME/SamlCertRotation"
pwsh ./scripts/redeploy-functions.ps1 -FunctionAppName $FUNCTION_APP_NAME -ResourceGroup $RESOURCE_GROUP
```

### Dashboard shows no data

1. Check browser console (F12) for errors
2. Verify the SWA backend link was configured (Step 7.10)
3. Check that Easy Auth is disabled on the Function App (Step 7.11)
4. Ensure API_BASE_URL in app.js is empty (SWA backend handles routing)
5. Verify `https://<SWA_HOST>/api/GetRoles` is not 404 (302/200 is expected)

Compatibility note for backend inspection command:

```powershell
az staticwebapp backends show `
    --resource-group $RESOURCE_GROUP `
    --name $STATIC_WEB_APP_NAME `
    -o json
```

Some CLI builds do not support `az staticwebapp backends list`.

### Dashboard shows `API error: 401`

This usually means the API exists, but auth context is not reaching Functions correctly.

```powershell
# 1) Confirm function routes are indexed (must not be empty)
az functionapp function list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[].name" -o table

# 2) Re-link backend (safe/idempotent)
$FUNCTION_APP_ID = az functionapp show --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME --query id -o tsv
$FUNC_LOCATION = az functionapp show --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME --query location -o tsv
az staticwebapp backends link --resource-group $RESOURCE_GROUP --name $STATIC_WEB_APP_NAME --backend-resource-id $FUNCTION_APP_ID --backend-region $FUNC_LOCATION

# 3) Disable Easy Auth on Function App AFTER backend link
$SUBSCRIPTION_ID = az account show --query id -o tsv
az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-09-01" `
    --body '{"properties":{"platform":{"enabled":false},"globalValidation":{"requireAuthentication":false,"unauthenticatedClientAction":"AllowAnonymous"}}}'
```

Then sign out and sign back in at `https://<SWA_HOST>/.auth/login/aad` and retry `https://<SWA_HOST>/api/dashboard/stats`.

### Dashboard shows `API error: 403`

This usually means SWA role enrichment is not reaching the API.

```powershell
# Verify GetRoles is reachable through SWA (must not be 404)
# Replace <SWA_HOST> with your Static Web App hostname
Invoke-WebRequest "https://<SWA_HOST>/api/GetRoles" -UseBasicParsing

# Verify role mapping app settings on Function App
az functionapp config appsettings list `
    --resource-group $RESOURCE_GROUP `
    --name $FUNCTION_APP_NAME `
    --query "[?name=='SWA_ADMIN_APP_ROLE' || name=='SWA_READER_APP_ROLE'].[name,value]" -o table

# Assign current signed-in user to Reader app role (PowerShell-safe JSON body)
$CLIENT_ID = az staticwebapp appsettings list --resource-group $RESOURCE_GROUP --name $STATIC_WEB_APP_NAME --query "properties.AAD_CLIENT_ID" -o tsv
$SP_ID = az ad sp show --id $CLIENT_ID --query id -o tsv
$USER_ID = az ad signed-in-user show --query id -o tsv
$READER_ROLE_ID = az ad app show --id $CLIENT_ID --query "appRoles[?value=='SamlCertRotation.Reader'].id | [0]" -o tsv

$body = @{
    principalId = $USER_ID
    resourceId = $SP_ID
    appRoleId = $READER_ROLE_ID
} | ConvertTo-Json -Compress

az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" `
    --headers "Content-Type=application/json" `
    --body $body

# Sign out and sign back in so SWA receives updated role claims
# https://<SWA_HOST>/.auth/logout
```

Expected values:
- `SWA_ADMIN_APP_ROLE = SamlCertRotation.Admin`
- `SWA_READER_APP_ROLE = SamlCertRotation.Reader`

### API returns 400 Bad Request

This usually means Easy Auth is enabled on the Function App:

```powershell
# Check if Easy Auth is enabled (should return "false")
$SUBSCRIPTION_ID = az account show --query id -o tsv
az rest --method GET `
    --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-09-01" `
    --query "properties.platform.enabled"

# If it returns "true", disable it:
az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$FUNCTION_APP_NAME/config/authsettingsV2?api-version=2022-09-01" `
    --body '{"properties":{"platform":{"enabled":false},"globalValidation":{"unauthenticatedClientAction":"AllowAnonymous"}}}'
```

> **Note**: The `az staticwebapp backends link` command (Step 7.10) enables Easy Auth on the Function App. Step 7.11 must run AFTER to disable it.

### Dashboard shows "Unexpected token '<'" error

This typically means the API is returning HTML instead of JSON. Common causes:

1. **Easy Auth is enabled on Function App** - Disable it via Step 7.11
2. **SWA backend link not configured** - Run Step 7.10
3. **Missing exclude patterns in staticwebapp.config.json** - Ensure `/api/*` is in exclude list

### Dashboard shows "Access Denied" / User shows as "anonymous"

1. **Enterprise App assignment not configured** - Run Step 7.4 through 7.6
2. **User not assigned to the Enterprise App** - Add user/group via Azure Portal
3. **SWA app settings not configured** - Run Step 7.9

### Auto-rotate status shows as "Not Set" (null) for all apps

This means the managed identity can't read custom security attributes. You need BOTH:
1. Graph API permission (`CustomSecAttributeAssignment.Read.All`) - Step 5.2
2. Attribute Assignment Reader role - Step 5.4

Also verify these common pitfalls:

1. **Managed identity selection for Graph**
    - Ensure `AZURE_CLIENT_ID` is set on the Function App and points to your user-assigned identity.
    - If multiple identities exist, Graph calls can silently use the wrong identity if this is not configured.

2. **Graph application permissions**
    - In addition to `CustomSecAttributeAssignment.Read.All`, make sure `Application.Read.All` is assigned on Microsoft Graph.
    - `Application.ReadWrite.All` is not always sufficient for all read query paths.

3. **Attribute set and key mapping**
    - Ensure Function App settings match your actual CSA payload exactly:
      - `CustomSecurityAttributeSet` (for example: `Applications`)
      - `CustomSecurityAttributeName` (for example: `SamlCertRotation`)
    - Verify by querying Graph directly:

```powershell
$targetSpId = "<SERVICE_PRINCIPAL_OBJECT_ID>"
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${targetSpId}?`$select=id,displayName,customSecurityAttributes" | ConvertTo-Json -Depth 20
```

4. **Token refresh after permission/role updates**
    - After assigning new Graph permissions or Entra roles, restart the Function App and wait for propagation.

```powershell
# Check if the role is assigned
az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$MANAGED_IDENTITY_PRINCIPAL_ID'&`$expand=roleDefinition" `
    --query "value[].{role:roleDefinition.displayName, scope:directoryScopeId}" -o table

# If "Attribute Assignment Reader" is not listed, assign it:
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
    --headers "Content-Type=application/json" `
    --body "{`"principalId`":`"$MANAGED_IDENTITY_PRINCIPAL_ID`",`"roleDefinitionId`":`"ffd52fa5-98dc-465c-991d-fc073eb59f8f`",`"directoryScopeId`":`"/`"}"

# Restart the Function App to refresh tokens
az functionapp stop --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
Start-Sleep -Seconds 30
az functionapp start --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
```

> **Note**: Entra ID role assignments can take up to 1 hour to propagate. If you just assigned the role, wait and try again.

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
}

# Delete the App Registration (also deletes the Service Principal)
if ($CLIENT_ID) {
    az ad app delete --id $CLIENT_ID
    Write-Host "Deleted App Registration: $CLIENT_ID"
}

# Delete the Security Group (optional - only if you created one manually)
# $GROUP_ID = "<your-group-object-id>"
# az ad group delete --group $GROUP_ID
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
5. Review run reports in the Reports tab for historical rotation trends
6. Use the Testing tab to verify email delivery and preview notification templates
