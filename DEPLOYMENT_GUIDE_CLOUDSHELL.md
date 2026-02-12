# SAML Certificate Rotation Tool - Azure Cloud Shell Deployment Guide

This guide walks you through deploying the SAML Certificate Rotation Tool using **Azure Cloud Shell**.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Upload Project to Cloud Shell](#step-1-upload-project-to-cloud-shell)
3. [Step 2: Prepare Your Environment](#step-2-prepare-your-environment)
4. [Step 3: Create Custom Security Attributes](#step-3-create-custom-security-attributes)
5. [Step 4: Deploy Azure Infrastructure](#step-4-deploy-azure-infrastructure)
6. [Step 5: Grant Microsoft Graph Permissions](#step-5-grant-microsoft-graph-permissions)
7. [Step 6: Deploy the Function App Code](#step-6-deploy-the-function-app-code)
8. [Step 7: Deploy the Dashboard](#step-7-deploy-the-dashboard)
9. [Step 8: Configure Email Notifications](#step-8-configure-email-notifications)
10. [Step 9: Tag Applications for Auto-Rotation](#step-9-tag-applications-for-auto-rotation)
11. [Step 10: Verify the Deployment](#step-10-verify-the-deployment)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- [ ] **Azure Subscription** with Owner or Contributor role
- [ ] **Microsoft Entra ID** with one of:
  - Global Administrator role, OR
  - Application Administrator + Attribute Definition Administrator roles
- [ ] Access to **Azure Cloud Shell** (https://shell.azure.com)

> **Note**: Azure Cloud Shell already has Azure CLI, .NET SDK, and Node.js pre-installed.

---

## Step 1: Upload Project to Cloud Shell

### Option A: Clone from Git Repository (Recommended)

If you have the project in a Git repository:

```bash
# Clone your repository
git clone https://github.com/YOUR_ORG/saml-cert-rotation.git
cd saml-cert-rotation
```

### Option B: Upload ZIP File

1. On your local machine, zip the entire project folder
2. In Cloud Shell, click the **Upload/Download files** button (up/down arrow icon)
3. Select **Upload** and choose your zip file
4. Extract in Cloud Shell:

```bash
# Create project directory
mkdir -p ~/saml-cert-rotation
cd ~/saml-cert-rotation

# Unzip (file will be in your home directory after upload)
unzip ~/SamlCertRotation.zip -d .

# If files are in a subfolder, move them up
# ls to check structure, then adjust as needed
```

### Option C: Upload Individual Files via Cloud Shell Editor

1. In Cloud Shell, click the **Editor** button (curly braces icon `{}`)
2. Create the folder structure manually
3. Copy/paste file contents from your local machine

### Verify Files Are Present

```bash
# Navigate to project root and verify structure
cd ~/saml-cert-rotation
ls -la

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

```bash
# Check current subscription
az account show --query "{Name:name, SubscriptionId:id}" -o table

# If you need to change subscription:
az account list --output table
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
```

### 2.2 Set Environment Variables

```bash
# Set variables (modify as needed)
export RESOURCE_GROUP="rg-saml-cert-rotation"
export LOCATION="eastus"

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

```bash
cd ~/saml-cert-rotation/infrastructure

# Open in Cloud Shell editor
code main.parameters.json
```

Update these values:
- `notificationSenderEmail`: Your notification sender email
- `adminNotificationEmails`: Admin emails (semicolon-separated)

Save the file (Ctrl+S) and close the editor.

### 4.2 Deploy Infrastructure with Bicep

```bash
# Make sure you're in the infrastructure directory
cd ~/saml-cert-rotation/infrastructure

# Deploy the infrastructure
az deployment group create \
    --resource-group $RESOURCE_GROUP \
    --template-file main.bicep \
    --parameters main.parameters.json \
    --query "properties.outputs" \
    -o json > deployment-outputs.json

# View the outputs
cat deployment-outputs.json | jq .
```

### 4.3 Save Output Values as Environment Variables

```bash
# Parse outputs and set as environment variables
export MANAGED_IDENTITY_PRINCIPAL_ID=$(cat deployment-outputs.json | jq -r '.managedIdentityPrincipalId.value')
export MANAGED_IDENTITY_CLIENT_ID=$(cat deployment-outputs.json | jq -r '.managedIdentityClientId.value')
export MANAGED_IDENTITY_NAME=$(cat deployment-outputs.json | jq -r '.managedIdentityName.value')
export FUNCTION_APP_NAME=$(cat deployment-outputs.json | jq -r '.functionAppName.value')
export FUNCTION_APP_URL=$(cat deployment-outputs.json | jq -r '.functionAppUrl.value')
export STATIC_WEB_APP_NAME=$(cat deployment-outputs.json | jq -r '.staticWebAppName.value')
export STORAGE_ACCOUNT_NAME=$(cat deployment-outputs.json | jq -r '.storageAccountName.value')

# Verify variables are set
echo "Managed Identity Principal ID: $MANAGED_IDENTITY_PRINCIPAL_ID"
echo "Managed Identity Name: $MANAGED_IDENTITY_NAME"
echo "Function App: $FUNCTION_APP_NAME"
echo "Function App URL: $FUNCTION_APP_URL"
echo "Static Web App: $STATIC_WEB_APP_NAME"
```

> **Important**: Save these values! If your Cloud Shell session times out, you'll need to re-run the export commands or retrieve values from the Azure Portal.

---

## Step 5: Grant Microsoft Graph Permissions

The managed identity needs Microsoft Graph API permissions. This is easiest to do via the Azure Portal.

### 5.1 Grant Permissions via Azure Portal

1. Go to [Azure Portal](https://portal.azure.com)
2. Search for **Enterprise applications**
3. Change the **Application type** filter to **Managed Identities**
4. Search for your managed identity name (the value from `$MANAGED_IDENTITY_NAME`)
5. Click on the managed identity
6. Go to **Permissions** in the left menu
7. Click **Grant admin consent for [your tenant]** if available

If permissions aren't listed, you need to add them via PowerShell:

### 5.2 Grant Permissions via Cloud Shell (PowerShell)

```bash
# Switch to PowerShell in Cloud Shell
pwsh
```

Then run in PowerShell:

```powershell
# Install Microsoft Graph module if needed
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Connect to Microsoft Graph (will open browser for auth)
Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"

# Set the managed identity principal ID (copy from earlier output)
$managedIdentityPrincipalId = $env:MANAGED_IDENTITY_PRINCIPAL_ID

# Get the managed identity service principal
$managedIdentitySP = Get-MgServicePrincipal -ServicePrincipalId $managedIdentityPrincipalId

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

# Exit PowerShell to return to bash
exit
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

```bash
# Return to bash if still in PowerShell
# Navigate to project root
cd ~/saml-cert-rotation

# Restore and build
dotnet restore src/SamlCertRotation/SamlCertRotation.csproj
dotnet build src/SamlCertRotation/SamlCertRotation.csproj --configuration Release

# Publish
dotnet publish src/SamlCertRotation/SamlCertRotation.csproj \
    --configuration Release \
    --output ./publish
```

### 6.2 Create Deployment Package

```bash
# Create zip file for deployment
cd ~/saml-cert-rotation/publish
zip -r ../function-app.zip .
cd ~/saml-cert-rotation
```

### 6.3 Deploy to Azure Function App

```bash
# Deploy the zip package
az functionapp deployment source config-zip \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME \
    --src function-app.zip

# Verify deployment - list functions
az functionapp function list \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME \
    --output table
```

You should see `CertificateChecker` and several `Dashboard*` functions listed.

---

## Step 7: Deploy the Dashboard

### 7.1 Get Static Web App Deployment Token

```bash
# Get deployment token
export SWA_TOKEN=$(az staticwebapp secrets list \
    --resource-group $RESOURCE_GROUP \
    --name $STATIC_WEB_APP_NAME \
    --query "properties.apiKey" -o tsv)

echo "Deployment token retrieved"
```

### 7.2 Update Dashboard Configuration

```bash
cd ~/saml-cert-rotation/dashboard

# Get your tenant ID
export TENANT_ID=$(az account show --query tenantId -o tsv)

# Update the staticwebapp.config.json with your tenant ID
sed -i "s/<YOUR_TENANT_ID>/$TENANT_ID/g" staticwebapp.config.json

# Update the API endpoint in index.html
sed -i "s|const API_BASE_URL = ''|const API_BASE_URL = '$FUNCTION_APP_URL'|g" index.html
```

### 7.3 Install SWA CLI and Deploy

```bash
# Install Static Web Apps CLI
npm install -g @azure/static-web-apps-cli

# Build dashboard (simple HTML, just needs to be in dist folder)
mkdir -p dist
cp index.html dist/
cp staticwebapp.config.json dist/

# Deploy
swa deploy ./dist \
    --deployment-token $SWA_TOKEN \
    --env production
```

### 7.4 Get Dashboard URL

```bash
# Get the Static Web App URL
az staticwebapp show \
    --resource-group $RESOURCE_GROUP \
    --name $STATIC_WEB_APP_NAME \
    --query "defaultHostname" -o tsv
```

---

## Step 8: Configure Email Notifications

### Option A: Use a Shared Mailbox (Recommended)

1. Go to [Microsoft 365 Admin Center](https://admin.microsoft.com)
2. Create a shared mailbox (e.g., `saml-rotation@yourdomain.com`)
3. The `Mail.Send` permission allows the managed identity to send as this mailbox

### Option B: Update Function App Settings

If you need to change the notification sender email:

```bash
az functionapp config appsettings set \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME \
    --settings "NotificationSenderEmail=your-sender@yourdomain.com"
```

---

## Step 9: Tag Applications for Auto-Rotation

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

### Via PowerShell in Cloud Shell

```bash
pwsh
```

```powershell
# Connect to Graph
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

exit
```

---

## Step 10: Verify the Deployment

### 10.1 Test the Function App API

```bash
# Get Function App key
FUNCTION_KEY=$(az functionapp keys list \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME \
    --query "functionKeys.default" -o tsv)

# Test dashboard stats endpoint
curl -s "$FUNCTION_APP_URL/api/dashboard/stats?code=$FUNCTION_KEY" | jq .
```

### 10.2 Manually Trigger Rotation

```bash
# Trigger manual rotation
curl -s -X POST "$FUNCTION_APP_URL/api/admin/trigger-rotation?code=$FUNCTION_KEY" | jq .
```

### 10.3 View Function Logs

```bash
# Stream logs (Ctrl+C to stop)
az functionapp log tail \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME
```

### 10.4 Access the Dashboard

Open your browser and navigate to:
```
https://<your-static-web-app-name>.azurestaticapps.net
```

---

## Troubleshooting

### "Permission denied" or "Insufficient privileges"

- Verify Graph API permissions were granted to the managed identity
- Check that admin consent was provided
- Wait 5-10 minutes for permissions to propagate

### Environment variables lost

Cloud Shell sessions timeout after ~20 minutes of inactivity. Re-run:

```bash
cd ~/saml-cert-rotation/infrastructure
export RESOURCE_GROUP="rg-saml-cert-rotation"
export FUNCTION_APP_NAME=$(cat deployment-outputs.json | jq -r '.functionAppName.value')
export FUNCTION_APP_URL=$(cat deployment-outputs.json | jq -r '.functionAppUrl.value')
# ... etc
```

### Function not triggering

```bash
# Check if functions are deployed
az functionapp function list \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME \
    --output table

# Check application settings
az functionapp config appsettings list \
    --resource-group $RESOURCE_GROUP \
    --name $FUNCTION_APP_NAME \
    --output table
```

### Dashboard shows no data

1. Verify CORS is configured on the Function App to allow your Static Web App URL
2. Check browser console (F12) for errors
3. Verify the API_BASE_URL in index.html is correct

---

## Quick Reference: Key Commands

```bash
# Re-export variables after session timeout
cd ~/saml-cert-rotation/infrastructure
export RESOURCE_GROUP="rg-saml-cert-rotation"
export FUNCTION_APP_NAME=$(cat deployment-outputs.json | jq -r '.functionAppName.value')
export FUNCTION_APP_URL=$(cat deployment-outputs.json | jq -r '.functionAppUrl.value')
export STATIC_WEB_APP_NAME=$(cat deployment-outputs.json | jq -r '.staticWebAppName.value')
export MANAGED_IDENTITY_PRINCIPAL_ID=$(cat deployment-outputs.json | jq -r '.managedIdentityPrincipalId.value')

# Test API
FUNCTION_KEY=$(az functionapp keys list --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME --query "functionKeys.default" -o tsv)
curl -s "$FUNCTION_APP_URL/api/dashboard/stats?code=$FUNCTION_KEY" | jq .

# View logs
az functionapp log tail --resource-group $RESOURCE_GROUP --name $FUNCTION_APP_NAME
```

---

## Next Steps

1. Monitor the dashboard for certificate expiration status
2. Review audit logs periodically
3. Adjust rotation policies as needed via the dashboard
4. Tag additional SAML applications with `AutoRotate=on` as desired
