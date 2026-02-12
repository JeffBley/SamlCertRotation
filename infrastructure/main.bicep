// ============================================================================
// SAML Certificate Rotation Tool - Main Bicep Template
// ============================================================================
// This template deploys:
// - User-Assigned Managed Identity
// - Storage Account (for Function App and Table Storage)
// - Application Insights
// - App Service Plan (Consumption)
// - Azure Function App
// - Static Web App (for Dashboard)
// ============================================================================

@description('The base name for all resources. Must be globally unique for storage account.')
@minLength(3)
@maxLength(11)
param baseName string

@description('The Azure region for all resources')
param location string = resourceGroup().location

@description('The tenant ID for Microsoft Entra ID')
param tenantId string = subscription().tenantId

@description('Email address to send notifications from (must be a valid mailbox)')
param notificationSenderEmail string

@description('Admin email addresses for daily summaries (semicolon-separated)')
param adminNotificationEmails string = ''

@description('Custom Security Attribute Set name')
param customSecurityAttributeSet string = 'SamlCertRotation'

@description('Custom Security Attribute name within the set')
param customSecurityAttributeName string = 'AutoRotate'

@description('Default days before expiry to create new certificate')
param defaultCreateCertDays int = 60

@description('Default days before expiry to activate new certificate')
param defaultActivateCertDays int = 30

// Variables
var uniqueSuffix = uniqueString(resourceGroup().id)
var storageAccountName = toLower('${baseName}${uniqueSuffix}')
var functionAppName = '${baseName}-func-${uniqueSuffix}'
var appServicePlanName = '${baseName}-plan-${uniqueSuffix}'
var appInsightsName = '${baseName}-insights-${uniqueSuffix}'
var managedIdentityName = '${baseName}-identity'
var staticWebAppName = '${baseName}-dashboard-${uniqueSuffix}'

// ============================================================================
// User-Assigned Managed Identity
// ============================================================================
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Identity'
  }
}

// ============================================================================
// Storage Account
// ============================================================================
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    accessTier: 'Hot'
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Storage'
  }
}

// Get storage account connection string
var storageConnectionString = 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'

// ============================================================================
// Application Insights
// ============================================================================
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Request_Source: 'rest'
    RetentionInDays: 90
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Monitoring'
  }
}

// ============================================================================
// App Service Plan (Consumption)
// ============================================================================
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
    size: 'Y1'
    family: 'Y'
    capacity: 0
  }
  kind: 'functionapp'
  properties: {
    reserved: false
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Hosting'
  }
}

// ============================================================================
// Azure Function App
// ============================================================================
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      netFrameworkVersion: 'v8.0'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      cors: {
        allowedOrigins: [
          'https://${staticWebAppName}.azurestaticapps.net'
        ]
        supportCredentials: false
      }
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: storageConnectionString
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: storageConnectionString
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'dotnet-isolated'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'AZURE_CLIENT_ID'
          value: managedIdentity.properties.clientId
        }
        {
          name: 'StorageConnectionString'
          value: storageConnectionString
        }
        {
          name: 'TenantId'
          value: tenantId
        }
        {
          name: 'NotificationSenderEmail'
          value: notificationSenderEmail
        }
        {
          name: 'AdminNotificationEmails'
          value: adminNotificationEmails
        }
        {
          name: 'CustomSecurityAttributeSet'
          value: customSecurityAttributeSet
        }
        {
          name: 'CustomSecurityAttributeName'
          value: customSecurityAttributeName
        }
        {
          name: 'DefaultCreateCertDaysBeforeExpiry'
          value: string(defaultCreateCertDays)
        }
        {
          name: 'DefaultActivateCertDaysBeforeExpiry'
          value: string(defaultActivateCertDays)
        }
      ]
    }
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Function App'
  }
}

// ============================================================================
// Static Web App (Dashboard)
// ============================================================================
resource staticWebApp 'Microsoft.Web/staticSites@2023-01-01' = {
  name: staticWebAppName
  location: 'eastus2' // Static Web Apps have limited region availability
  sku: {
    name: 'Free'
    tier: 'Free'
  }
  properties: {
    stagingEnvironmentPolicy: 'Enabled'
    allowConfigFileUpdates: true
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Dashboard'
  }
}

// ============================================================================
// Outputs
// ============================================================================
output managedIdentityPrincipalId string = managedIdentity.properties.principalId
output managedIdentityClientId string = managedIdentity.properties.clientId
output managedIdentityName string = managedIdentity.name
output functionAppName string = functionApp.name
output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'
output staticWebAppName string = staticWebApp.name
output staticWebAppUrl string = 'https://${staticWebApp.properties.defaultHostname}'
output storageAccountName string = storageAccount.name
output appInsightsName string = appInsights.name

// Output instructions
output nextSteps string = '''
========================================
NEXT STEPS
========================================
1. Grant Microsoft Graph API permissions to the Managed Identity
2. Create Custom Security Attributes in Entra ID
3. Deploy the Function App code
4. Deploy the Dashboard to Static Web App
5. Configure notification sender mailbox

See DEPLOYMENT_GUIDE.md for detailed instructions.
'''
