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
var shortSuffix = substring(uniqueSuffix, 0, 8)
var storageAccountName = toLower('${baseName}${uniqueSuffix}')
var functionAppName = '${baseName}-func-${uniqueSuffix}'
var appServicePlanName = '${baseName}-plan-${uniqueSuffix}'
var appInsightsName = '${baseName}-insights-${uniqueSuffix}'
var logAnalyticsName = '${baseName}-logs-${uniqueSuffix}'
var managedIdentityName = '${baseName}-identity'
var staticWebAppName = '${baseName}-dashboard-${uniqueSuffix}'
var keyVaultName = '${baseName}kv${shortSuffix}'
var logicAppName = '${baseName}-email-${uniqueSuffix}'

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
// Key Vault
// ============================================================================
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Secrets'
  }
}

// Key Vault Secrets Officer role for managed identity
// This allows the function app to read and write secrets
resource keyVaultSecretsOfficerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, managedIdentity.id, 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  scope: keyVault
  properties: {
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7') // Key Vault Secrets Officer
  }
}

// Key Vault secret for Logic App callback URL (contains SAS token)
resource logicAppEmailUrlSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'LogicAppEmailUrl'
  properties: {
    value: listCallbackUrl('${logicApp.id}/triggers/manual', '2019-05-01').value
  }
  dependsOn: [
    keyVaultSecretsOfficerRole
  ]
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
// Log Analytics Workspace
// ============================================================================
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Monitoring'
  }
}

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
    WorkspaceResourceId: logAnalyticsWorkspace.id
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
    keyVaultReferenceIdentity: managedIdentity.id
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
        {
          name: 'RotationSchedule'
          value: '0 0 6 * * *'
        }
        {
          name: 'LogicAppEmailUrl'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=LogicAppEmailUrl)'
        }
        {
          name: 'KeyVaultUri'
          value: keyVault.properties.vaultUri
        }
        {
          name: 'SubscriptionId'
          value: subscription().subscriptionId
        }
        {
          name: 'SwaResourceGroup'
          value: resourceGroup().name
        }
        {
          name: 'SwaName'
          value: staticWebAppName
        }
        {
          name: 'SWA_DEFAULT_HOSTNAME'
          value: staticWebApp.properties.defaultHostname
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
    name: 'Standard'
    tier: 'Standard'
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

// Contributor role for managed identity on SWA (allows updating app settings)
resource swaContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(staticWebApp.id, managedIdentity.id, 'b24988ac-6180-42a0-ab88-20f7382dd24c')
  scope: staticWebApp
  properties: {
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c') // Contributor
  }
}

// ============================================================================
// Logic App API Connection (Office 365 Outlook)
// ============================================================================
resource office365Connection 'Microsoft.Web/connections@2016-06-01' = {
  name: '${baseName}-office365'
  location: location
  properties: {
    displayName: 'Office 365 Outlook - SAML Cert Rotation'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
    }
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Email Notifications'
  }
}

// ============================================================================
// Logic App (Email Notifications)
// ============================================================================
resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        manual: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              properties: {
                to: {
                  type: 'string'
                  description: 'Recipient email address(es), semicolon-separated'
                }
                subject: {
                  type: 'string'
                  description: 'Email subject'
                }
                body: {
                  type: 'string'
                  description: 'Email body (HTML supported)'
                }
              }
              required: [
                'to'
                'subject'
                'body'
              ]
            }
          }
        }
      }
      actions: {
        Send_an_email_V2: {
          type: 'ApiConnection'
          runAfter: {}
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/v2/Mail'
            body: {
              To: '@triggerBody()?[\'to\']'
              Subject: '@triggerBody()?[\'subject\']'
              Body: '<p>@{triggerBody()?[\'body\']}</p>'
              Importance: 'Normal'
            }
          }
        }
        Response: {
          type: 'Response'
          kind: 'Http'
          runAfter: {
            Send_an_email_V2: [
              'Succeeded'
            ]
          }
          inputs: {
            statusCode: 200
            body: {
              status: 'sent'
            }
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          office365: {
            connectionId: office365Connection.id
            connectionName: office365Connection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
          }
        }
      }
    }
  }
  tags: {
    purpose: 'SAML Certificate Rotation Tool'
    component: 'Email Notifications'
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
output logAnalyticsWorkspaceName string = logAnalyticsWorkspace.name
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output logicAppName string = logicApp.name
output apiConnectionName string = office365Connection.name

// Output instructions
output nextSteps string = '''
========================================
NEXT STEPS
========================================
1. Grant Microsoft Graph API permissions to the Managed Identity
2. Create Custom Security Attributes in Entra ID
3. Authorize the Office 365 API Connection (Portal: Edit API connection → Authorize)
4. Deploy the Function App code
5. Deploy the Dashboard to Static Web App
6. Configure Dashboard Access Control

See DEPLOYMENT_GUIDE.md for detailed instructions.
'''
