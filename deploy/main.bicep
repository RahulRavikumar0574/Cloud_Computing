@description('Location for all resources')
param location string = resourceGroup().location

@description('Prefix for resource names')
param prefix string = 'cloudsec'

@description('Environment name (e.g. staging, prod)')
param environment string = 'prod'

@description('Container image tag')
param imageTag string = 'latest'

@description('Whether to deploy Container App resource. Set false during stage 1 to provision ACR before image build.')
param deployContainerApp bool = true

var uniqueSuffix = substring(uniqueString(resourceGroup().id), 0, 6)
var acrName = replace('${prefix}acr${uniqueSuffix}', '-', '')
var storageAccountName = replace('${prefix}sa${uniqueSuffix}', '-', '')
var logAnalyticsName = '${prefix}-law-${environment}'
var containerAppEnvName = '${prefix}-cae-${environment}'
var containerAppName = '${prefix}-api-${environment}'
var eventGridTopicName = '${prefix}-egt-${environment}'

// 1. Azure Container Registry (Admin credentials disabled, using Managed Identity)
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

// 2. Azure Storage Account (Data Plane for telemetry & alerts)
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
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
}

resource ingressContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'ingress-telemetry'
}

resource egressContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'egress-alerts'
}

// 3. Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// 4. Azure Event Grid Topic
resource eventGridTopic 'Microsoft.EventGrid/topics@2023-12-15-preview' = {
  name: eventGridTopicName
  location: location
  properties: {
    inputSchema: 'EventGridSchema'
    publicNetworkAccess: 'Enabled'
  }
}

// 5. Container Apps Managed Environment
resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: containerAppEnvName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// 6. Container App (FastAPI Security Engine) - Authenticates to ACR via System-Assigned Managed Identity
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = if (deployContainerApp) {
  name: containerAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: 'system'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'cloud-sec-api'
          image: '${acr.properties.loginServer}/cloud-sec-api:${imageTag}'
          resources: {
            cpu: json('1.0')
            memory: '2.0Gi'
          }
          env: [
            {
              name: 'ARTIFACTS_DIR'
              value: '/app/artifacts'
            }
            {
              name: 'AZURE_STORAGE_ACCOUNT_URL'
              value: storageAccount.properties.primaryEndpoints.blob
            }
            {
              name: 'EVENT_GRID_TOPIC_ENDPOINT'
              value: eventGridTopic.properties.endpoint
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/ready'
                port: 8000
              }
              periodSeconds: 15
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// Role Assignments for Container App System-Assigned Managed Identity

// AcrPull role: 7f951dda-4ed3-4680-a7ca-43fe172d538d (Allows Container App to pull image without passwords)
resource acrPullRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployContainerApp) {
  name: guid(acr.id, containerAppName, 'AcrPull')
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: deployContainerApp ? containerApp.identity.principalId : ''
    principalType: 'ServicePrincipal'
  }
}

// Storage Blob Data Contributor: ba92f5b4-2d11-453d-a403-e96b0029c9fe
resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployContainerApp) {
  name: guid(storageAccount.id, containerAppName, 'StorageBlobDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: deployContainerApp ? containerApp.identity.principalId : ''
    principalType: 'ServicePrincipal'
  }
}

// EventGrid Data Sender: d5a91429-5739-47e0-306b-3470040c5e7b
resource eventGridRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployContainerApp) {
  name: guid(eventGridTopic.id, containerAppName, 'EventGridDataSender')
  scope: eventGridTopic
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'd5a91429-5739-47e0-306b-3470040c5e7b')
    principalId: deployContainerApp ? containerApp.identity.principalId : ''
    principalType: 'ServicePrincipal'
  }
}

output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output storageAccountName string = storageAccount.name
output eventGridTopicEndpoint string = eventGridTopic.properties.endpoint
output apiEndpoint string = deployContainerApp ? 'https://${containerApp.properties.configuration.ingress.fqdn}' : ''
