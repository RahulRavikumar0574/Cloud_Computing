<#
.SYNOPSIS
    Azure Deployment Automation Script for Cloud-Native Container Security Engine (PowerShell).

.DESCRIPTION
    Provisions Azure Infrastructure (ACR, Storage, Event Grid, Container Apps), builds the
    container image in ACR, and deploys the hardened FastAPI detection engine using Managed Identity.

.PARAMETER ResourceGroup
    Target Azure Resource Group name. Default: rg-container-security
.PARAMETER Location
    Azure region. Default: eastus
.PARAMETER Prefix
    Naming prefix for resources. Default: cloudsec
.PARAMETER Environment
    Environment name. Default: prod
.PARAMETER ImageTag
    Docker image tag. Default: latest
#>

[CmdletBinding()]
param(
    [string]$ResourceGroup = "rg-container-security",
    [string]$Location = "eastus",
    [string]$Prefix = "cloudsec",
    [string]$Environment = "prod",
    [string]$ImageTag = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Azure Cloud-Native Container Security Deployment ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Location:       $Location"
Write-Host "Prefix:         $Prefix"
Write-Host "Environment:    $Environment"
Write-Host "Image Tag:      $ImageTag"

# Check Azure CLI availability
$azCmd = Get-Command az -ErrorAction SilentlyContinue
if (-not $azCmd) {
    Write-Error "Azure CLI ('az') is not installed or not in PATH. Please install Azure CLI from: https://learn.microsoft.com/cli/azure/install-azure-cli"
    exit 1
}

# Check Azure Authentication
Write-Host "Checking Azure authentication..." -ForegroundColor Yellow
$account = az account show --output json 2>$null
if (-not $account) {
    Write-Error "Not logged in to Azure. Please run 'az login' first."
    exit 1
}

# 1. Create Resource Group if not exists
Write-Host "[1/5] Ensuring Resource Group exists..." -ForegroundColor Cyan
az group create --name $ResourceGroup --location $Location --output table

# 2. Stage 1: Deploy base infrastructure (ACR, Storage, Log Analytics, Event Grid)
# deployContainerApp=false ensures ACR exists before attempting to pull image
Write-Host "[2/5] Deploying Base Infrastructure (ACR, Storage, Event Grid, CAE)..." -ForegroundColor Cyan
az deployment group create `
    --resource-group $ResourceGroup `
    --name "cloudsec-infra-base" `
    --template-file "deploy/main.bicep" `
    --parameters prefix=$Prefix environment=$Environment deployContainerApp=false `
    --output table

# 3. Retrieve ACR Resource Name and details via native TSV queries
Write-Host "[3/5] Retrieving infrastructure configuration..." -ForegroundColor Cyan
$AcrName = (az deployment group show --resource-group $ResourceGroup --name "cloudsec-infra-base" --query "properties.outputs.acrName.value" -o tsv).Trim()
$AcrServer = (az deployment group show --resource-group $ResourceGroup --name "cloudsec-infra-base" --query "properties.outputs.acrLoginServer.value" -o tsv).Trim()
$StorageAccount = (az deployment group show --resource-group $ResourceGroup --name "cloudsec-infra-base" --query "properties.outputs.storageAccountName.value" -o tsv).Trim()
$EventGrid = (az deployment group show --resource-group $ResourceGroup --name "cloudsec-infra-base" --query "properties.outputs.eventGridTopicEndpoint.value" -o tsv).Trim()

Write-Host "ACR Resource Name: $AcrName"
Write-Host "ACR Login Server:  $AcrServer"

# 4. Build and push image into ACR using cloud build
Write-Host "[4/5] Building Docker container image in ACR: $AcrName..." -ForegroundColor Cyan
az acr build `
    --registry $AcrName `
    --image "cloud-sec-api:$ImageTag" `
    --file "cloud/Dockerfile" .

# 5. Stage 2: Deploy Container App & configure Managed Identity role assignments
Write-Host "[5/5] Deploying Container App and configuring RBAC roles..." -ForegroundColor Cyan
az deployment group create `
    --resource-group $ResourceGroup `
    --name "cloudsec-app-deploy" `
    --template-file "deploy/main.bicep" `
    --parameters prefix=$Prefix environment=$Environment deployContainerApp=true imageTag=$ImageTag `
    --output table

$ApiEndpoint = (az deployment group show --resource-group $ResourceGroup --name "cloudsec-app-deploy" --query "properties.outputs.apiEndpoint.value" -o tsv).Trim()

# Verify API Health with retry loop
Write-Host "Verifying API health at: $ApiEndpoint/health..." -ForegroundColor Yellow
$MaxRetries = 12
$RetryDelay = 10
$Healthy = $false

for ($i = 1; $i -le $MaxRetries; $i++) {
    Write-Host "Health check attempt $i of $MaxRetries..."
    try {
        $response = Invoke-RestMethod -Uri "$ApiEndpoint/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
        if ($response.status -eq "healthy") {
            Write-Host "API is healthy!" -ForegroundColor Green
            $Healthy = $true
            break
        }
    }
    catch {
        # Retry
    }
    Start-Sleep -Seconds $RetryDelay
}

if (-not $Healthy) {
    Write-Warning "Health probe timed out. The Container App replica may still be starting."
    Write-Warning "Check container logs using: az containerapp logs show --name ${Prefix}-api-${Environment} --resource-group $ResourceGroup"
}

Write-Host ""
Write-Host "=== Deployment Summary ===" -ForegroundColor Green
Write-Host "API Endpoint:        $ApiEndpoint"
Write-Host "ACR Resource:        $AcrName ($AcrServer)"
Write-Host "Storage Account:     $StorageAccount"
Write-Host "Event Grid Endpoint: $EventGrid"
