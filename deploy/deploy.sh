#!/usr/bin/env bash
# ==============================================================================
# Azure Deployment Automation Script for Cloud-Native Container Security Engine
# ==============================================================================
set -euo pipefail

RESOURCE_GROUP=${1:-"rg-container-security"}
LOCATION=${2:-"eastus"}
PREFIX=${3:-"cloudsec"}
ENVIRONMENT=${4:-"prod"}
IMAGE_TAG=${5:-"latest"}

echo "=== Azure Cloud-Native Container Security Deployment ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location:       $LOCATION"
echo "Prefix:         $PREFIX"
echo "Environment:    $ENVIRONMENT"
echo "Image Tag:      $IMAGE_TAG"

# Check Azure CLI availability
if ! command -v az &> /dev/null; then
    echo "ERROR: Azure CLI ('az') is not installed or not in PATH."
    echo "Install Azure CLI from: https://learn.microsoft.com/cli/azure/install-azure-cli"
    exit 1
fi

# Check Azure Authentication
echo "Checking Azure authentication..."
if ! az account show --output none 2>/dev/null; then
    echo "ERROR: Not logged in to Azure. Please run 'az login' first."
    exit 1
fi

# 1. Create Resource Group if not exists
echo "[1/5] Ensuring Resource Group exists..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output table

# 2. Stage 1: Deploy base infrastructure (ACR, Storage, Log Analytics, Event Grid)
# deployContainerApp=false ensures ACR exists before attempting to pull image
echo "[2/5] Deploying Base Infrastructure (ACR, Storage, Event Grid, CAE)..."
az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-infra-base" \
    --template-file deploy/main.bicep \
    --parameters prefix="$PREFIX" environment="$ENVIRONMENT" deployContainerApp=false \
    --output table

# 3. Retrieve ACR Resource Name and details directly via native TSV queries (no jq required)
echo "[3/5] Retrieving infrastructure configuration..."
ACR_NAME=$(az deployment group show \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-infra-base" \
    --query "properties.outputs.acrName.value" -o tsv)

ACR_SERVER=$(az deployment group show \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-infra-base" \
    --query "properties.outputs.acrLoginServer.value" -o tsv)

STORAGE_ACCOUNT=$(az deployment group show \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-infra-base" \
    --query "properties.outputs.storageAccountName.value" -o tsv)

EVENT_GRID=$(az deployment group show \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-infra-base" \
    --query "properties.outputs.eventGridTopicEndpoint.value" -o tsv)

echo "ACR Resource Name: $ACR_NAME"
echo "ACR Login Server:  $ACR_SERVER"

# 4. Build and push image into ACR using cloud build
echo "[4/5] Building Docker container image in ACR: $ACR_NAME..."
az acr build \
    --registry "$ACR_NAME" \
    --image "cloud-sec-api:$IMAGE_TAG" \
    --file cloud/Dockerfile .

# 5. Stage 2: Deploy Container App & configure Managed Identity role assignments
echo "[5/5] Deploying Container App and configuring RBAC roles..."
az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-app-deploy" \
    --template-file deploy/main.bicep \
    --parameters prefix="$PREFIX" environment="$ENVIRONMENT" deployContainerApp=true imageTag="$IMAGE_TAG" \
    --output table

API_ENDPOINT=$(az deployment group show \
    --resource-group "$RESOURCE_GROUP" \
    --name "cloudsec-app-deploy" \
    --query "properties.outputs.apiEndpoint.value" -o tsv)

# Verify API Health with retry loop
echo "Verifying API health at: $API_ENDPOINT/health..."
MAX_RETRIES=12
RETRY_DELAY=10
HEALTHY=false

for i in $(seq 1 $MAX_RETRIES); do
    echo "Health check attempt $i of $MAX_RETRIES..."
    if curl -s -f -m 5 "$API_ENDPOINT/health" > /dev/null 2>&1; then
        echo "API is healthy!"
        HEALTHY=true
        break
    fi
    sleep $RETRY_DELAY
done

if [ "$HEALTHY" = false ]; then
    echo "WARNING: Health probe timed out. The Container App replica may still be starting."
    echo "Check container logs using: az containerapp logs show --name ${PREFIX}-api-${ENVIRONMENT} --resource-group $RESOURCE_GROUP"
fi

echo ""
echo "=== Deployment Summary ==="
echo "API Endpoint:        $API_ENDPOINT"
echo "ACR Resource:        $ACR_NAME ($ACR_SERVER)"
echo "Storage Account:     $STORAGE_ACCOUNT"
echo "Event Grid Endpoint: $EVENT_GRID"
