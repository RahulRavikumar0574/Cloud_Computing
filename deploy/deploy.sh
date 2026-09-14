#!/usr/bin/env bash
# ==============================================================================
# Azure Deployment Automation Script for Cloud-Native Container Security Engine
# ==============================================================================
set -euo pipefail

RESOURCE_GROUP=${1:-"rg-container-security"}
LOCATION=${2:-"eastus"}
PREFIX=${3:-"cloudsec"}
ENVIRONMENT=${4:-"prod"}

echo "=== Azure Cloud-Native Container Security Deployment ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location:       $LOCATION"
echo "Prefix:         $PREFIX"
echo "Environment:    $ENVIRONMENT"

# 1. Create Resource Group if not exists
echo "[1/4] Ensuring Resource Group exists..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o table

# 2. Deploy Bicep template
echo "[2/4] Deploying Infrastructure (ACR, ACA, Storage, Event Grid)..."
DEPLOY_OUTPUT=$(az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file deploy/main.bicep \
    --parameters prefix="$PREFIX" environment="$ENVIRONMENT" \
    --query properties.outputs -o json)

ACR_SERVER=$(echo "$DEPLOY_OUTPUT" | jq -r '.acrLoginServer.value')
API_ENDPOINT=$(echo "$DEPLOY_OUTPUT" | jq -r '.apiEndpoint.value')
STORAGE_ACCOUNT=$(echo "$DEPLOY_OUTPUT" | jq -r '.storageAccountName.value')
EVENT_GRID=$(echo "$DEPLOY_OUTPUT" | jq -r '.eventGridTopicEndpoint.value')

# 3. Build and push image to ACR
echo "[3/4] Building and pushing Docker container to ACR: $ACR_SERVER..."
az acr build --registry "$ACR_SERVER" --image cloud-sec-api:latest -f cloud/Dockerfile .

# 4. Verify deployment health
echo "[4/4] Verifying API Health..."
echo "API URL: $API_ENDPOINT"
curl -s -f "$API_ENDPOINT/health" || echo "Note: Initial replica may take a few seconds to start."

echo ""
echo "=== Deployment Complete ==="
echo "API Endpoint:        $API_ENDPOINT"
echo "Storage Account:     $STORAGE_ACCOUNT"
echo "Event Grid Endpoint: $EVENT_GRID"
