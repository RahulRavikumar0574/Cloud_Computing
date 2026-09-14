# Azure Cloud Setup Guide

This guide walks through setting up the required Azure cloud infrastructure for deploying the **Cloud-Native Container Security Framework**.

---

## 1. Prerequisites

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (version >= 2.50.0)
- Authenticated session: `az login`
- Permissions: Contributor or Owner role on your Azure Subscription.

---

## 2. Resource Overview

| Resource | Purpose | Configuration |
|---|---|---|
| **Resource Group** | Logical resource boundary | e.g., `rg-cloudsec-prod` |
| **Azure Container Registry (ACR)** | Hosts hardened API Docker images | Basic SKU |
| **Storage Account** | Telemetry ingestion & egress alerts | Standard_LRS, TLS 1.2 |
| **Container Apps Environment** | Serverless container host | Backed by Log Analytics |
| **Container App** | Hosts FastAPI Inference API | 1.0 vCPU, 2.0 GiB RAM, Min 1 / Max 5 |
| **Azure Event Grid Topic** | Publishes breakout incident events | EventGridSchema |
| **Log Analytics Workspace** | Centralized logging & monitoring | 30 days retention |

---

## 3. Step-by-Step Azure CLI Setup

### Step 3.1: Define Variables
```bash
RESOURCE_GROUP="rg-cloudsec-prod"
LOCATION="eastus"
PREFIX="cloudsec"
UNIQUE_ID=$(head /dev/urandom | tr -dc a-z0-9 | head -c 5)

ACR_NAME="${PREFIX}acr${UNIQUE_ID}"
STORAGE_NAME="${PREFIX}sa${UNIQUE_ID}"
EVENT_GRID_TOPIC="${PREFIX}-egt-prod"
LOG_ANALYTICS="${PREFIX}-law-prod"
ACA_ENV="${PREFIX}-cae-prod"
ACA_APP="${PREFIX}-api-prod"
```

### Step 3.2: Create Resource Group
```bash
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
```

### Step 3.3: Create Storage Account & Containers
```bash
# 1. Storage Account
az storage account create \
  --name "$STORAGE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

# 2. Ingress & Egress Containers
STORAGE_KEY=$(az storage account keys list --account-name "$STORAGE_NAME" --query "[0].value" -o tsv)

az storage container create --name "ingress-telemetry" --account-name "$STORAGE_NAME" --account-key "$STORAGE_KEY"
az storage container create --name "egress-alerts" --account-name "$STORAGE_NAME" --account-key "$STORAGE_KEY"
```

### Step 3.4: Create Azure Container Registry (ACR)
```bash
az acr create \
  --name "$ACR_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --sku Basic \
  --admin-enabled true
```

### Step 3.5: Create Azure Event Grid Topic
```bash
az eventgrid topic create \
  --name "$EVENT_GRID_TOPIC" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION"
```

### Step 3.6: Create Log Analytics & Container Apps Environment
```bash
# 1. Log Analytics
az monitor log-analytics workspace create \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LOG_ANALYTICS" \
  --location "$LOCATION"

LOG_ANALYTICS_ID=$(az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS" --query customerId -o tsv)
LOG_ANALYTICS_KEY=$(az monitor log-analytics workspace get-shared-keys --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS" --query primarySharedKey -o tsv)

# 2. Container Apps Managed Environment
az containerapp env create \
  --name "$ACA_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --logs-workspace-id "$LOG_ANALYTICS_ID" \
  --logs-workspace-key "$LOG_ANALYTICS_KEY"
```

---

## 4. Managed Identity & RBAC Configuration

To avoid embedding credentials in code or environment variables, use **System-Assigned Managed Identity**.

### Step 4.1: Assign Managed Identity to Container App
When creating or updating the Container App:
```bash
az containerapp identity assign \
  --name "$ACA_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --system-assigned
```

Retrieve the Principal ID:
```bash
APP_PRINCIPAL_ID=$(az containerapp show \
  --name "$ACA_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --query identity.principalId -o tsv)
```

### Step 4.2: Grant Storage Permissions
Role: `Storage Blob Data Contributor`
```bash
STORAGE_ID=$(az storage account show --name "$STORAGE_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv)

az role assignment create \
  --assignee "$APP_PRINCIPAL_ID" \
  --role "Storage Blob Data Contributor" \
  --scope "$STORAGE_ID"
```

### Step 4.3: Grant Event Grid Permissions
Role: `EventGrid Data Sender`
```bash
EVENT_GRID_ID=$(az eventgrid topic show --name "$EVENT_GRID_TOPIC" --resource-group "$RESOURCE_GROUP" --query id -o tsv)

az role assignment create \
  --assignee "$APP_PRINCIPAL_ID" \
  --role "EventGrid Data Sender" \
  --scope "$EVENT_GRID_ID"
```

---

## 5. Environment Variables Reference

| Environment Variable | Required Mode | Description | Example |
|---|---|---|---|
| `ARTIFACTS_DIR` | All | Directory containing trained model files | `artifacts` |
| `AZURE_STORAGE_ACCOUNT_URL` | Azure (MI) | Blob Storage primary endpoint | `https://cloudsecsa123.blob.core.windows.net/` |
| `AZURE_STORAGE_CONNECTION_STRING` | Azure (Dev) | Connection string (fallback for local dev) | `DefaultEndpointsProtocol=https;...` |
| `EVENT_GRID_TOPIC_ENDPOINT` | Azure | Azure Event Grid Topic endpoint URL | `https://cloudsec-egt-prod.eastus-1.eventgrid.azure.net/api/events` |
| `EVENT_GRID_TOPIC_KEY` | Azure (Key) | Topic key (if not using Managed Identity) | `a8B3...` |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Optional | Azure Monitor OpenTelemetry connection | `InstrumentationKey=...;IngestionEndpoint=...` |

> [!NOTE]
> If none of the Azure variables are provided, the system runs automatically in **Local Mock Mode**, utilizing `mock_storage/` and console logging.

---

## 6. Subscribing to Event Grid Alerts (SOC / Sentinel Integration)

You can route incident breakout alerts directly to an Azure Logic App, Webhook, or Azure Sentinel:

```bash
# Example: Create an Event Grid subscription routing to a Webhook or Sentinel
az eventgrid event-subscription create \
  --name "sub-breakout-alerts" \
  --source-resource-id "$EVENT_GRID_ID" \
  --endpoint "https://your-soc-webhook.example.com/alerts" \
  --included-event-types "SecurityAlert.ContainerBreakout"
```

---

## 7. Troubleshooting

- **503 Service Unavailable on `/ready`**:
  Models or artifacts failed to load. Check Container App log stream:
  ```bash
  az containerapp logs show --name "$ACA_APP" --resource-group "$RESOURCE_GROUP" --follow
  ```
- **Storage 403 Forbidden**:
  Verify the role assignment `Storage Blob Data Contributor` is propagation to the Managed Identity principal ID.
- **Event Grid 401/403**:
  Ensure the identity has the `EventGrid Data Sender` role assigned on the topic scope.
