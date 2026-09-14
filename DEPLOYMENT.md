# Deployment Guide

This guide covers deployment instructions for:
1. **Local Development & Mock Mode**
2. **Containerized Execution (Docker)**
3. **Azure Cloud-Native Deployment (Azure Container Apps + ACR)**
4. **AKS Telemetry Collector Deployment (Falco / Tetragon)**
5. **Background Telemetry Ingestion Worker**

---

## 1. Local Development & Mock Mode

No Azure credentials or Docker required.

### 1.1: Environment Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 1.2: Generate Synthetic Telemetry & Train Models
```bash
# 1. Synthesize eBPF logs (200 sessions, 10% threats)
python telemetry/attack_simulator.py --num-sessions 200 --threat-ratio 0.25 --output-path data/raw_ebpf_logs.json

# 2. Run preprocessing pipeline
python preprocessing/pipeline.py \
  --input-path data/raw_ebpf_logs.json \
  --tabular-output data/processed_tabular.csv \
  --sequence-output data/processed_sequences.npy \
  --artifacts-dir artifacts

# 3. Train unified model ensemble
python models/train.py
```

### 1.3: Run FastAPI Inference API
```bash
uvicorn cloud.app:app --host 0.0.0.0 --port 8000
```
Verify endpoints:
- `curl http://localhost:8000/health` -> `{"status": "healthy"}`
- `curl http://localhost:8000/ready` -> `{"status": "ready", "models_loaded": true}`
- `curl http://localhost:8000/metrics` -> Metrics snapshot

### 1.4: Execute Local Test Suite
```bash
pytest tests/ -v
```

---

## 2. Containerized Execution (Docker)

The application includes a hardened multi-stage Docker build running under a non-root service account (`appuser:appgroup`).

### 2.1: Build Docker Image
```bash
docker build -t cloud-sec-api:latest -f cloud/Dockerfile .
```

### 2.2: Run Container Locally
```bash
docker run -d \
  --name cloud-sec-engine \
  -p 8000:8000 \
  -e ARTIFACTS_DIR=/app/artifacts \
  cloud-sec-api:latest
```

### 2.3: Test Container Health
```bash
# Health probe
curl -f http://localhost:8000/health

# Readiness probe
curl -f http://localhost:8000/ready

# POST Detection test
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d @data/raw_ebpf_logs.json
```

---

## 3. Azure Cloud-Native Deployment (Bicep + Azure CLI)

### 3.1: Automated Deployment via Bicep
A complete Bicep template ([`deploy/main.bicep`](file:///d:/Projects/Cloud/deploy/main.bicep)) provisions ACR, Azure Container Apps, Storage Account, Event Grid Topic, Log Analytics, and RBAC Managed Identity role assignments.

```bash
# 1. Login to Azure
az login

# 2. Execute automated deployment script
chmod +x deploy/deploy.sh
./deploy/deploy.sh "rg-container-security" "eastus" "cloudsec" "prod"
```

### 3.2: Manual Azure Container App Creation (Alternative)
```bash
# Build image directly in ACR
az acr build --registry <acr-name> --image cloud-sec-api:latest -f cloud/Dockerfile .

# Create Container App
az containerapp create \
  --name cloud-sec-api \
  --resource-group rg-container-security \
  --environment cloudsec-cae-prod \
  --image <acr-name>.azurecr.io/cloud-sec-api:latest \
  --target-port 8000 \
  --ingress external \
  --cpu 1.0 --memory 2.0Gi \
  --min-replicas 1 --max-replicas 5 \
  --env-vars \
    ARTIFACTS_DIR=/app/artifacts \
    AZURE_STORAGE_ACCOUNT_URL=https://<storage-account>.blob.core.windows.net/ \
    EVENT_GRID_TOPIC_ENDPOINT=https://<eventgrid-topic>.eastus-1.eventgrid.azure.net/api/events
```

---

## 4. Background Ingestion Worker Deployment

[`cloud/ingestion_worker.py`](file:///d:/Projects/Cloud/cloud/ingestion_worker.py) can run as a persistent worker or scheduled job.

### Option A: Azure Container App Job (Serverless Scheduled Batch)
```bash
az containerapp job create \
  --name "cloud-sec-ingest-job" \
  --resource-group "rg-container-security" \
  --environment "cloudsec-cae-prod" \
  --trigger-type "Schedule" \
  --cron-expression "*/5 * * * *" \
  --replica-timeout 300 \
  --image "<acr-name>.azurecr.io/cloud-sec-api:latest" \
  --command "python" "cloud/ingestion_worker.py" "--once" "--max-blobs" "20"
```

### Option B: Kubernetes CronJob (Inside AKS)
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cloud-sec-ingest-worker
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: ingest-worker
            image: <acr-name>.azurecr.io/cloud-sec-api:latest
            command: ["python", "cloud/ingestion_worker.py", "--once"]
            env:
            - name: AZURE_STORAGE_ACCOUNT_URL
              value: "https://<storage-account>.blob.core.windows.net/"
            - name: EVENT_GRID_TOPIC_ENDPOINT
              value: "https://<eventgrid-topic>.eastus-1.eventgrid.azure.net/api/events"
          restartPolicy: OnFailure
```

---

## 5. AKS Telemetry Collector Deployment (Falco DaemonSet)

Deploy Falco with modern eBPF probe and Falcosidekick on AKS to automatically forward kernel events to Azure Blob Storage:

```bash
# 1. Connect to your AKS cluster
az aks get-credentials --resource-group <rg> --name <aks-cluster-name>

# 2. Add Falcosecurity Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# 3. Deploy Falco with modern eBPF and Blob Storage sink
helm install falco falcosecurity/falco \
  --namespace falco-security \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.azure.storage.account="<storage-account-name>" \
  --set falcosidekick.config.azure.storage.container="ingress-telemetry" \
  --set falcosidekick.config.azure.storage.uploadtype="batch" \
  --set falcosidekick.config.azure.storage.batchsize=50 \
  -f deploy/falco-aks-daemonset.yaml
```

---

## 6. GitHub Actions CI/CD Setup

To enable automated testing and gated deployment on commit:
1. Navigate to your GitHub repository **Settings -> Secrets and variables -> Actions**.
2. Add secrets:
   - `AZURE_CLIENT_ID` (Managed Identity / App Registration Client ID)
   - `AZURE_TENANT_ID` (Azure Active Directory Tenant ID)
   - `AZURE_SUBSCRIPTION_ID` (Azure Subscription ID)
   - `ACR_NAME` (e.g. `cloudsecacr123`)
   - `ACR_LOGIN_SERVER` (e.g. `cloudsecacr123.azurecr.io`)
   - `AZURE_RESOURCE_GROUP` (e.g. `rg-container-security`)
   - `CONTAINER_APP_NAME` (e.g. `cloudsec-api`)
3. Create GitHub Environment `production` with required reviewers for release gating.
4. On `git push origin main`, workflow `.github/workflows/ci-cd.yml` will automatically run pytest, build & push the Docker image, deploy to staging, and await approval for production.
