# Azure Cloud-Native Container Security Framework

> **Real-Time Kubernetes Container Breakout Detection with Explainable AI (SHAP) & Azure Native Integration**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Azure](https://img.shields.io/badge/Azure-Cloud--Native-0089D6.svg)](https://azure.microsoft.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-BiLSTM-EE4C2C.svg)](https://pytorch.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-Ensemble-EB5424.svg)](https://xgboost.readthedocs.io/)
[![SHAP](https://img.shields.io/badge/XAI-SHAP%20TreeExplainer-green.svg)](https://shap.readthedocs.io/)
[![Tests](https://img.shields.io/badge/pytest-25%20passed-brightgreen.svg)]()

---

## 📖 Overview

The **Azure Cloud-Native Container Security Framework** monitors kernel system call event streams in Kubernetes clusters (AKS) to detect container escape and privilege breakout attacks in real time.

It combines an ensemble of **XGBoost** (for tabular event burst and frequency features) and a **Bidirectional LSTM** (for sequence dynamics) to calculate a unified risk score. Whenever an attack is identified, the system triggers **Explainable AI (SHAP)** to pinpoint exact syscall attributions and dispatches structured security incidents to **Azure Event Grid** and **Azure Monitor** for immediate SOC response.

---

## 🏛 Architecture

```
                                +---------------------------------------------------+
                                |            AKS Runtime Kernel Telemetry           |
                                |     (Falco / Tetragon modern eBPF probes)         |
                                +---------------------------------------------------+
                                                          |
                                                          v
                                        +-----------------------------------+
                                        |    Azure Blob Storage (Ingress)   |
                                        |        "ingress-telemetry"        |
                                        +-----------------------------------+
                                                          |
                               +--------------------------+--------------------------+
                               |                                                     |
                               v                                                     v
            +------------------------------------+                +------------------------------------+
            |      FastAPI Real-Time API         |                |     Batch Ingestion Worker         |
            |          POST /detect              |                |    (Azure Container App Job)       |
            +------------------------------------+                +------------------------------------+
                               \                                                     /
                                +-------------------------+-------------------------+
                                                          |
                                                          v
                                        +-----------------------------------+
                                        |       Telemetry Normalizer        |
                                        |   (Sanitizes Falco/Tetragon JSON) |
                                        +-----------------------------------+
                                                          |
                                                          v
                                        +-----------------------------------+
                                        |     Session Window Builder        |
                                        |     (50 events/window/pod)        |
                                        +-----------------------------------+
                                              /                       \
                                             v                         v
                           +--------------------+           +--------------------+
                           |  Tabular Extractor |           | Sequence Tokenizer |
                           +--------------------+           +--------------------+
                                     |                                |
                                     v                                v
                           +--------------------+           +--------------------+
                           |  XGBoost Booster   |           | Padding-Aware LSTM |
                           +--------------------+           +--------------------+
                                     \                                /
                                      +---------------+--------------+
                                                      |
                                                      v
                                        +-----------------------------------+
                                        |       Risk Aggregator (Avg)       |
                                        |      Threshold Check (>= 0.65)    |
                                        +-----------------------------------+
                                                      |
                                                      v
                                        +-----------------------------------+
                                        |      SHAP Runtime Explainer       |
                                        |   (Top Feature Contributor JSON)  |
                                        +-----------------------------------+
                                                      |
                                      +---------------+---------------+
                                      |                               |
                                      v                               v
                    +-----------------------------------+   +-----------------------------------+
                    |    Azure Blob Storage (Egress)    |   |     Azure Event Grid Topic        |
                    |         "egress-alerts"           |   |   SecurityAlert.ContainerBreakout |
                    +-----------------------------------+   +-----------------------------------+
                                                                              |
                                                                              v
                                                            +-----------------------------------+
                                                            |   Azure Sentinel / SOC Webhook    |
                                                            +-----------------------------------+
```

---

## 🌟 Key Features

1. **Dual-Mode Architectural Parity**:
   - **Local Mode:** Self-contained, operates out of the box using `mock_storage/` with zero Azure credentials required.
   - **Azure Mode:** Switches to `DefaultAzureCredential` (Managed Identity), live Blob Storage, and Azure Event Grid topics.
2. **Padding-Aware BiLSTM**:
   - Accurately captures variable-length syscall sequences without `<PAD>` token distortion.
3. **Transparent Explainable AI (XAI)**:
   - Evaluates tree attributions using `shap.TreeExplainer` for each incident, producing clear explanations (e.g., `count_mount contributed +0.3821 to breakout risk`).
4. **Resilient Ingestion Worker**:
   - Autonomous batch processing with exponential retries, JSON validation, and safe transactional blob deletion.
5. **Production FastAPI Service**:
   - Features `GET /health` (liveness), `GET /ready` (readiness), and `GET /metrics` (diagnostics).
   - Traceable request correlation (`X-Correlation-ID`) and client error shielding.
6. **Container Security Hardened**:
   - Multi-stage Docker build running under non-root account `appuser` (UID 10001) with active healthchecks.
7. **Complete Infrastructure as Code (IaC)**:
   - Full Bicep template (`deploy/main.bicep`) and deployment automation script (`deploy/deploy.sh`).
8. **Automated CI/CD**:
   - GitHub Actions workflow (`.github/workflows/ci-cd.yml`) with automated testing and gated release approvals.

---

## 🚀 Quick Start (Local)

### 1. Installation
```bash
git clone https://github.com/your-org/Cloud.git
cd Cloud

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Generate Data & Train
```bash
# Generate synthetic container escape logs
python telemetry/attack_simulator.py --num-sessions 200 --threat-ratio 0.25

# Process features & tokens
python preprocessing/pipeline.py

# Train ensemble models
python models/train.py
```

### 3. Run FastAPI
```bash
uvicorn cloud.app:app --host 0.0.0.0 --port 8000
```
- API Docs: `http://localhost:8000/docs`
- Health Probe: `http://localhost:8000/health`
- Readiness Probe: `http://localhost:8000/ready`
- Metrics: `http://localhost:8000/metrics`

### 4. Run Test Suite
```bash
pytest tests/ -v
```

---

## 📂 Project Structure

```
Cloud/
├── config.yaml                     # Framework parameters, syscall vocabulary, scenarios
├── requirements.txt                # Pinned production & development dependencies
├── telemetry/
│   ├── attack_simulator.py         # Synthetic eBPF/Falco log generator
│   ├── log_parser.py               # JSON log line validator and parser
│   └── normalizer.py               # Production Falco & Tetragon telemetry adapter
├── preprocessing/
│   └── pipeline.py                 # Window builder, Tabular extractor, Sequence tokenizer
├── models/
│   ├── xgboost_model.py            # XGBoost training & metric calculation
│   ├── bilstm_model.py             # Padding-aware BiLSTM model architecture
│   └── train.py                    # Unified training orchestrator
├── explainability/
│   └── explainer.py                # SHAP-based RuntimeXAIExplainer
├── cloud/
│   ├── app.py                      # Production FastAPI inference service
│   ├── engine.py                   # Core cloud-agnostic inference engine
│   ├── azure_storage.py            # Hardened Azure Blob Storage ingester
│   ├── event_dispatcher.py         # Azure Event Grid publisher & local mock fallback
│   ├── ingestion_worker.py         # Batch & continuous ingestion worker
│   ├── monitoring.py               # Azure Monitor OpenTelemetry & metrics adapter
│   └── Dockerfile                  # Hardened multi-stage non-root container build
├── deploy/
│   ├── main.bicep                  # Complete Azure infrastructure Bicep template
│   ├── deploy.sh                   # Azure deployment automation script
│   └── falco-aks-daemonset.yaml    # Falco + Falcosidekick DaemonSet for AKS
├── .github/
│   └── workflows/ci-cd.yml         # GitHub Actions testing, building, and deploy workflow
├── artifacts/                      # Model checkpoints & serialized tokenizers
├── tests/                          # Automated pytest suite (25 test cases)
├── ARCHITECTURE.md                 # System architecture & core design principles
├── AZURE_SETUP.md                  # Detailed Azure cloud configuration & RBAC guide
└── DEPLOYMENT.md                   # Multi-environment deployment instructions
```

---

## 📚 Documentation Links

- [System Architecture](ARCHITECTURE.md)
- [Azure Cloud Setup & RBAC Guide](AZURE_SETUP.md)
- [Deployment Guide (Local, Docker, ACA, AKS)](DEPLOYMENT.md)

---

## 🔒 License & Security
This project is licensed under the Apache 2.0 License. Designed for defense-in-depth container security monitoring.
