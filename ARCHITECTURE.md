# System Architecture

## Overview

The **Azure Cloud-Native Container Security Framework** provides real-time detection and explainable attribution for container breakout/escape attempts within Kubernetes clusters (AKS). It analyzes kernel-level system call telemetry through a multi-model ensemble (XGBoost + BiLSTM) coupled with SHAP tree-explainability, dispatching structured threat incidents to Azure Event Grid and SOC dashboards.

---

## Architectural Principles: Core vs Cloud Adapters

The framework enforces strict separation between the ML detection engine and the infrastructure layer:

```
+-------------------------------------------------------------------------------+
|                             DETECTION CORE                                    |
|                                                                               |
|   Telemetry Event Stream                                                      |
|             |                                                                 |
|             v                                                                 |
|   [SessionWindowBuilder] (50 events/window per container)                     |
|        /          \                                                           |
|       v            v                                                          |
|   [Tabular]    [Sequential]                                                   |
|   Extractor     Tokenizer                                                     |
|       |             |                                                         |
|       v             v                                                         |
|   [XGBoost]     [BiLSTM]                                                      |
|   Classifier   Classifier (Padding-Aware)                                     |
|        \           /                                                          |
|         v         v                                                           |
|     [Risk Aggregator] (Threshold >= 0.65)                                     |
|             |                                                                 |
|             v                                                                 |
|     [SHAP Explainer] (TreeExplainer Feature Attributions)                     |
|             |                                                                 |
|             v                                                                 |
|   Incident Report Object                                                      |
+-------------------------------------------------------------------------------+
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
+-----------------------------+                           +-----------------------------+
|        LOCAL ADAPTERS       |                           |        AZURE ADAPTERS       |
|                             |                           |                             |
| - Mock Storage Directory    |                           | - Azure Blob Storage        |
|   mock_storage/ingress      |                           |   ingress-telemetry         |
|   mock_storage/egress       |                           |   egress-alerts             |
| - Local Event Dispatcher    |                           | - Azure Event Grid Topic    |
|   mock_storage/events/      |                           |   (Managed Identity / Key)  |
| - In-Memory Metrics         |                           | - Azure Monitor /           |
|                             |                           |   Application Insights      |
+-----------------------------+                           +-----------------------------+
```

---

## Telemetry Ingestion Plane

The system accepts runtime system call logs from two primary sources:
1. **AKS Production DaemonSet:** [Cilium Tetragon](https://tetragon.io/) or [Falco](https://falco.org/) with Falcosidekick forwarding JSON events to Azure Blob Storage container `ingress-telemetry`.
2. **Local Attack Simulator:** Synthetic eBPF-style container escape logs generated via `telemetry/attack_simulator.py`.

The `TelemetryNormalizer` converts diverse agent outputs into a standardized event schema:

```json
{
  "timestamp": "2026-09-14T12:00:00.000Z",
  "container_id": "3a89e17b8f2d",
  "pod_name": "payment-api-7b89d-abcde",
  "namespace": "production",
  "syscall": "mount",
  "process_name": "bash",
  "return_value": 0,
  "is_threat": 0,
  "attack_type": "None"
}
```

---

## Machine Learning & Explainability Engine

### 1. Tabular Feature Extractor (`preprocessing/pipeline.py`)
Extracts windowed behavioral metrics across 50 consecutive events:
- High-risk syscall counts (`count_mount`, `count_ptrace`, `count_nsenter`, `count_chroot`, `count_capset`, `count_process_vm_writev`, `count_connect`).
- Behavioral ratios (`ratio_unique_syscalls`, `ratio_failed_syscalls`).
- Burst dynamics (`event_burst_count`, `unique_process_count`).

### 2. Sequential Tokenizer (`preprocessing/pipeline.py`)
Tokenizes syscall sequences into fixed-length integer vectors (`shape=(batch, 50)`) right-padded with `<PAD>` (token 0).

### 3. Model Ensemble:
- **XGBoost Classifier:** Tree-based ensemble trained on tabular behavioral features.
- **BiLSTM Classifier:** Bidirectional LSTM with padding-aware pooling extracting temporal sequence dynamics.
- **Combined Risk Aggregation:**
  $$\text{Risk} = \frac{P_{\text{XGBoost}} + P_{\text{BiLSTM}}}{2}$$
  Sessions with $\text{Risk} \ge 0.65$ trigger an incident alert and SHAP explanation.

### 4. Explainable AI (SHAP TreeExplainer)
For every detected incident, `RuntimeXAIExplainer` calculates exact marginal feature contributions (e.g. `count_mount contributed +0.412 to breakout risk`), providing immediate root-cause transparency for SOC analysts.

---

## Event Grid Incident Schema

When breakout risk exceeds 0.65, an event is published to Azure Event Grid:

- **Subject:** `container-escape/<incident_id>`
- **EventType:** `SecurityAlert.ContainerBreakout`
- **Payload:**
```json
{
  "incident_id": "7f6511ab-1c32-4416-8f2e-0a5688b7bc92",
  "container_id": "3a89e17b8f2d",
  "pod_name": "payment-api-7b89d-abcde",
  "overall_risk_score": 0.9412,
  "bilstm_score": 0.9125,
  "xgb_score": 0.9698,
  "attack_classification": "Privileged Container Breakout",
  "shap_top_indicators": [
    {
      "feature": "count_mount",
      "contribution": 0.4128,
      "description": "count_mount contributed +0.4128 to breakout risk"
    },
    {
      "feature": "count_chroot",
      "contribution": 0.2814,
      "description": "count_chroot contributed +0.2814 to breakout risk"
    }
  ]
}
```

---

## Security Model

1. **Least Privilege Non-Root Container:** Dockerfile runs as `appuser:appgroup` (UID 10001).
2. **Zero Hardcoded Secrets:** Credentials resolved via Azure Managed Identity (`DefaultAzureCredential`).
3. **Internal Error Shielding:** FastAPI shields internal tracebacks from HTTP clients, returning sanitized correlation IDs.
4. **Safe Ingestion Transactionality:** Ingestion worker deletes ingress blobs only after successful inference and alert dispatch.
