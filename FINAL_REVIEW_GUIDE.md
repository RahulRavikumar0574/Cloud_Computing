# Final Review Guide — Cloud-Native Container Breakout Detection on Azure

A presentation flow for the cloud computing course final review: what to say, what to show, and how to answer likely questions. Plan for about **15 minutes** plus questions.

**Live app:** https://cloudsec-api-prod.ashyrock-f544a837.centralindia.azurecontainerapps.io/
**Azure resource group:** `rg-container-security` (Central India, Azure for Students subscription)

---

## Flow at a glance

| # | Section | Time | What's on screen |
|---|---|---|---|
| 1 | Problem and goal | 1.5 min | Dashboard header |
| 2 | Architecture on Azure | 3 min | Dashboard flow diagram, then the resource group in the portal |
| 3 | Containerisation with Docker | 2 min | `cloud/Dockerfile` |
| 4 | Detection pipeline (ML) | 2 min | Dashboard status cards |
| 5 | Live demo | 4 min | Dashboard → Blob Storage → Event Grid → Log stream |
| 6 | Results | 1 min | Results table below |
| 7 | Challenges and how they were solved | 1.5 min | This guide |
| 8 | Limitations and future work | 1 min | This guide |

---

## 1. Problem and goal

**Say:**
- Containers share the host's kernel. A *container breakout* is when an attacker inside a container escapes to the host, for example by mounting the host filesystem, abusing a mounted Docker socket, injecting into another process's memory, or entering host namespaces.
- These attacks show up as unusual **system call (syscall) sequences**, which tools like Falco and Tetragon capture with eBPF.
- **Goal:** build a cloud-native service that scores container syscall telemetry, explains each alert, and plugs into Azure's storage, eventing and monitoring services. It is deployed as containers with infrastructure-as-code.

---

## 2. Architecture on Azure

```
 eBPF syscall telemetry          Azure Container Registry (ACR)
 (simulated in the demo)              │  image: cloud-sec-api:v3
          │                           ▼ pull (admin credential stored as an app secret)
          ▼                 ┌──────────────────────────────────┐
   HTTPS ingress ─────────▶ │ Azure Container Apps             │
                            │  FastAPI + XGBoost + BiLSTM + SHAP│──▶ Log Analytics (logs, diagnostics)
                            │  System-assigned managed identity │
                            └───────┬───────────────┬──────────┘
                     RBAC: Storage  │               │  RBAC: EventGrid
                Blob Data Contributor               │  Data Sender
                                    ▼               ▼
                     Blob Storage: egress-alerts   Event Grid topic
                     (one JSON report per threat)  (SecurityAlert.ContainerBreakout
                                                    → SOC / Sentinel / webhooks)
```

**Azure services and why each is used:**

| Service | Resource | Role in the project |
|---|---|---|
| Azure Container Registry | `cloudsecacr3nl3e7` | Private registry for the Docker image |
| Azure Container Apps | `cloudsec-api-prod` in environment `cloudsec-cae-prod` | Serverless container hosting: HTTPS ingress, health probes, revisions, autoscaling 1–5 replicas on HTTP load |
| Managed Identity + RBAC | System-assigned identity on the app | Password-free access to Storage and Event Grid. Roles: Storage Blob Data Contributor, EventGrid Data Sender, AcrPull |
| Blob Storage | `cloudsecsa3nl3e7` | `egress-alerts` holds incident reports; `ingress-telemetry` is for batch telemetry uploads |
| Event Grid | `cloudsec-egt-prod` | Publishes each detection as an event that security tools can subscribe to |
| Log Analytics | `cloudsec-law-prod` | Central log store for the Container Apps environment |
| Bicep (infrastructure as code) | `deploy/main.bicep` | Declares every resource and role assignment; deployed in two stages (infrastructure first, then the app once the image exists) |

**Show:** in the Azure portal, open `rg-container-security` and point out each resource in the list.

**Talking points:**
- **No secrets in code:** the app reaches Storage and Event Grid with its managed identity, and the roles are scoped to those two resources only (least privilege).
- **The registry is the one exception.** The Container Apps environment is an *Express* environment, which doesn't support managed-identity image pulls, so the image is pulled with the registry's admin credential, stored as a Container App secret and filled in by Bicep at deploy time.
- **Health probes:** Azure calls `/health` (liveness) and `/ready` (readiness) and restarts or withholds traffic from unhealthy replicas.

---

## 3. Containerisation with Docker

**Show:** `cloud/Dockerfile`

| Practice | How it's done |
|---|---|
| Multi-stage build | Stage 1 compiles dependencies into a virtualenv; stage 2 copies only the virtualenv, so compilers never ship |
| Runs as non-root | Dedicated `appuser` (UID 10001) |
| Built-in health check | `HEALTHCHECK` calls `/health` |
| Smaller image | CPU-only PyTorch, and the unused NVIDIA GPU library removed. PyTorch ships as its own layer so no single upload is too large |
| Reproducible | XGBoost pinned to the version the model artifacts expect |

**Say:** Azure Container Registry's cloud build feature (ACR Tasks) is disabled on student subscriptions, so the image is built with Docker Desktop and pushed with `docker push`. Each release gets its own tag (`v2`, `v3`), which makes Container Apps start a new revision.

---

## 4. Detection pipeline

1. **Windowing:** events are grouped per container and pod into windows of up to 50 syscalls.
2. **Two models score every window:**
   - **XGBoost** on 11 tabular features: counts of high-risk syscalls (`mount`, `ptrace`, `nsenter`, `chroot`, `capset`, `process_vm_writev`, `connect`), the ratio of unique syscalls, the failure ratio, burst size and process count.
   - **BiLSTM** (bidirectional LSTM) on the ordered syscall sequence, which captures the *order* of calls.
3. **Ensemble:** risk = average of the two scores. **Risk ≥ 0.65 → incident.**
4. **Explainability:** **SHAP** reports which features pushed each incident's score up or down, so an analyst can see *why* it was flagged.
5. **Response:** each incident is written to Blob Storage and published to Event Grid.

---

## 5. Live demo script

**Before the review:** open these browser tabs and sign in to the portal.

1. The dashboard (live app URL above)
2. Portal → `cloudsecsa3nl3e7` → **Containers** → `egress-alerts`
3. Portal → `cloudsec-api-prod` → **Log stream** (under Monitoring)
4. Portal → `cloudsec-egt-prod` → **Metrics** → "Published Events"

**Steps:**

1. **Dashboard, top section.** "Operational", models loaded, and Blob Storage and Event Grid shown as *Azure (managed identity)*. This proves the container is talking to real Azure services, not local mocks.
2. **Flow diagram.** One sentence per box.
3. **Run simulation** (6 attack sessions, 8 normal sessions).
   - **Summary chips:** threats detected, attacks caught, false alarms.
   - **Table:** each session's risk bar against the black threshold line.
   - **Grey areas:** a "Service calling a database" can score 0.2–0.6 because it uses `connect`, like Docker socket abuse does. A *stealthy* partial-chain attack may stay under the line and be missed. This is the honest trade-off of any detector.
   - **Incident cards:** BiLSTM and XGBoost scores and the SHAP bars. For example, `count_ptrace` pushing a memory-injection alert up.
4. **Blob Storage tab:** refresh `egress-alerts`, open the newest `incident_….json`, and match the incident ID with the dashboard card.
5. **Event Grid tab:** the Published Events count goes up.
6. **Log stream tab:** the app's log lines for the detections it just made.
7. *(Optional)* Container App → **Revisions and replicas** to show revision history, and **Scale** to show the 1–5 replica rule.

> If the live demo fails (network, credits), the API docs at `/docs` show every endpoint, and the evaluation results below came from the same models.

---

## 6. Results

Evaluation on **1,000 fresh simulated sessions** (300 attacks, 700 normal) never seen in training, at the 0.65 threshold:

| Metric | Value |
|---|---|
| Attacks caught (recall) | **234 / 300 (78%)** |
| False alarms | **0 / 700** |

| Scenario | Mean risk | Flagged |
|---|---|---|
| Memory Injection — full / stealthy | 0.998 / 0.998 | 27/27, 42/42 |
| Namespace Escape — full / stealthy | 0.997 / 0.993 | 31/31, 38/38 |
| Privileged Container Escape — full / stealthy | 0.997 / 0.694 | 41/41, 21/40 |
| Docker Socket Abuse — full / stealthy | 0.895 / 0.431 | 34/36, **0/45** |
| Normal: Service calling a database | 0.205 (max 0.486) | 0/155 |
| Normal: Init / maintenance job | 0.130 (max 0.446) | 0/90 |
| Normal: Debugger / profiler (strace) | 0.005 | 0/67 |
| Normal: Web server | 0.003 | 0/388 |

Validation scores during training: XGBoost ROC-AUC 0.991, BiLSTM ROC-AUC 0.980.

**Interpretation:** loud attacks are caught reliably. **Stealthy Docker-socket abuse is missed:** its partial chain (`socket`, `connect`, `write`) is almost identical to a normal service connecting to a database. The current features can't tell *what* is being connected to, which leads into future work.

---

## 7. Challenges and how they were solved

| Problem | Cause | Fix |
|---|---|---|
| `az acr build` rejected | ACR Tasks are disabled on Azure for Students | Built locally with Docker Desktop, then `docker push` |
| Container crashed at startup | XGBoost 3.2 model format unreadable by SHAP; model was trained on 3.0.5 | Pinned `xgboost==3.0.5` |
| `PermissionError: mock_storage` | Non-root user couldn't create its fallback folder | Created the folder with the right owner in the Dockerfile |
| Push kept failing on one layer | One 2.19 GB layer; the connection dropped mid-upload | Removed the unused NVIDIA library and split PyTorch into its own layer |
| `ExpressEnvironmentFeatureNotSupported` | Express environments don't allow managed-identity image pulls | Registry admin credential stored as a Container App secret |
| `RoleDefinitionDoesNotExist` | Wrong Event Grid Data Sender role GUID in the Bicep file | Corrected it to `d5a91429-5739-47e2-a06b-3470a27159e7` |
| Attacks never flagged | Models trained on only 200 sessions; risk scores stayed under 0.65 | Retrained on more data |
| Scores only ~0 or ~0.99 | Simulated attacks and normal traffic were perfectly separable | Added grey-area normal workloads, stealthy attacks and a 4th attack type, then retrained |

---

## 8. Limitations and future work

- **The data is synthetic.** The next step is real Falco/Tetragon telemetry from AKS. `deploy/falco-aks-daemonset.yaml` and the Helm steps in `DEPLOYMENT.md` are prepared but **not deployed**.
- **Stealthy Docker-socket abuse is missed.** Features such as file or socket paths (`/var/run/docker.sock`) and connection destinations would separate it from a normal service connecting to a database.
- **CI/CD:** `.github/workflows/ci-cd.yml` defines test → build → staging → gated production, but the GitHub secrets aren't configured, so deployments are manual today.
- **Registry authentication:** moving to a standard (workload-profiles) environment would allow managed-identity image pulls and retire the admin credential.
- **Cost:** one replica always runs. Scaling to zero between demos would save credit at the cost of a slow first request.

---

## Likely questions

- **Why Container Apps instead of AKS or App Service?** Container Apps runs containers serverlessly with built-in HTTPS, revisions and HTTP autoscaling, without managing a Kubernetes cluster. AKS is planned only for the telemetry collector (Falco runs as a DaemonSet on each node).
- **What is a managed identity?** An identity Azure creates for the app, with no password to store. The app requests tokens at runtime, and RBAC role assignments decide what it can access.
- **Why two models?** XGBoost captures *what* syscalls occur (counts and ratios); the BiLSTM captures *the order* they occur in. Averaging both makes the score more robust than either alone.
- **What does SHAP add?** Per-alert reasons. Security teams need to know why something was flagged before acting on it.
- **How does it scale?** The Container Apps HTTP rule adds replicas (up to 5) when concurrent requests exceed 50 per replica.
- **What happens if Storage or Event Grid is unavailable?** Detection itself keeps working. If Storage can't be reached when the app starts, it switches to local mock files. A failed upload later is logged, and the incident is still returned in the API response. If an Event Grid publish fails, the event is written to the local log instead (see `cloud/azure_storage.py` and `cloud/event_dispatcher.py`).
- **Why 0.65 as the threshold?** It's the project's default. Lowering it would catch more stealthy attacks but raise false alarms on grey-area workloads. The dashboard table shows this trade-off directly.
- **How is the infrastructure reproducible?** `deploy/main.bicep` declares every resource and role assignment, and the same template redeploys the app with a new image tag.

---

## Pre-review checklist

- [ ] Open the live URL; the dashboard shows **Operational**
- [ ] Run one simulation in advance, so there are blobs in `egress-alerts` to show
- [ ] Portal tabs open and signed in (Storage, Event Grid metrics, Log stream)
- [ ] Azure for Students credit remaining checked in the portal (Cost Management)
- [ ] Backup: screenshots of the dashboard results and an incident blob, in case of network issues
