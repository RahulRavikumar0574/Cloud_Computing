import os
import sys
import uuid
import time
import json
import logging
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Query, status
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.pipeline import SequenceTokenizer, TabularFeatureExtractor
from cloud.azure_storage import AzureBlobTelemetryIngester
from cloud.event_dispatcher import SecurityEventDispatcher
from cloud.engine import SecurityInferenceEngine
from cloud.monitoring import metrics_client
from telemetry.attack_simulator import generate_session

DASHBOARD_PATH = Path(__file__).resolve().parent / "static" / "dashboard.html"

# Alias classes into __main__ namespace to resolve pickle loading mismatch
sys.modules['__main__'].SequenceTokenizer = SequenceTokenizer
sys.modules['__main__'].TabularFeatureExtractor = TabularFeatureExtractor

logger = logging.getLogger("CloudSecurityAPI")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class Globals:
    engine: Optional[SecurityInferenceEngine] = None
    ingester: Optional[AzureBlobTelemetryIngester] = None
    dispatcher: Optional[SecurityEventDispatcher] = None
    startup_time: float = 0.0

    # Backwards compatibility handles
    tokenizer = None
    tabular_extractor = None
    bilstm_model = None
    xai_explainer = None


def init():
    """Initializes the ML inference engine, Azure storage ingester, and event dispatcher."""
    logger.info("Initializing models and adapters...")
    artifacts_dir = os.environ.get("ARTIFACTS_DIR", "artifacts")

    try:
        Globals.engine = SecurityInferenceEngine(artifacts_dir=artifacts_dir)
        # Populate backward-compatibility properties
        Globals.tokenizer = Globals.engine.tokenizer
        Globals.tabular_extractor = Globals.engine.tabular_extractor
        Globals.bilstm_model = Globals.engine.bilstm_model
        Globals.xai_explainer = Globals.engine.xai_explainer

        Globals.ingester = AzureBlobTelemetryIngester()
        Globals.dispatcher = SecurityEventDispatcher()
        Globals.startup_time = time.time()
        logger.info("API services initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize engine and adapters: {e}", exc_info=True)
        raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI modern lifespan context manager replacing deprecated on_event."""
    init()
    yield
    logger.info("Shutting down CloudSecurityAPI...")


app = FastAPI(
    title="Azure Cloud-Native Container Security Engine",
    description="Real-time Kubernetes Container Breakout Detection with Explainable AI (SHAP)",
    version="2.0.0",
    lifespan=lifespan
)


# Correlation ID & Metrics Middleware
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id
    start_time = time.time()
    response = await call_next(request)
    latency_ms = (time.time() - start_time) * 1000.0
    metrics_client.record_request(request.url.path, latency_ms, response.status_code)
    response.headers["x-correlation-id"] = correlation_id
    return response


# --- Pydantic Schemas ---

class TelemetryEvent(BaseModel):
    timestamp: Optional[str] = None
    container_id: Optional[str] = "unknown"
    pod_name: Optional[str] = "unknown"
    namespace: Optional[str] = "default"
    syscall: str
    process_name: Optional[str] = "unknown"
    return_value: Optional[int] = 0
    is_threat: Optional[int] = 0
    attack_type: Optional[str] = "None"

    model_config = {"extra": "allow"}


class FeatureContribution(BaseModel):
    feature: str
    contribution: float
    description: str


class IncidentReportModel(BaseModel):
    incident_id: str
    container_id: str
    pod_name: str
    overall_risk_score: float
    bilstm_score: float
    xgb_score: float
    attack_classification: str
    shap_top_indicators: List[Dict[str, Any]]


class DetectionResponse(BaseModel):
    status: str
    correlation_id: Optional[str] = None
    processed_windows: int = 0
    threats_detected: int = 0
    reports: List[Dict[str, Any]] = []
    message: Optional[str] = None


def publish_reports(reports: List[Dict[str, Any]], processed_windows: int) -> List[Dict[str, Any]]:
    """
    Uploads each incident report to egress storage, dispatches it to Event Grid,
    and records inference metrics. Returns where each incident was delivered.
    """
    deliveries = []
    for report in reports:
        # Upload to egress alerts storage
        report_name = f"incident_{report['incident_id']}.json"
        stored = Globals.ingester.upload_egress_report(report_name, report) if Globals.ingester else False

        # Dispatch to Azure Event Grid
        dispatch = Globals.dispatcher.dispatch_incident(report) if Globals.dispatcher else {}

        deliveries.append({
            "incident_id": report["incident_id"],
            "blob_name": report_name,
            "stored": stored,
            "storage_mode": Globals.ingester.auth_mode if Globals.ingester else "unknown",
            "event_status": dispatch.get("status", "skipped"),
            "event_mode": dispatch.get("mode", "unknown")
        })

    # Track telemetry metrics
    max_risk = max([r.get("overall_risk_score", 0.0) for r in reports], default=0.0)
    metrics_client.record_inference(processed_windows, len(reports), max_risk)
    return deliveries


# --- Endpoints ---

@app.get("/", include_in_schema=False)
async def dashboard():
    """Serves the interactive demo dashboard."""
    return FileResponse(DASHBOARD_PATH, media_type="text/html")

@app.get("/health", tags=["Health Probes"])
async def health():
    """Liveness probe: returns 200 if the process is alive."""
    return {
        "status": "healthy",
        "service": "cloud-sec-api",
        "uptime_seconds": round(time.time() - Globals.startup_time, 2) if Globals.startup_time else 0
    }


@app.get("/ready", tags=["Health Probes"])
async def ready():
    """Readiness probe: verifies ML models and pipeline artifacts are loaded into memory."""
    if Globals.engine and Globals.engine.is_ready:
        return {
            "status": "ready",
            "models_loaded": True,
            "artifacts_dir": Globals.engine.artifacts_dir,
            "storage_mode": Globals.ingester.auth_mode if Globals.ingester else "unknown",
            "event_grid_mode": Globals.dispatcher.mode if Globals.dispatcher else "unknown"
        }
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Models and pipeline artifacts are not fully loaded."
    )


@app.post("/detect", tags=["Inference"])
async def detect(request: Request):
    """
    Accepts raw container runtime event batches and performs ensemble inference.
    Dispatches high-risk alerts to Event Grid and logs SHAP attribution.
    """
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8").strip()

    if not body_str:
        return {
            "status": "success",
            "correlation_id": correlation_id,
            "message": "No events to process",
            "processed_windows": 0,
            "threats_detected": 0,
            "reports": []
        }

    try:
        # Standard JSON first
        payload = json.loads(body_str)
    except json.JSONDecodeError:
        # Fallback: NDJSON (line-by-line JSON)
        try:
            payload = [json.loads(line) for line in body_str.splitlines() if line.strip()]
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload format")

    if not isinstance(payload, list):
        raise HTTPException(status_code=400, detail="Payload must be a list of telemetry events")

    if not payload:
        return {
            "status": "success",
            "correlation_id": correlation_id,
            "message": "No events to process",
            "processed_windows": 0,
            "threats_detected": 0,
            "reports": []
        }

    # Ensure engine is loaded
    if not Globals.engine or not Globals.engine.is_ready:
        raise HTTPException(status_code=503, detail="Inference engine is not ready")

    try:
        # Run detection through core engine
        result = Globals.engine.run_detection(payload)
        reports = result.get("reports", [])
        publish_reports(reports, result.get("processed_windows", 0))

        return {
            "status": "success",
            "correlation_id": correlation_id,
            "processed_windows": result.get("processed_windows", 0),
            "threats_detected": result.get("threats_detected", 0),
            "reports": reports
        }

    except HTTPException:
        raise
    except Exception as e:
        metrics_client.record_inference_failure(str(e))
        logger.error(f"[CID {correlation_id}] Inference error: {e}", exc_info=True)
        # Shield internal stack trace from client
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error occurred. Reference Correlation ID: {correlation_id}"
        )


@app.post("/demo/simulate", tags=["Demo"])
async def simulate(
    request: Request,
    attack_sessions: int = Query(3, ge=0, le=20, description="Number of simulated container-escape sessions"),
    normal_sessions: int = Query(5, ge=0, le=20, description="Number of simulated benign sessions")
):
    """
    Generates synthetic eBPF telemetry with the attack simulator, runs it through the
    detection engine, and publishes flagged incidents exactly like /detect does.
    Also returns per-session scores so the dashboard can show them against the threshold.
    """
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))

    if not Globals.engine or not Globals.engine.is_ready:
        raise HTTPException(status_code=503, detail="Inference engine is not ready")

    events = []
    for _ in range(attack_sessions):
        events.extend(generate_session(is_threat=True))
    for _ in range(normal_sessions):
        events.extend(generate_session(is_threat=False))

    if not events:
        raise HTTPException(status_code=400, detail="Request at least one session to simulate")

    try:
        result = Globals.engine.run_detection(events)
        reports = result.get("reports", [])
        deliveries = publish_reports(reports, result.get("processed_windows", 0))
    except Exception as e:
        metrics_client.record_inference_failure(str(e))
        logger.error(f"[CID {correlation_id}] Simulation error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation error occurred. Reference Correlation ID: {correlation_id}"
        )

    return {
        "status": "success",
        "correlation_id": correlation_id,
        "events_generated": len(events),
        "processed_windows": result.get("processed_windows", 0),
        "threats_detected": result.get("threats_detected", 0),
        "risk_threshold": result.get("risk_threshold"),
        "window_scores": result.get("window_scores", []),
        "reports": reports,
        "deliveries": deliveries
    }


@app.get("/metrics", tags=["Monitoring"])
async def metrics_endpoint():
    """Prometheus / Azure Monitor compatible diagnostic metrics summary."""
    return metrics_client.get_summary()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)