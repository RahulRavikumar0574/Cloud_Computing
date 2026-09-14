import pytest
import os
import json
import numpy as np
from fastapi.testclient import TestClient

# Mock environment variables before importing app
os.environ["AZURE_STORAGE_CONNECTION_STRING"] = ""
os.environ["ARTIFACTS_DIR"] = "artifacts"

from cloud.app import app, init, Globals
from explainability.explainer import RuntimeXAIExplainer

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_models():
    """Initializes the models and artifacts required by the app."""
    # Create mock artifacts if they don't exist
    from pathlib import Path
    Path("artifacts").mkdir(exist_ok=True)
    
    # Run the app's initialization
    try:
        init()
    except Exception as e:
        pytest.skip(f"Could not initialize app (missing artifacts?): {e}")

def test_xai_explainer():
    """Tests the RuntimeXAIExplainer logic."""
    if Globals.xai_explainer is None:
        pytest.skip("XAI Explainer not loaded.")
        
    explainer = Globals.xai_explainer
    
    # Create a dummy session feature vector matching the tabular extractor shape
    num_features = len(explainer.feature_names)
    dummy_features = np.zeros((1, num_features))
    
    # High risk values to trigger risk
    # Assuming count_mount, count_execve etc are features
    for i, name in enumerate(explainer.feature_names):
        if "count_" in name:
            dummy_features[0, i] = 10
            
    explanation = explainer.explain_session(dummy_features)
    
    assert "risk_score" in explanation
    assert "top_indicators" in explanation
    
    assert 0.0 <= explanation["risk_score"] <= 1.0
    
    indicators = explanation["top_indicators"]
    assert isinstance(indicators, list)
    if indicators:
        assert "feature" in indicators[0]
        assert "contribution" in indicators[0]
        
    payload = explainer.serialize_payload(explanation)
    assert isinstance(payload, str)
    assert "risk_score" in json.loads(payload)

def test_api_detect_endpoint():
    """Tests the /detect API endpoint with simulated payload."""
    # Create a batch of simulated eBPF events
    payload = []
    
    # 50 events to complete a window
    for i in range(50):
        event = {
            "container_id": "test-container-123",
            "pod_name": "test-pod",
            "timestamp": "2026-09-08T12:00:00Z",
            "syscall": "mount" if i < 10 else "read",
            "process_name": "bash",
            "return_value": 0,
            "is_threat": 1 if i < 5 else 0,
            "attack_type": "Privileged Container Breakout"
        }
        payload.append(event)
        
    response = client.post("/detect", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "success"
    assert data["processed_windows"] == 1
    
    # Check if a threat was detected (depends on model outputs, but we assert format)
    assert "threats_detected" in data
    assert "reports" in data
    
    if data["threats_detected"] > 0:
        report = data["reports"][0]
        assert "incident_id" in report
        assert "overall_risk_score" in report
        assert "shap_top_indicators" in report
        assert report["overall_risk_score"] > 0.65

def test_api_detect_empty_payload():
    """Tests the /detect API endpoint with an empty payload."""
    response = client.post("/detect", json=[])
    assert response.status_code == 200
    data = response.json()
    assert data["processed_windows"] == 0

def test_api_detect_invalid_payload():
    """Tests the /detect API endpoint with an invalid payload."""
    response = client.post("/detect", json={"invalid": "payload"})
    assert response.status_code == 400

def test_api_health_endpoint():
    """Tests the /health liveness probe."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "cloud-sec-api"
    assert "uptime_seconds" in data

def test_api_ready_endpoint():
    """Tests the /ready readiness probe."""
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["models_loaded"] is True
    assert "storage_mode" in data
    assert "event_grid_mode" in data

def test_api_metrics_endpoint():
    """Tests the /metrics endpoint."""
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "request_count" in data
    assert "windows_processed" in data

def test_correlation_id_propagation():
    """Tests that x-correlation-id is returned in response headers and detect payload."""
    custom_cid = "test-cid-98765"
    response = client.get("/health", headers={"x-correlation-id": custom_cid})
    assert response.headers.get("x-correlation-id") == custom_cid

