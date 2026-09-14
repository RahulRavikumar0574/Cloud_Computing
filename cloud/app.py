import os
import sys
import torch
import json
import uuid
import logging
from typing import List, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

from explainability.explainer import RuntimeXAIExplainer
from models.bilstm_model import SyscallBiLSTM
from preprocessing.pipeline import (
    SessionWindowBuilder, 
    PipelineArtifacts, 
    SequenceTokenizer, 
    TabularFeatureExtractor
)
from cloud.azure_storage import AzureBlobTelemetryIngester

# Alias classes into __main__ namespace to resolve pickle loading mismatch
sys.modules['__main__'].SequenceTokenizer = SequenceTokenizer
sys.modules['__main__'].TabularFeatureExtractor = TabularFeatureExtractor

logger = logging.getLogger(__name__)

# Globals for models and pipeline
app = FastAPI(title="Azure Cloud-Native Security Engine")

class Globals:
    tokenizer = None
    tabular_extractor = None
    bilstm_model = None
    xai_explainer = None
    ingester = None

def init():
    """Simulates Azure ML init() paradigm for loading models and artifacts."""
    logger.info("Initializing models and artifacts...")
    
    # Load preprocessing artifacts
    artifacts_dir = os.environ.get("ARTIFACTS_DIR", "artifacts")
    try:
        Globals.tokenizer, Globals.tabular_extractor = PipelineArtifacts.load_artifacts(artifacts_dir)
    except Exception as e:
        logger.error(f"Failed to load preprocessing artifacts: {e}")
        raise
        
    # Load BiLSTM model
    bilstm_path = os.path.join(artifacts_dir, "bilstm_model.pt")
    try:
        state_dict = torch.load(bilstm_path, map_location=torch.device('cpu'))
        checkpoint_vocab_size = state_dict["embedding.weight"].shape[0]
        Globals.bilstm_model = SyscallBiLSTM(vocab_size=checkpoint_vocab_size)
        Globals.bilstm_model.load_state_dict(state_dict)
        Globals.bilstm_model.eval()
    except Exception as e:
        logger.error(f"Failed to load BiLSTM model: {e}")
        raise
        
    # Initialize XAI Explainer
    xgb_path = os.path.join(artifacts_dir, "xgboost_model.json")
    try:
        feature_names = Globals.tabular_extractor.feature_cols
        Globals.xai_explainer = RuntimeXAIExplainer(model_path=xgb_path, feature_names=feature_names)
    except Exception as e:
        logger.error(f"Failed to load XGBoost / XAI explainer: {e}")
        raise
        
    # Initialize Ingester
    Globals.ingester = AzureBlobTelemetryIngester()
    
    logger.info("Initialization complete.")

@app.on_event("startup")
async def startup_event():
    init()

@app.post("/detect")
async def run(request: Request):
    """
    Simulates Azure ML run() paradigm.
    Accepts raw container runtime event batches and performs ensemble inference.
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8").strip()

    if not body_str:
        return {"status": "success", "message": "No events to process", "reports": []}

    try:
        # Try standard JSON array first
        payload = json.loads(body_str)
    except json.JSONDecodeError:
        # Fallback: Parse NDJSON (line-by-line JSON)
        try:
            payload = [json.loads(line) for line in body_str.splitlines() if line.strip()]
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if not isinstance(payload, list):
        raise HTTPException(status_code=400, detail="Payload must be a list of events")
        
    if not payload:
        return {"status": "success", "message": "No events to process", "reports": []}
        
    # Process through pipeline
    window_builder = SessionWindowBuilder(window_size_events=50)
    windows = window_builder.build_windows(payload)
    
    if not windows:
        return {"status": "success", "message": "No complete windows built", "reports": []}
        
    X_tabular, _ = Globals.tabular_extractor.extract(windows)
    X_seq = Globals.tokenizer.transform(windows)
    
    # Inference
    reports = []
    
    # BiLSTM predictions
    X_seq_tensor = torch.tensor(X_seq, dtype=torch.long)
    with torch.no_grad():
        bilstm_out = Globals.bilstm_model(X_seq_tensor)
        bilstm_probs = torch.sigmoid(bilstm_out).numpy()
        
    # XGBoost predictions
    xgb_probs = Globals.xai_explainer.model.predict_proba(X_tabular.values)[:, 1] if Globals.xai_explainer.model.predict_proba(X_tabular.values).shape[1] > 1 else Globals.xai_explainer.model.predict_proba(X_tabular.values)[:, 0]
    
    # Iterate through windows
    for i, window in enumerate(windows):
        container_id = window.get("container_id", "unknown")
        pod_name = window.get("pod_name", "unknown")
        
        bilstm_score = float(bilstm_probs[i])
        xgb_score = float(xgb_probs[i])
        
        # Ensemble risk score (average)
        overall_risk_score = (bilstm_score + xgb_score) / 2.0
        
        if overall_risk_score > 0.65:
            # Trigger XAI Explainer
            session_features = X_tabular.iloc[i].values
            explanation = Globals.xai_explainer.explain_session(session_features)
            
            # Simulated event dispatch
            incident_id = str(uuid.uuid4())
            logger.warning(f"High risk detected! Dispatched to Azure Event Grid: Incident {incident_id}")
            
            report = {
                "incident_id": incident_id,
                "container_id": container_id,
                "pod_name": pod_name,
                "overall_risk_score": overall_risk_score,
                "bilstm_score": bilstm_score,
                "xgb_score": xgb_score,
                "attack_classification": window.get("attack_type", "Unknown"),
                "shap_top_indicators": explanation.get("top_indicators", [])
            }
            reports.append(report)
            
            # Upload to egress
            report_name = f"incident_{incident_id}.json"
            Globals.ingester.upload_egress_report(report_name, report)
            
    return {
        "status": "success",
        "processed_windows": len(windows),
        "threats_detected": len(reports),
        "reports": reports
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)