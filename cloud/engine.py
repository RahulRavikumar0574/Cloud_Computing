import os
import sys
import uuid
import logging
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from explainability.explainer import RuntimeXAIExplainer
from models.bilstm_model import SyscallBiLSTM
from preprocessing.pipeline import (
    SessionWindowBuilder,
    PipelineArtifacts,
    SequenceTokenizer,
    TabularFeatureExtractor
)

# Alias classes into __main__ namespace to resolve pickle loading mismatch
sys.modules['__main__'].SequenceTokenizer = SequenceTokenizer
sys.modules['__main__'].TabularFeatureExtractor = TabularFeatureExtractor

logger = logging.getLogger(__name__)


class SecurityInferenceEngine:
    """
    Core ensemble detection engine combining XGBoost + BiLSTM + SHAP explainability.
    Independent of Azure - can run locally, in Docker, in FastAPI, or inside batch workers.
    """

    def __init__(self, artifacts_dir: str = "artifacts", risk_threshold: float = 0.65):
        self.artifacts_dir = artifacts_dir
        self.risk_threshold = risk_threshold
        self.tokenizer: Optional[SequenceTokenizer] = None
        self.tabular_extractor: Optional[TabularFeatureExtractor] = None
        self.bilstm_model: Optional[SyscallBiLSTM] = None
        self.xai_explainer: Optional[RuntimeXAIExplainer] = None
        self.window_builder = SessionWindowBuilder(window_size_events=50)
        self.is_ready: bool = False

        self.load_artifacts()

    def load_artifacts(self):
        """Loads serialized tokenizers, feature extractors, and models."""
        logger.info(f"Loading inference artifacts from {self.artifacts_dir}...")
        
        # Preprocessing artifacts
        self.tokenizer, self.tabular_extractor = PipelineArtifacts.load_artifacts(self.artifacts_dir)

        # BiLSTM model
        bilstm_path = os.path.join(self.artifacts_dir, "bilstm_model.pt")
        state_dict = torch.load(bilstm_path, map_location=torch.device("cpu"))
        vocab_size = state_dict["embedding.weight"].shape[0]
        self.bilstm_model = SyscallBiLSTM(vocab_size=vocab_size)
        self.bilstm_model.load_state_dict(state_dict)
        self.bilstm_model.eval()

        # XGBoost + SHAP explainer
        xgb_path = os.path.join(self.artifacts_dir, "xgboost_model.json")
        feature_names = self.tabular_extractor.feature_cols
        self.xai_explainer = RuntimeXAIExplainer(model_path=xgb_path, feature_names=feature_names)

        self.is_ready = True
        logger.info("SecurityInferenceEngine successfully initialized.")

    def run_detection(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs complete detection flow on a batch of telemetry events.
        Returns processed summary and list of incident reports.
        """
        if not events:
            return {
                "status": "success",
                "message": "No events to process",
                "processed_windows": 0,
                "threats_detected": 0,
                "reports": []
            }

        windows = self.window_builder.build_windows(events)
        if not windows:
            return {
                "status": "success",
                "message": "No complete windows built",
                "processed_windows": 0,
                "threats_detected": 0,
                "reports": []
            }

        X_tabular, _ = self.tabular_extractor.extract(windows)
        X_seq = self.tokenizer.transform(windows)

        # BiLSTM inference
        X_seq_tensor = torch.tensor(X_seq, dtype=torch.long)
        with torch.no_grad():
            bilstm_out = self.bilstm_model(X_seq_tensor)
            bilstm_probs = torch.sigmoid(bilstm_out).numpy()

        # XGBoost inference
        xgb_preds_proba = self.xai_explainer.model.predict_proba(X_tabular.values)
        xgb_probs = xgb_preds_proba[:, 1] if xgb_preds_proba.shape[1] > 1 else xgb_preds_proba[:, 0]

        reports = []
        window_scores = []
        for i, window in enumerate(windows):
            container_id = window.get("container_id", "unknown")
            pod_name = window.get("pod_name", "unknown")
            bilstm_score = float(bilstm_probs[i])
            xgb_score = float(xgb_probs[i])

            overall_risk_score = (bilstm_score + xgb_score) / 2.0
            flagged = overall_risk_score >= self.risk_threshold

            window_scores.append({
                "container_id": container_id,
                "pod_name": pod_name,
                "event_count": len(window.get("events", [])),
                "labelled_attack_type": window.get("attack_type", "None"),
                "overall_risk_score": overall_risk_score,
                "bilstm_score": bilstm_score,
                "xgb_score": xgb_score,
                "flagged": flagged
            })

            if flagged:
                session_features = X_tabular.iloc[i].values
                explanation = self.xai_explainer.explain_session(session_features)

                incident_id = str(uuid.uuid4())
                report = {
                    "incident_id": incident_id,
                    "container_id": container_id,
                    "pod_name": pod_name,
                    "overall_risk_score": overall_risk_score,
                    "bilstm_score": bilstm_score,
                    "xgb_score": xgb_score,
                    "attack_classification": window.get("attack_type", "Suspicious Activity"),
                    "shap_top_indicators": explanation.get("top_indicators", [])
                }
                reports.append(report)

        return {
            "status": "success",
            "processed_windows": len(windows),
            "threats_detected": len(reports),
            "reports": reports,
            "window_scores": window_scores,
            "risk_threshold": self.risk_threshold
        }
