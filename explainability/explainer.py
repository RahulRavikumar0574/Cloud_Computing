import shap
import xgboost as xgb
import json
import numpy as np

class RuntimeXAIExplainer:
    def __init__(self, model_path: str, feature_names: list[str] = None):
        """
        Initializes the RuntimeXAIExplainer.
        
        Args:
            model_path: Path to the saved XGBoost model JSON file.
            feature_names: Optional list of feature names for SHAP.
        """
        self.model_path = model_path
        self.feature_names = feature_names
        
        # Load the XGBoost model
        self.model = xgb.XGBClassifier()
        self.model.load_model(self.model_path)
        
        # Initialize the SHAP TreeExplainer
        # Using the underlying booster for SHAP TreeExplainer
        self.explainer = shap.TreeExplainer(self.model)

    def explain_session(self, session_features: np.ndarray, feature_names: list[str] = None) -> dict:
        """
        Explains a single session feature vector.
        
        Args:
            session_features: 1D or 2D numpy array containing features for a single session.
            feature_names: Optional feature names to override defaults.
            
        Returns:
            dict: Containing predicted probability, top attributions, and a method for JSON.
        """
        # Ensure 2D array
        if session_features.ndim == 1:
            session_features = session_features.reshape(1, -1)
            
        # Get prediction probability for class 1 (escape risk)
        probs = self.model.predict_proba(session_features)
        risk_score = float(probs[0, 1]) if probs.shape[1] > 1 else float(probs[0])
        
        # Calculate SHAP values
        shap_values = self.explainer.shap_values(session_features)
        
        # Depending on objective, shap_values might be a list (multiclass) or array
        if isinstance(shap_values, list):
            shap_values = shap_values[1] # Take class 1
            
        # Since it's a single session, take the first row
        instance_shap = shap_values[0]
        
        # Get feature names
        names = feature_names or self.feature_names or [f"feature_{i}" for i in range(session_features.shape[1])]
        
        # Pair feature names with their shap values
        attributions = list(zip(names, instance_shap))
        
        # Sort by absolute contribution (highest first)
        attributions.sort(key=lambda x: abs(x[1]), reverse=True)
        
        top_indicators = [
            {"feature": name, "contribution": float(val), "description": f"{name} contributed {'+' if val > 0 else ''}{val:.4f} to breakout risk"}
            for name, val in attributions[:5] # Top 5
        ]
        
        result = {
            "risk_score": risk_score,
            "top_indicators": top_indicators
        }
        
        return result
    
    def serialize_payload(self, result: dict) -> str:
        """Serializes the result to a JSON payload for SOC dashboards."""
        return json.dumps(result, indent=2)
