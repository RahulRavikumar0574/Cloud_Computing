import xgboost as xgb
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, log_loss, accuracy_score
import pandas as pd
import numpy as np
from pathlib import Path

def train_xgboost(X_train, y_train, X_val, y_val):
    model = xgb.XGBClassifier(
        learning_rate=0.1,
        max_depth=5,
        n_estimators=100,
        eval_metric='logloss',
        random_state=42,
        early_stopping_rounds=10
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    preds_proba = model.predict_proba(X_val)[:, 1]
    preds_binary = model.predict(X_val)
    
    metrics = {
        "logloss": log_loss(y_val, preds_proba),
        "accuracy": accuracy_score(y_val, preds_binary),
        "precision": precision_score(y_val, preds_binary, zero_division=0),
        "recall": recall_score(y_val, preds_binary, zero_division=0),
        "f1": f1_score(y_val, preds_binary, zero_division=0),
        "roc_auc": roc_auc_score(y_val, preds_proba) if len(np.unique(y_val)) > 1 else 0.5
    }
    
    return model, metrics

def save_xgboost_model(model, directory_path):
    path = Path(directory_path)
    path.mkdir(parents=True, exist_ok=True)
    model.save_model(path / "xgboost_model.json")
