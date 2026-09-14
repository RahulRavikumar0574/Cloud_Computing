import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.bilstm_model import train_bilstm, save_bilstm_model
from models.xgboost_model import train_xgboost, save_xgboost_model

def get_vocab_size(artifacts_dir):
    sys.path.append(str(Path(__file__).parent.parent))
    from preprocessing.pipeline import PipelineArtifacts
    try:
        tokenizer, _ = PipelineArtifacts.load_artifacts(artifacts_dir)
        return len(tokenizer.vocab)
    except Exception:
        return 100 # Fallback

def ensure_sufficient_data(tabular_path, sequence_path, raw_log_path):
    if not Path(tabular_path).exists() or not Path(sequence_path).exists():
        rows = 0
    else:
        df = pd.read_csv(tabular_path)
        rows = len(df)
        
    if rows < 100:
        print(f"Insufficient data ({rows} rows). Regenerating logs and preprocessing...")
        # Run simulator
        subprocess.run([sys.executable, "telemetry/attack_simulator.py", "--num-sessions", "200", "--output-path", raw_log_path], check=True)
        # Run preprocessing
        subprocess.run([sys.executable, "preprocessing/pipeline.py", "--input-path", raw_log_path, "--tabular-output", tabular_path, "--sequence-output", sequence_path, "--artifacts-dir", "artifacts"], check=True)
        
def main():
    parser = argparse.ArgumentParser(description="Unified Model Training Orchestrator")
    parser.add_argument("--tabular-path", type=str, default="data/processed_tabular.csv")
    parser.add_argument("--sequence-path", type=str, default="data/processed_sequences.npy")
    parser.add_argument("--raw-log-path", type=str, default="data/raw_ebpf_logs.json")
    parser.add_argument("--artifacts-dir", type=str, default="artifacts")
    
    args = parser.parse_args()
    
    ensure_sufficient_data(args.tabular_path, args.sequence_path, args.raw_log_path)
    
    print("Loading data...")
    df = pd.read_csv(args.tabular_path)
    X_seq = np.load(args.sequence_path)
    
    y = df["label"].values
    X_tab = df.drop(columns=["label"]).values
    
    # Train-test split (stratified)
    X_tab_train, X_tab_val, X_seq_train, X_seq_val, y_train, y_val = train_test_split(
        X_tab, X_seq, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training XGBoost on {len(X_tab_train)} samples...")
    xgb_model, xgb_metrics = train_xgboost(X_tab_train, y_train, X_tab_val, y_val)
    
    vocab_size = get_vocab_size(args.artifacts_dir)
    print(f"Training BiLSTM on {len(X_seq_train)} samples (vocab size: {vocab_size})...")
    bilstm_model, bilstm_metrics = train_bilstm(X_seq_train, y_train, X_seq_val, y_val, vocab_size=vocab_size, epochs=10)
    
    # Save artifacts
    print("Saving models...")
    save_xgboost_model(xgb_model, args.artifacts_dir)
    save_bilstm_model(bilstm_model, args.artifacts_dir)
    
    print("\n--- Performance Comparison ---")
    print(f"{'Metric':<15} | {'XGBoost':<15} | {'BiLSTM':<15}")
    print("-" * 50)
    
    metrics_list = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    for m in metrics_list:
        xgb_val = xgb_metrics.get(m, 0.0)
        bilstm_val = bilstm_metrics.get(m, 0.0)
        print(f"{m.capitalize():<15} | {xgb_val:<15.4f} | {bilstm_val:<15.4f}")

if __name__ == "__main__":
    main()
