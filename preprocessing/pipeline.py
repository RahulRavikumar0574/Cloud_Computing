import pandas as pd
import numpy as np
import json
import argparse
import pickle
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import os

class SessionWindowBuilder:
    def __init__(self, window_size_events: int = 50):
        self.window_size_events = window_size_events

    def build_windows(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Group by container_id and pod_name
        grouped_events = defaultdict(list)
        for log in logs:
            key = (log.get("container_id", "unknown"), log.get("pod_name", "unknown"))
            grouped_events[key].append(log)

        windows = []
        for key, events in grouped_events.items():
            # Sort events by timestamp (if epoch_time is available, prefer it, otherwise fallback to timestamp string)
            events.sort(key=lambda x: x.get("epoch_time", x.get("timestamp", "")))
            
            for i in range(0, len(events), self.window_size_events):
                chunk = events[i:i + self.window_size_events]
                
                is_threat = 1 if any(e.get("is_threat", 0) == 1 for e in chunk) else 0
                attack_type = "None"
                if is_threat:
                    # Find the primary attack type
                    attack_types = [e.get("attack_type") for e in chunk if e.get("is_threat") == 1]
                    if attack_types:
                        attack_type = attack_types[0]
                
                windows.append({
                    "container_id": key[0],
                    "pod_name": key[1],
                    "events": chunk,
                    "is_threat": is_threat,
                    "attack_type": attack_type
                })
        return windows

class TabularFeatureExtractor:
    def __init__(self):
        self.high_risk_syscalls = ["mount", "ptrace", "nsenter", "chroot", "capset", "process_vm_writev", "connect"]
        self.feature_cols = None

    def extract(self, windows: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, np.ndarray]:
        features_list = []
        labels = []
        
        for w in windows:
            events = w["events"]
            num_events = len(events)
            if num_events == 0:
                continue
            
            # Frequencies
            syscall_counts = defaultdict(int)
            unique_syscalls = set()
            unique_processes = set()
            failed_syscalls = 0
            
            for e in events:
                syscall = e.get("syscall", "")
                syscall_counts[syscall] += 1
                unique_syscalls.add(syscall)
                unique_processes.add(e.get("process_name", ""))
                
                if e.get("return_value", 0) == -1:
                    failed_syscalls += 1
            
            features = {}
            for syscall in self.high_risk_syscalls:
                features[f"count_{syscall}"] = syscall_counts[syscall]
                
            features["ratio_unique_syscalls"] = len(unique_syscalls) / num_events
            features["ratio_failed_syscalls"] = failed_syscalls / num_events
            features["event_burst_count"] = num_events
            features["unique_process_count"] = len(unique_processes)
            
            features_list.append(features)
            labels.append(w["is_threat"])
            
        df = pd.DataFrame(features_list)
        # Fill missing with 0
        df.fillna(0, inplace=True)
        self.feature_cols = df.columns.tolist()
        
        return df, np.array(labels)

class SequenceTokenizer:
    def __init__(self, max_seq_len: int = 50):
        self.max_seq_len = max_seq_len
        self.vocab = {"<PAD>": 0, "<UNK>": 1}
        self.next_idx = 2

    def fit(self, windows: List[Dict[str, Any]]):
        for w in windows:
            for e in w["events"]:
                syscall = e.get("syscall")
                if syscall and syscall not in self.vocab:
                    self.vocab[syscall] = self.next_idx
                    self.next_idx += 1

    def transform(self, windows: List[Dict[str, Any]]) -> np.ndarray:
        sequences = []
        for w in windows:
            seq = []
            for e in w["events"]:
                syscall = e.get("syscall")
                token = self.vocab.get(syscall, self.vocab["<UNK>"])
                seq.append(token)
                
            # Truncate
            if len(seq) > self.max_seq_len:
                seq = seq[:self.max_seq_len]
            # Pad
            elif len(seq) < self.max_seq_len:
                seq = seq + [self.vocab["<PAD>"]] * (self.max_seq_len - len(seq))
                
            sequences.append(seq)
            
        return np.array(sequences, dtype=np.int32)

class PipelineArtifacts:
    @staticmethod
    def save_artifacts(directory_path: str, tokenizer: SequenceTokenizer, tabular_extractor: TabularFeatureExtractor):
        path = Path(directory_path)
        path.mkdir(parents=True, exist_ok=True)
        
        with open(path / "tokenizer.pkl", "wb") as f:
            pickle.dump(tokenizer, f)
            
        with open(path / "tabular_extractor.pkl", "wb") as f:
            pickle.dump(tabular_extractor, f)
            
    @staticmethod
    def load_artifacts(directory_path: str) -> Tuple[SequenceTokenizer, TabularFeatureExtractor]:
        path = Path(directory_path)
        
        with open(path / "tokenizer.pkl", "rb") as f:
            tokenizer = pickle.load(f)
            
        with open(path / "tabular_extractor.pkl", "rb") as f:
            tabular_extractor = pickle.load(f)
            
        return tokenizer, tabular_extractor

def main():
    parser = argparse.ArgumentParser(description="Preprocessing Pipeline")
    parser.add_argument("--input-path", type=str, default="data/raw_ebpf_logs.json")
    parser.add_argument("--tabular-output", type=str, default="data/processed_tabular.csv")
    parser.add_argument("--sequence-output", type=str, default="data/processed_sequences.npy")
    parser.add_argument("--artifacts-dir", type=str, default="artifacts")
    
    args = parser.parse_args()
    
    # Needs telemetry.log_parser
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from telemetry.log_parser import parse_log_line
    
    logs = []
    if os.path.exists(args.input_path):
        with open(args.input_path, "r") as f:
            for line in f:
                record = parse_log_line(line)
                if record:
                    logs.append(record)
    else:
        print(f"Input file not found: {args.input_path}")
        return

    print(f"Loaded {len(logs)} parsed events.")
    
    window_builder = SessionWindowBuilder(window_size_events=50)
    windows = window_builder.build_windows(logs)
    print(f"Generated {len(windows)} session windows.")
    
    tabular_extractor = TabularFeatureExtractor()
    X_tabular, y_tabular = tabular_extractor.extract(windows)
    
    tokenizer = SequenceTokenizer(max_seq_len=50)
    tokenizer.fit(windows)
    X_seq = tokenizer.transform(windows)
    
    print(f"X_tabular shape: {X_tabular.shape}")
    print(f"y shape: {y_tabular.shape}")
    print(f"X_seq shape: {X_seq.shape}")
    
    # Save outputs
    Path(args.tabular_output).parent.mkdir(parents=True, exist_ok=True)
    X_tabular["label"] = y_tabular
    X_tabular.to_csv(args.tabular_output, index=False)
    
    Path(args.sequence_output).parent.mkdir(parents=True, exist_ok=True)
    np.save(args.sequence_output, X_seq)
    
    # Save artifacts
    PipelineArtifacts.save_artifacts(args.artifacts_dir, tokenizer, tabular_extractor)
    print("Preprocessing completed and artifacts saved.")

if __name__ == "__main__":
    main()
