import pytest
import numpy as np
import pandas as pd
import tempfile
import os
from preprocessing.pipeline import SessionWindowBuilder, TabularFeatureExtractor, SequenceTokenizer, PipelineArtifacts

def test_session_window_builder():
    builder = SessionWindowBuilder(window_size_events=2)
    logs = [
        {"container_id": "c1", "pod_name": "p1", "timestamp": "2026-09-08T10:00:00Z", "epoch_time": 1, "is_threat": 0, "attack_type": "None"},
        {"container_id": "c1", "pod_name": "p1", "timestamp": "2026-09-08T10:00:01Z", "epoch_time": 2, "is_threat": 1, "attack_type": "priv_escape"},
        {"container_id": "c1", "pod_name": "p1", "timestamp": "2026-09-08T10:00:02Z", "epoch_time": 3, "is_threat": 0, "attack_type": "None"},
    ]
    windows = builder.build_windows(logs)
    assert len(windows) == 2
    assert windows[0]["is_threat"] == 1
    assert windows[0]["attack_type"] == "priv_escape"
    assert len(windows[0]["events"]) == 2
    
    assert windows[1]["is_threat"] == 0
    assert len(windows[1]["events"]) == 1

def test_tabular_feature_extractor():
    extractor = TabularFeatureExtractor()
    windows = [{
        "is_threat": 1,
        "events": [
            {"syscall": "mount", "process_name": "bash", "return_value": 0},
            {"syscall": "mount", "process_name": "bash", "return_value": -1},
            {"syscall": "read", "process_name": "bash", "return_value": 0}
        ]
    }]
    X, y = extractor.extract(windows)
    
    assert len(X) == 1
    assert len(y) == 1
    assert y[0] == 1
    assert X["count_mount"][0] == 2
    assert X["ratio_failed_syscalls"][0] == pytest.approx(1/3)
    assert X["unique_process_count"][0] == 1
    assert X["ratio_unique_syscalls"][0] == pytest.approx(2/3)

def test_sequence_tokenizer():
    tokenizer = SequenceTokenizer(max_seq_len=3)
    windows = [{
        "events": [
            {"syscall": "read"},
            {"syscall": "write"},
            {"syscall": "open"}
        ]
    }, {
        "events": [
            {"syscall": "read"}
        ]
    }]
    
    tokenizer.fit(windows)
    X = tokenizer.transform(windows)
    
    assert X.shape == (2, 3)
    # Check padding
    assert X[1][1] == 0
    assert X[1][2] == 0
    
def test_save_load_artifacts():
    tokenizer = SequenceTokenizer(max_seq_len=10)
    tokenizer.vocab["test_syscall"] = 2
    extractor = TabularFeatureExtractor()
    
    with tempfile.TemporaryDirectory() as d:
        PipelineArtifacts.save_artifacts(d, tokenizer, extractor)
        t_loaded, e_loaded = PipelineArtifacts.load_artifacts(d)
        
        assert t_loaded.max_seq_len == 10
        assert "test_syscall" in t_loaded.vocab
        assert e_loaded.high_risk_syscalls == extractor.high_risk_syscalls
