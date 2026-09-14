import pytest
import torch
import numpy as np
import xgboost as xgb
from models.bilstm_model import SyscallBiLSTM, train_bilstm
from models.xgboost_model import train_xgboost

def test_bilstm_forward_pass():
    vocab_size = 10
    max_seq_len = 50
    batch_size = 4
    
    model = SyscallBiLSTM(vocab_size=vocab_size, embedding_dim=16, hidden_dim=16, num_layers=1)
    
    # Dummy input
    X = torch.randint(0, vocab_size, (batch_size, max_seq_len))
    
    out = model(X)
    
    assert out.shape == (batch_size,)

def test_xgboost_interface():
    # Dummy data
    X_train = np.random.rand(100, 5)
    y_train = np.random.randint(0, 2, 100)
    X_val = np.random.rand(20, 5)
    y_val = np.random.randint(0, 2, 20)
    
    model, metrics = train_xgboost(X_train, y_train, X_val, y_val)
    
    assert isinstance(model, xgb.XGBClassifier)
    assert "logloss" in metrics
    assert "roc_auc" in metrics
    
    preds = model.predict(X_val)
    assert len(preds) == 20
