import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import numpy as np
from pathlib import Path

class SyscallBiLSTM(nn.Module):
    def __init__(self, vocab_size, embedding_dim=64, hidden_dim=64, num_layers=2, dropout=0.2):
        super(SyscallBiLSTM, self).__init__()
        self.embedding = nn.Embedding(num_embeddings=vocab_size, embedding_dim=embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )
        self.fc = nn.Linear(hidden_dim * 2, 1)
        
    def forward(self, x):
        if x.dim() == 1:
            x = x.unsqueeze(0)
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        
        # Calculate actual lengths excluding padding token 0
        lengths = (x != 0).sum(dim=1).clamp(min=1)
        batch_size = x.size(0)
        hidden_dim = self.lstm.hidden_size
        
        # Extract forward feature at last valid token and backward feature at token 0
        forward_feats = lstm_out[:, :, :hidden_dim]
        backward_feats = lstm_out[:, :, hidden_dim:]
        
        idx = (lengths - 1).long()
        last_forward = forward_feats[torch.arange(batch_size, device=x.device), idx, :]
        first_backward = backward_feats[:, 0, :]
        
        pooled = torch.cat([last_forward, first_backward], dim=-1)
        out = self.fc(pooled)
        return out.squeeze(-1)

class SyscallDataset(Dataset):
    def __init__(self, X_seq, y):
        self.X = torch.tensor(X_seq, dtype=torch.long)
        self.y = torch.tensor(y, dtype=torch.float32)
        
    def __len__(self):
        return len(self.X)
        
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

def train_bilstm(X_train, y_train, X_val, y_val, vocab_size, batch_size=32, epochs=50, lr=0.001, patience=5):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    train_dataset = SyscallDataset(X_train, y_train)
    val_dataset = SyscallDataset(X_val, y_val)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    
    model = SyscallBiLSTM(vocab_size=vocab_size).to(device)
    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    
    best_val_loss = float('inf')
    epochs_no_improve = 0
    best_model_state = None
    
    for epoch in range(epochs):
        model.train()
        train_loss = 0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            
            optimizer.zero_grad()
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()
            
        model.eval()
        val_loss = 0
        all_preds = []
        all_targets = []
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)
                val_loss += loss.item()
                
                probs = torch.sigmoid(outputs).cpu().numpy()
                all_preds.extend(probs)
                all_targets.extend(y_batch.cpu().numpy())
                
        val_loss /= len(val_loader)
        
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            epochs_no_improve = 0
            best_model_state = model.state_dict().copy()
        else:
            epochs_no_improve += 1
            
        if epochs_no_improve >= patience:
            break
            
    if best_model_state:
        model.load_state_dict(best_model_state)
    
    # Calculate final metrics on val set
    all_preds = np.array(all_preds)
    all_targets = np.array(all_targets)
    preds_binary = (all_preds > 0.5).astype(int)
    
    metrics = {
        "accuracy": accuracy_score(all_targets, preds_binary),
        "precision": precision_score(all_targets, preds_binary, zero_division=0),
        "recall": recall_score(all_targets, preds_binary, zero_division=0),
        "f1": f1_score(all_targets, preds_binary, zero_division=0),
        "roc_auc": roc_auc_score(all_targets, all_preds) if len(np.unique(all_targets)) > 1 else 0.5
    }
    
    return model, metrics

def save_bilstm_model(model, directory_path):
    path = Path(directory_path)
    path.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), path / "bilstm_model.pt")
