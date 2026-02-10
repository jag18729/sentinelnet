#!/usr/bin/env python3
"""
SentinelNet: Hybrid 1D-CNN + BiLSTM for network intrusion detection.

Architecture:
- 1D Conv blocks extract local feature patterns from flow data
- BiLSTM captures temporal/sequential dependencies
- Classification head outputs multi-class attack probabilities
"""

import torch
import torch.nn as nn
from typing import Optional


class SentinelNet(nn.Module):
    """
    Hybrid 1D-CNN + BiLSTM for network intrusion detection.
    
    Args:
        input_dim: Number of input features per flow
        num_classes: Number of output classes (attack types + benign)
        hidden_dim: LSTM hidden dimension
        num_layers: Number of LSTM layers
        dropout: Dropout probability
    """
    
    def __init__(
        self,
        input_dim: int,
        num_classes: int,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super(SentinelNet, self).__init__()
        
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.hidden_dim = hidden_dim
        
        # 1D Convolutional feature extractor
        self.conv_block = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(input_dim // 2)
        )
        
        # Bidirectional LSTM for sequential patterns
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes)
        )
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        """Initialize model weights."""
        for m in self.modules():
            if isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
            elif isinstance(m, nn.BatchNorm1d):
                nn.init.constant_(m.weight, 1)
                nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                nn.init.constant_(m.bias, 0)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Input tensor of shape (batch, features)
            
        Returns:
            Logits tensor of shape (batch, num_classes)
        """
        # x shape: (batch, features)
        x = x.unsqueeze(1)  # (batch, 1, features) for Conv1d
        
        # CNN feature extraction
        conv_out = self.conv_block(x)  # (batch, 128, features//2)
        conv_out = conv_out.permute(0, 2, 1)  # (batch, features//2, 128) for LSTM
        
        # BiLSTM temporal modeling
        lstm_out, _ = self.lstm(conv_out)  # (batch, seq_len, hidden*2)
        
        # Use final hidden state
        final = lstm_out[:, -1, :]  # (batch, hidden*2)
        
        # Classification
        logits = self.classifier(final)
        
        return logits
    
    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Get class predictions."""
        with torch.no_grad():
            logits = self.forward(x)
            return logits.argmax(dim=1)
    
    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Get class probabilities."""
        with torch.no_grad():
            logits = self.forward(x)
            return torch.softmax(logits, dim=1)


class BaselineMLP(nn.Module):
    """Simple MLP baseline for comparison."""
    
    def __init__(
        self,
        input_dim: int,
        num_classes: int,
        hidden_dims: list = [256, 128, 64],
        dropout: float = 0.3,
    ):
        super(BaselineMLP, self).__init__()
        
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev_dim = hidden_dim
        
        layers.append(nn.Linear(prev_dim, num_classes))
        
        self.network = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


def get_model(
    model_name: str,
    input_dim: int,
    num_classes: int,
    **kwargs
) -> nn.Module:
    """Factory function to get model by name."""
    models = {
        "sentinelnet": SentinelNet,
        "mlp": BaselineMLP,
    }
    
    if model_name not in models:
        raise ValueError(f"Unknown model: {model_name}. Available: {list(models.keys())}")
    
    return models[model_name](input_dim=input_dim, num_classes=num_classes, **kwargs)


if __name__ == "__main__":
    # Test model
    batch_size = 32
    input_dim = 78  # CICIDS2017 has ~78 features
    num_classes = 15  # CICIDS2017 has 15 classes
    
    model = SentinelNet(input_dim=input_dim, num_classes=num_classes)
    x = torch.randn(batch_size, input_dim)
    
    output = model(x)
    print(f"Input shape: {x.shape}")
    print(f"Output shape: {output.shape}")
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
