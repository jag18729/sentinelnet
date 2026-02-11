#!/usr/bin/env python3
"""
TabNet baseline model for network intrusion detection.

TabNet (Arik & Pfister, 2019) is an attention-based architecture for tabular data.
Key advantages:
- Interpretable (built-in feature importance)
- Lightweight (1-5M params typical)
- Trainable entirely on Pi 5 (edge training demonstration)

This provides a unique research angle: demonstrating edge-deployable TRAINING,
not just inference.
"""

import numpy as np
from pathlib import Path
from typing import Optional, Tuple
import pickle


def train_tabnet(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    n_d: int = 8,
    n_a: int = 8,
    n_steps: int = 3,
    gamma: float = 1.3,
    lr: float = 0.02,
    max_epochs: int = 100,
    patience: int = 15,
    batch_size: int = 256,
    save_path: Optional[Path] = None,
) -> Tuple:
    """
    Train TabNet classifier.
    
    Args:
        X_train, y_train: Training data
        X_val, y_val: Validation data
        n_d, n_a: Width of decision/attention embeddings (reduced for Pi)
        n_steps: Number of decision steps
        gamma: Coefficient for feature reusage
        lr: Learning rate
        max_epochs: Maximum training epochs
        patience: Early stopping patience
        batch_size: Batch size
        save_path: Optional path to save model
        
    Returns:
        Trained TabNetClassifier, training history
    """
    try:
        from pytorch_tabnet.tab_model import TabNetClassifier
    except ImportError:
        raise ImportError(
            "pytorch-tabnet not installed. Run: pip install pytorch-tabnet"
        )
    
    clf = TabNetClassifier(
        n_d=n_d,
        n_a=n_a,
        n_steps=n_steps,
        gamma=gamma,
        optimizer_params=dict(lr=lr),
        scheduler_params=dict(step_size=10, gamma=0.9),
        scheduler_fn=None,  # Use default
        device_name='cpu',  # Pi 5 CPU only
        verbose=1,
    )
    
    clf.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        eval_name=['val'],
        eval_metric=['accuracy', 'logloss'],
        max_epochs=max_epochs,
        patience=patience,
        batch_size=batch_size,
    )
    
    if save_path:
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        clf.save_model(str(save_path))
        print(f"[✓] TabNet model saved to {save_path}")
    
    return clf, clf.history


def get_feature_importance(clf, feature_names: list) -> dict:
    """
    Extract feature importance from trained TabNet.
    
    This is a key advantage of TabNet - built-in interpretability.
    """
    importances = clf.feature_importances_
    return dict(sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True
    ))


def load_tabnet(model_path: Path):
    """Load saved TabNet model."""
    from pytorch_tabnet.tab_model import TabNetClassifier
    clf = TabNetClassifier()
    clf.load_model(str(model_path))
    return clf


if __name__ == "__main__":
    # Quick test with synthetic data
    print("[*] Testing TabNet with synthetic data...")
    
    np.random.seed(42)
    X = np.random.randn(1000, 78).astype(np.float32)
    y = np.random.randint(0, 5, 1000)
    
    X_train, X_val = X[:800], X[800:]
    y_train, y_val = y[:800], y[800:]
    
    clf, history = train_tabnet(
        X_train, y_train,
        X_val, y_val,
        max_epochs=5,
        n_d=4, n_a=4,  # Very small for test
    )
    
    print(f"[✓] Final val accuracy: {history['val_accuracy'][-1]:.4f}")
    print(f"[✓] TabNet test complete")
