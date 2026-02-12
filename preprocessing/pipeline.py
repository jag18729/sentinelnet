#!/usr/bin/env python3
"""
Data preprocessing pipeline for network flow classification.

Handles:
- Loading CSV datasets (CICIDS2017, CSE-CIC-IDS2018)
- Cleaning inf/nan values
- Label encoding
- Feature normalization
- Train/val/test splitting
- PyTorch DataLoader creation
"""

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from pathlib import Path
from typing import Tuple, Optional
import pickle


class NetworkFlowDataset(Dataset):
    """PyTorch dataset for network flow classification."""
    
    def __init__(self, features: np.ndarray, labels: np.ndarray):
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels)
    
    def __len__(self) -> int:
        return len(self.labels)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.features[idx], self.labels[idx]


def load_cicids2017(data_dir: Path) -> pd.DataFrame:
    """Load CICIDS2017 from parquet shards or CSV files."""
    # Try parquet first (preferred - faster, smaller)
    parquet_files = sorted(data_dir.glob("train-*.parquet"))
    if parquet_files:
        print(f"[*] Loading {len(parquet_files)} parquet shards...")
        dfs = []
        for pf in parquet_files:
            print(f"    - {pf.name}")
            dfs.append(pd.read_parquet(pf))
        return pd.concat(dfs, ignore_index=True)

    # Fallback to CSV
    csv_dir = data_dir / "raw" / "cicids2017" / "MachineLearningCSV" / "MachineLearningCVE"
    if not csv_dir.exists():
        csv_dir = data_dir / "raw" / "cicids2017"
    
    csv_files = list(csv_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No parquet or CSV files found in {data_dir}")
    
    print(f"[*] Loading {len(csv_files)} CSV files...")
    dfs = []
    for csv_file in csv_files:
        print(f"    - {csv_file.name}")
        df = pd.read_csv(csv_file, low_memory=False)
        dfs.append(df)
    
    return pd.concat(dfs, ignore_index=True)


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean dataset: handle inf/nan, strip whitespace from columns."""
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Replace inf with nan, then drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    initial_len = len(df)
    df.dropna(inplace=True)
    dropped = initial_len - len(df)
    
    if dropped > 0:
        print(f"[*] Dropped {dropped:,} rows with inf/nan values ({dropped/initial_len*100:.2f}%)")
    
    return df


def build_dataloaders(
    csv_path: Optional[Path] = None,
    df: Optional[pd.DataFrame] = None,
    batch_size: int = 256,
    val_split: float = 0.15,
    test_split: float = 0.15,
    random_state: int = 42,
    save_artifacts: Optional[Path] = None,
) -> Tuple[DataLoader, DataLoader, DataLoader, LabelEncoder, StandardScaler, list]:
    """
    Build train/val/test DataLoaders from CSV or DataFrame.
    
    Returns:
        train_loader, val_loader, test_loader, label_encoder, scaler, feature_names
    """
    # Load data
    if df is None:
        if csv_path is None:
            raise ValueError("Must provide either csv_path or df")
        df = pd.read_csv(csv_path, low_memory=False)
    
    # Clean
    df = clean_dataframe(df)
    
    # Identify label column (CICIDS uses ' Label' with space, normalize it)
    label_col = None
    for col in ['Label', ' Label', 'label']:
        if col in df.columns:
            label_col = col
            break
    
    if label_col is None:
        raise ValueError(f"No label column found. Columns: {df.columns.tolist()}")
    
    # Encode labels
    label_encoder = LabelEncoder()
    labels = label_encoder.fit_transform(df[label_col])
    
    print(f"[*] Classes ({len(label_encoder.classes_)}): {label_encoder.classes_.tolist()}")
    
    # Extract features
    feature_cols = [c for c in df.columns if c != label_col]
    features = df[feature_cols].values.astype(np.float32)
    
    print(f"[*] Features: {features.shape[1]}, Samples: {features.shape[0]:,}")
    
    # Normalize
    scaler = StandardScaler()
    features = scaler.fit_transform(features)
    
    # Stratified split
    X_train, X_temp, y_train, y_temp = train_test_split(
        features, labels,
        test_size=(val_split + test_split),
        stratify=labels,
        random_state=random_state
    )
    
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=test_split / (val_split + test_split),
        stratify=y_temp,
        random_state=random_state
    )
    
    print(f"[*] Split: train={len(y_train):,}, val={len(y_val):,}, test={len(y_test):,}")
    
    # Create DataLoaders
    train_loader = DataLoader(
        NetworkFlowDataset(X_train, y_train),
        batch_size=batch_size,
        shuffle=True,
        num_workers=2,
        pin_memory=True,
    )
    
    val_loader = DataLoader(
        NetworkFlowDataset(X_val, y_val),
        batch_size=batch_size,
        num_workers=2,
        pin_memory=True,
    )
    
    test_loader = DataLoader(
        NetworkFlowDataset(X_test, y_test),
        batch_size=batch_size,
        num_workers=2,
        pin_memory=True,
    )
    
    # Save artifacts if requested
    if save_artifacts:
        save_artifacts.mkdir(parents=True, exist_ok=True)
        with open(save_artifacts / "label_encoder.pkl", "wb") as f:
            pickle.dump(label_encoder, f)
        with open(save_artifacts / "scaler.pkl", "wb") as f:
            pickle.dump(scaler, f)
        with open(save_artifacts / "feature_names.pkl", "wb") as f:
            pickle.dump(feature_cols, f)
        print(f"[✓] Saved artifacts to {save_artifacts}")
    
    return train_loader, val_loader, test_loader, label_encoder, scaler, feature_cols


if __name__ == "__main__":
    # Test with CICIDS2017
    data_dir = Path(__file__).parent.parent / "data"
    df = load_cicids2017(data_dir)
    train_loader, val_loader, test_loader, le, scaler, features = build_dataloaders(
        df=df,
        batch_size=256,
        save_artifacts=data_dir / "artifacts"
    )
    print(f"[✓] DataLoaders ready")
