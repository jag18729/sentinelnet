"""Tests for data preprocessing pipeline."""

import pytest
import numpy as np
import pandas as pd
import torch

from preprocessing.pipeline import (
    NetworkFlowDataset,
    clean_dataframe,
    build_dataloaders,
)


class TestNetworkFlowDataset:

    def test_length(self):
        features = np.random.randn(100, 78).astype(np.float32)
        labels = np.random.randint(0, 15, 100)
        ds = NetworkFlowDataset(features, labels)
        assert len(ds) == 100

    def test_getitem_types(self):
        features = np.random.randn(10, 78).astype(np.float32)
        labels = np.random.randint(0, 5, 10)
        ds = NetworkFlowDataset(features, labels)
        x, y = ds[0]
        assert isinstance(x, torch.Tensor)
        assert isinstance(y, torch.Tensor)
        assert x.dtype == torch.float32
        assert y.dtype == torch.int64

    def test_feature_shape(self):
        features = np.random.randn(10, 78).astype(np.float32)
        labels = np.random.randint(0, 5, 10)
        ds = NetworkFlowDataset(features, labels)
        x, y = ds[3]
        assert x.shape == (78,)
        assert y.shape == ()


class TestCleanDataframe:

    def test_removes_inf_values(self):
        df = pd.DataFrame({
            "a": [1.0, np.inf, 3.0],
            "b": [4.0, 5.0, -np.inf],
        })
        cleaned = clean_dataframe(df)
        assert len(cleaned) == 1
        assert not np.any(np.isinf(cleaned.values))

    def test_removes_nan_values(self):
        df = pd.DataFrame({
            "a": [1.0, np.nan, 3.0],
            "b": [4.0, 5.0, 6.0],
        })
        cleaned = clean_dataframe(df)
        assert len(cleaned) == 2
        assert not cleaned.isnull().any().any()

    def test_strips_column_whitespace(self):
        df = pd.DataFrame({" col1 ": [1], "col2 ": [2]})
        cleaned = clean_dataframe(df)
        assert list(cleaned.columns) == ["col1", "col2"]

    def test_no_data_lost_when_clean(self):
        df = pd.DataFrame({"a": [1.0, 2.0], "b": [3.0, 4.0]})
        cleaned = clean_dataframe(df)
        assert len(cleaned) == 2


class TestBuildDataloaders:

    @pytest.fixture
    def sample_df(self):
        np.random.seed(42)
        n = 200
        features = np.random.randn(n, 5).astype(np.float32)
        labels = np.random.choice(["BENIGN", "DoS", "Probe"], n)
        df = pd.DataFrame(features, columns=[f"feat_{i}" for i in range(5)])
        df["Label"] = labels
        return df

    def test_returns_seven_items(self, sample_df):
        result = build_dataloaders(df=sample_df, batch_size=32)
        assert len(result) == 7

    def test_loader_produces_batches(self, sample_df):
        train_loader, val_loader, test_loader, le, scaler, fnames, cw = build_dataloaders(
            df=sample_df, batch_size=32
        )
        batch_x, batch_y = next(iter(train_loader))
        assert batch_x.shape[1] == 5
        assert batch_y.shape[0] == batch_x.shape[0]

    def test_label_encoder_has_classes(self, sample_df):
        _, _, _, le, _, _, _ = build_dataloaders(df=sample_df, batch_size=32)
        assert len(le.classes_) == 3
        assert "BENIGN" in le.classes_

    def test_scaler_fitted(self, sample_df):
        _, _, _, _, scaler, _, _ = build_dataloaders(df=sample_df, batch_size=32)
        assert hasattr(scaler, "mean_")
        assert len(scaler.mean_) == 5

    def test_feature_names_returned(self, sample_df):
        _, _, _, _, _, fnames, _ = build_dataloaders(df=sample_df, batch_size=32)
        assert len(fnames) == 5
        assert all(f.startswith("feat_") for f in fnames)

    def test_class_weights_returned(self, sample_df):
        _, _, _, le, _, _, class_weights = build_dataloaders(df=sample_df, batch_size=32)
        assert len(class_weights) == len(le.classes_)
        assert all(w > 0 for w in class_weights)

    def test_no_label_column_raises(self):
        df = pd.DataFrame({"a": [1.0], "b": [2.0]})
        with pytest.raises(ValueError, match="No label column"):
            build_dataloaders(df=df)

    def test_no_data_source_raises(self):
        with pytest.raises(ValueError, match="Must provide"):
            build_dataloaders()

    def test_save_artifacts(self, sample_df, tmp_path):
        build_dataloaders(df=sample_df, batch_size=32, save_artifacts=tmp_path)
        assert (tmp_path / "label_encoder.pkl").exists()
        assert (tmp_path / "scaler.pkl").exists()
        assert (tmp_path / "feature_names.pkl").exists()
