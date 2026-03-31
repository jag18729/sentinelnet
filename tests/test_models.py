"""Tests for SentinelNet model architecture and factory."""

import pytest
import torch
import torch.nn as nn

from models.sentinel_net import SentinelNet, BaselineMLP, get_model


class TestSentinelNet:
    """Tests for the SentinelNet CNN+BiLSTM model."""

    def test_forward_shape(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        x = torch.randn(32, 78)
        out = model(x)
        assert out.shape == (32, 15)

    def test_single_sample(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        x = torch.randn(1, 78)
        out = model(x)
        assert out.shape == (1, 15)

    def test_predict_returns_class_ids(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        x = torch.randn(8, 78)
        preds = model.predict(x)
        assert preds.shape == (8,)
        assert preds.min() >= 0
        assert preds.max() < 15

    def test_predict_proba_sums_to_one(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        x = torch.randn(4, 78)
        probs = model.predict_proba(x)
        assert probs.shape == (4, 15)
        sums = probs.sum(dim=1)
        assert torch.allclose(sums, torch.ones(4), atol=1e-5)

    def test_different_input_dims(self):
        for dim in [10, 50, 78, 128]:
            model = SentinelNet(input_dim=dim, num_classes=5)
            x = torch.randn(4, dim)
            out = model(x)
            assert out.shape == (4, 5)

    def test_different_hidden_dims(self):
        model = SentinelNet(input_dim=78, num_classes=15, hidden_dim=64, num_layers=1)
        x = torch.randn(4, 78)
        out = model(x)
        assert out.shape == (4, 15)

    def test_gradients_flow(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        x = torch.randn(4, 78)
        y = torch.randint(0, 15, (4,))
        logits = model(x)
        loss = nn.CrossEntropyLoss()(logits, y)
        loss.backward()
        for name, param in model.named_parameters():
            assert param.grad is not None, f"No gradient for {name}"

    def test_eval_mode_no_grad(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        model.eval()
        x = torch.randn(4, 78)
        with torch.no_grad():
            out = model(x)
        assert out.shape == (4, 15)

    def test_parameter_count_positive(self):
        model = SentinelNet(input_dim=78, num_classes=15)
        param_count = sum(p.numel() for p in model.parameters())
        assert param_count > 0


class TestBaselineMLP:
    """Tests for the baseline MLP model."""

    def test_forward_shape(self):
        model = BaselineMLP(input_dim=78, num_classes=15)
        x = torch.randn(16, 78)
        out = model(x)
        assert out.shape == (16, 15)

    def test_custom_hidden_dims(self):
        model = BaselineMLP(input_dim=78, num_classes=10, hidden_dims=[128, 64])
        x = torch.randn(4, 78)
        out = model(x)
        assert out.shape == (4, 10)


class TestModelFactory:
    """Tests for the get_model factory function."""

    def test_get_sentinelnet(self):
        model = get_model("sentinelnet", input_dim=78, num_classes=15)
        assert isinstance(model, SentinelNet)

    def test_get_mlp(self):
        model = get_model("mlp", input_dim=78, num_classes=15)
        assert isinstance(model, BaselineMLP)

    def test_unknown_model_raises(self):
        with pytest.raises(ValueError, match="Unknown model"):
            get_model("transformer", input_dim=78, num_classes=15)
