"""Tests for adversarial attack implementations."""

import pytest
import torch

from models.sentinel_net import SentinelNet
from adversarial.attacks import (
    fgsm_attack,
    pgd_attack,
    cw_attack,
    get_attack,
    evaluate_robustness,
)


@pytest.fixture
def model():
    m = SentinelNet(input_dim=78, num_classes=15)
    m.eval()
    return m


@pytest.fixture
def sample_data():
    x = torch.randn(8, 78).clamp(0, 1)
    y = torch.randint(0, 15, (8,))
    return x, y


class TestFGSM:

    def test_output_shape(self, model, sample_data):
        x, y = sample_data
        x_adv = fgsm_attack(model, x, y, epsilon=0.1)
        assert x_adv.shape == x.shape

    def test_perturbation_bounded(self, model, sample_data):
        x, y = sample_data
        eps = 0.1
        x_adv = fgsm_attack(model, x, y, epsilon=eps)
        diff = (x_adv - x).abs().max()
        assert diff <= eps + 1e-6

    def test_clipping(self, model, sample_data):
        x, y = sample_data
        x_adv = fgsm_attack(model, x, y, epsilon=0.5, clip_min=0.0, clip_max=1.0)
        assert x_adv.min() >= 0.0
        assert x_adv.max() <= 1.0

    def test_adversarial_differs_from_input(self, model, sample_data):
        x, y = sample_data
        x_adv = fgsm_attack(model, x, y, epsilon=0.1)
        assert not torch.allclose(x_adv, x)


class TestPGD:

    def test_output_shape(self, model, sample_data):
        x, y = sample_data
        x_adv = pgd_attack(model, x, y, epsilon=0.1, num_steps=5)
        assert x_adv.shape == x.shape

    def test_perturbation_bounded(self, model, sample_data):
        x, y = sample_data
        eps = 0.1
        x_adv = pgd_attack(model, x, y, epsilon=eps, num_steps=5)
        diff = (x_adv - x).abs().max()
        assert diff <= eps + 1e-6

    def test_clipping(self, model, sample_data):
        x, y = sample_data
        x_adv = pgd_attack(model, x, y, epsilon=0.5, num_steps=5, clip_min=0.0, clip_max=1.0)
        assert x_adv.min() >= 0.0 - 1e-6
        assert x_adv.max() <= 1.0 + 1e-6

    def test_no_random_start(self, model, sample_data):
        x, y = sample_data
        x_adv = pgd_attack(model, x, y, epsilon=0.1, num_steps=3, random_start=False)
        assert x_adv.shape == x.shape


class TestCW:

    def test_output_shape(self, model, sample_data):
        x, y = sample_data
        x_adv = cw_attack(model, x, y, num_steps=10)
        assert x_adv.shape == x.shape

    def test_clipping(self, model, sample_data):
        x, y = sample_data
        x_adv = cw_attack(model, x, y, num_steps=10, clip_min=0.0, clip_max=1.0)
        assert x_adv.min() >= -0.1  # tanh mapping may go slightly outside
        assert x_adv.max() <= 1.1


class TestGetAttack:

    def test_get_fgsm(self, model, sample_data):
        x, y = sample_data
        attack_fn = get_attack("fgsm", epsilon=0.1)
        x_adv = attack_fn(model, x, y)
        assert x_adv.shape == x.shape

    def test_get_pgd(self, model, sample_data):
        x, y = sample_data
        attack_fn = get_attack("pgd", epsilon=0.1, num_steps=3)
        x_adv = attack_fn(model, x, y)
        assert x_adv.shape == x.shape

    def test_unknown_attack_raises(self):
        with pytest.raises(ValueError, match="Unknown attack"):
            get_attack("deepfool")


class TestEvaluateRobustness:

    def test_returns_clean_accuracy(self, model):
        x = torch.randn(16, 78).clamp(0, 1)
        y = torch.randint(0, 15, (16,))
        dataset = torch.utils.data.TensorDataset(x, y)
        loader = torch.utils.data.DataLoader(dataset, batch_size=8)

        results = evaluate_robustness(model, loader, {})
        assert "clean" in results
        assert "accuracy" in results["clean"]
        assert 0 <= results["clean"]["accuracy"] <= 1

    def test_includes_attack_results(self, model):
        x = torch.randn(16, 78).clamp(0, 1)
        y = torch.randint(0, 15, (16,))
        dataset = torch.utils.data.TensorDataset(x, y)
        loader = torch.utils.data.DataLoader(dataset, batch_size=8)

        attacks = {"fgsm": lambda m, x, y: fgsm_attack(m, x, y, epsilon=0.1)}
        results = evaluate_robustness(model, loader, attacks)
        assert "fgsm" in results
        assert "accuracy" in results["fgsm"]
