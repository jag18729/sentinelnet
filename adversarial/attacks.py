#!/usr/bin/env python3
"""
Adversarial attack implementations for SentinelNet.

Implements:
- FGSM (Fast Gradient Sign Method) - Goodfellow et al., 2014
- PGD (Projected Gradient Descent) - Madry et al., 2017
- C&W (Carlini & Wagner) - Carlini & Wagner, 2017

These attacks are used to evaluate model robustness and for adversarial training.
"""

import torch
import torch.nn as nn
from typing import Callable, Dict, Optional
import numpy as np


def fgsm_attack(
    model: nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float = 0.1,
    clip_min: float = 0.0,
    clip_max: float = 1.0,
) -> torch.Tensor:
    """
    Fast Gradient Sign Method (Goodfellow et al., 2014).
    
    Single-step perturbation along gradient direction.
    
    Args:
        model: Target model
        x: Input samples (batch, features)
        y: True labels
        epsilon: Perturbation magnitude
        clip_min: Minimum value for clipping
        clip_max: Maximum value for clipping
        
    Returns:
        Adversarial examples
    """
    model.eval()
    
    x_adv = x.clone().detach().requires_grad_(True)
    
    logits = model(x_adv)
    loss = nn.CrossEntropyLoss()(logits, y)
    loss.backward()
    
    # Create perturbation
    perturbation = epsilon * x_adv.grad.sign()
    x_adv = x_adv + perturbation
    
    # Clip to valid range
    x_adv = torch.clamp(x_adv, clip_min, clip_max)
    
    return x_adv.detach()


def pgd_attack(
    model: nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float = 0.1,
    alpha: float = 0.01,
    num_steps: int = 40,
    clip_min: float = 0.0,
    clip_max: float = 1.0,
    random_start: bool = True,
) -> torch.Tensor:
    """
    Projected Gradient Descent (Madry et al., 2017).
    
    Iterative attack, stronger than FGSM.
    
    Args:
        model: Target model
        x: Input samples
        y: True labels
        epsilon: Maximum perturbation (L-inf)
        alpha: Step size per iteration
        num_steps: Number of attack iterations
        clip_min: Minimum value for clipping
        clip_max: Maximum value for clipping
        random_start: Whether to start from random point in epsilon-ball
        
    Returns:
        Adversarial examples
    """
    model.eval()
    
    x_adv = x.clone().detach()
    
    # Random start within epsilon-ball
    if random_start:
        x_adv = x_adv + torch.zeros_like(x_adv).uniform_(-epsilon, epsilon)
        x_adv = torch.clamp(x_adv, clip_min, clip_max)
    
    for _ in range(num_steps):
        x_adv.requires_grad_(True)
        
        logits = model(x_adv)
        loss = nn.CrossEntropyLoss()(logits, y)
        loss.backward()
        
        # Gradient step
        x_adv = x_adv.detach() + alpha * x_adv.grad.sign()
        
        # Project back into epsilon-ball
        delta = torch.clamp(x_adv - x, min=-epsilon, max=epsilon)
        x_adv = torch.clamp(x + delta, clip_min, clip_max)
    
    return x_adv.detach()


def cw_attack(
    model: nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    c: float = 1.0,
    kappa: float = 0.0,
    num_steps: int = 100,
    lr: float = 0.01,
    clip_min: float = 0.0,
    clip_max: float = 1.0,
) -> torch.Tensor:
    """
    Carlini & Wagner L2 attack (Carlini & Wagner, 2017).
    
    Optimization-based attack that finds minimal perturbations.
    
    Args:
        model: Target model
        x: Input samples
        y: True labels (attack aims to misclassify)
        c: Confidence parameter
        kappa: Confidence margin
        num_steps: Optimization steps
        lr: Learning rate
        clip_min: Minimum value
        clip_max: Maximum value
        
    Returns:
        Adversarial examples
    """
    model.eval()
    
    # Initialize perturbation
    w = torch.zeros_like(x, requires_grad=True)
    optimizer = torch.optim.Adam([w], lr=lr)
    
    best_adv = x.clone()
    best_l2 = torch.full((x.shape[0],), float('inf'), device=x.device)
    
    for step in range(num_steps):
        # Transform w to valid input range using tanh
        x_adv = torch.tanh(w) * (clip_max - clip_min) / 2 + (clip_max + clip_min) / 2
        
        # L2 distance
        l2_dist = torch.sum((x_adv - x) ** 2, dim=1)
        
        # Model output
        logits = model(x_adv)
        
        # C&W loss: maximize margin between true class and next best
        one_hot = torch.zeros_like(logits).scatter_(1, y.unsqueeze(1), 1)
        real = (one_hot * logits).sum(dim=1)
        other = ((1 - one_hot) * logits - one_hot * 1e4).max(dim=1)[0]
        
        # f(x') = max(real - other + kappa, 0)
        f_loss = torch.clamp(real - other + kappa, min=0)
        
        # Total loss
        loss = l2_dist.mean() + c * f_loss.mean()
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        # Track best adversarial examples
        pred = logits.argmax(dim=1)
        successful = pred != y
        improved = l2_dist < best_l2
        update_mask = successful & improved
        
        if update_mask.any():
            best_adv[update_mask] = x_adv[update_mask].detach()
            best_l2[update_mask] = l2_dist[update_mask].detach()
    
    return best_adv


def evaluate_robustness(
    model: nn.Module,
    test_loader: torch.utils.data.DataLoader,
    attacks: Dict[str, Callable],
    device: str = 'cpu',
) -> Dict[str, Dict[str, float]]:
    """
    Evaluate model accuracy under multiple attack strategies.
    
    Args:
        model: Target model
        test_loader: Test data loader
        attacks: Dict of attack_name -> attack_function
        device: Device to use
        
    Returns:
        Dict with clean and adversarial accuracies
    """
    model.eval()
    model.to(device)
    
    results = {'clean': {'correct': 0, 'total': 0}}
    for name in attacks:
        results[name] = {'correct': 0, 'total': 0}
    
    for x, y in test_loader:
        x, y = x.to(device), y.to(device)
        
        # Clean accuracy
        with torch.no_grad():
            pred = model(x).argmax(dim=1)
            results['clean']['correct'] += (pred == y).sum().item()
            results['clean']['total'] += y.size(0)
        
        # Attack accuracy
        for name, attack_fn in attacks.items():
            x_adv = attack_fn(model, x, y)
            with torch.no_grad():
                pred_adv = model(x_adv).argmax(dim=1)
                results[name]['correct'] += (pred_adv == y).sum().item()
                results[name]['total'] += y.size(0)
    
    # Compute percentages
    for key in results:
        total = results[key]['total']
        results[key]['accuracy'] = results[key]['correct'] / total if total > 0 else 0
    
    return results


def get_attack(name: str, **kwargs) -> Callable:
    """Get attack function by name with preset parameters."""
    attacks = {
        'fgsm': lambda m, x, y: fgsm_attack(m, x, y, **kwargs),
        'pgd': lambda m, x, y: pgd_attack(m, x, y, **kwargs),
        'cw': lambda m, x, y: cw_attack(m, x, y, **kwargs),
    }
    
    if name not in attacks:
        raise ValueError(f"Unknown attack: {name}. Available: {list(attacks.keys())}")
    
    return attacks[name]


if __name__ == "__main__":
    # Test attacks
    from models.sentinel_net import SentinelNet
    
    # Create dummy model and data
    model = SentinelNet(input_dim=78, num_classes=15)
    x = torch.randn(8, 78)
    y = torch.randint(0, 15, (8,))
    
    # Test FGSM
    x_fgsm = fgsm_attack(model, x, y, epsilon=0.1)
    print(f"FGSM perturbation L-inf: {(x_fgsm - x).abs().max():.4f}")
    
    # Test PGD
    x_pgd = pgd_attack(model, x, y, epsilon=0.1, num_steps=10)
    print(f"PGD perturbation L-inf: {(x_pgd - x).abs().max():.4f}")
    
    print("[✓] Attack implementations working")
