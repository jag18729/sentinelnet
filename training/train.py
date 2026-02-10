#!/usr/bin/env python3
"""
Training script for SentinelNet.

Features:
- wandb experiment tracking
- Learning rate scheduling (cosine annealing)
- Early stopping
- Model checkpointing
- Mixed precision training (optional)
"""

import argparse
import os
from pathlib import Path
from datetime import datetime
import yaml
import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import CosineAnnealingLR
from tqdm import tqdm
import wandb

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.sentinel_net import get_model
from preprocessing.pipeline import build_dataloaders, load_cicids2017


def train_epoch(
    model: nn.Module,
    train_loader: torch.utils.data.DataLoader,
    criterion: nn.Module,
    optimizer: optim.Optimizer,
    device: str,
    epoch: int,
) -> dict:
    """Train for one epoch."""
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    
    pbar = tqdm(train_loader, desc=f"Epoch {epoch}")
    for batch_idx, (x, y) in enumerate(pbar):
        x, y = x.to(device), y.to(device)
        
        optimizer.zero_grad()
        logits = model(x)
        loss = criterion(logits, y)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        pred = logits.argmax(dim=1)
        correct += (pred == y).sum().item()
        total += y.size(0)
        
        pbar.set_postfix({
            'loss': f"{total_loss/(batch_idx+1):.4f}",
            'acc': f"{100*correct/total:.2f}%"
        })
    
    return {
        'train_loss': total_loss / len(train_loader),
        'train_acc': correct / total,
    }


def validate(
    model: nn.Module,
    val_loader: torch.utils.data.DataLoader,
    criterion: nn.Module,
    device: str,
) -> dict:
    """Validate model."""
    model.eval()
    total_loss = 0
    correct = 0
    total = 0
    
    with torch.no_grad():
        for x, y in val_loader:
            x, y = x.to(device), y.to(device)
            logits = model(x)
            loss = criterion(logits, y)
            
            total_loss += loss.item()
            pred = logits.argmax(dim=1)
            correct += (pred == y).sum().item()
            total += y.size(0)
    
    return {
        'val_loss': total_loss / len(val_loader),
        'val_acc': correct / total,
    }


def train(config: dict) -> None:
    """Main training function."""
    # Setup device
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"[*] Using device: {device}")
    
    # Setup wandb
    if config.get('wandb', False):
        wandb.init(
            project="sentinelnet",
            name=config.get('run_name', f"run-{datetime.now():%Y%m%d-%H%M%S}"),
            config=config,
        )
    
    # Load data
    data_dir = Path(config.get('data_dir', 'data'))
    print(f"[*] Loading data from {data_dir}")
    
    df = load_cicids2017(data_dir)
    train_loader, val_loader, test_loader, label_encoder, scaler, feature_names = build_dataloaders(
        df=df,
        batch_size=config.get('batch_size', 256),
        save_artifacts=data_dir / 'artifacts',
    )
    
    # Create model
    input_dim = len(feature_names)
    num_classes = len(label_encoder.classes_)
    
    model = get_model(
        model_name=config.get('model', 'sentinelnet'),
        input_dim=input_dim,
        num_classes=num_classes,
        hidden_dim=config.get('hidden_dim', 128),
        num_layers=config.get('num_layers', 2),
        dropout=config.get('dropout', 0.3),
    )
    model.to(device)
    
    print(f"[*] Model: {config.get('model', 'sentinelnet')}")
    print(f"[*] Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Loss and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(
        model.parameters(),
        lr=config.get('lr', 1e-3),
        weight_decay=config.get('weight_decay', 1e-4),
    )
    
    # Scheduler
    scheduler = CosineAnnealingLR(
        optimizer,
        T_max=config.get('epochs', 50),
        eta_min=config.get('min_lr', 1e-6),
    )
    
    # Training loop
    best_val_acc = 0
    patience = config.get('patience', 10)
    patience_counter = 0
    checkpoint_dir = Path(config.get('checkpoint_dir', 'checkpoints'))
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    for epoch in range(1, config.get('epochs', 50) + 1):
        # Train
        train_metrics = train_epoch(model, train_loader, criterion, optimizer, device, epoch)
        
        # Validate
        val_metrics = validate(model, val_loader, criterion, device)
        
        # Step scheduler
        scheduler.step()
        
        # Log metrics
        metrics = {**train_metrics, **val_metrics, 'lr': scheduler.get_last_lr()[0]}
        print(f"Epoch {epoch}: loss={val_metrics['val_loss']:.4f}, acc={val_metrics['val_acc']*100:.2f}%")
        
        if config.get('wandb', False):
            wandb.log(metrics, step=epoch)
        
        # Save best model
        if val_metrics['val_acc'] > best_val_acc:
            best_val_acc = val_metrics['val_acc']
            patience_counter = 0
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_acc': best_val_acc,
                'config': config,
            }, checkpoint_dir / 'best.pt')
            print(f"[✓] Saved best model (acc={best_val_acc*100:.2f}%)")
        else:
            patience_counter += 1
        
        # Early stopping
        if patience_counter >= patience:
            print(f"[!] Early stopping at epoch {epoch}")
            break
    
    # Final test evaluation
    print("\n[*] Final test evaluation...")
    model.load_state_dict(torch.load(checkpoint_dir / 'best.pt')['model_state_dict'])
    test_metrics = validate(model, test_loader, criterion, device)
    print(f"Test accuracy: {test_metrics['val_acc']*100:.2f}%")
    
    if config.get('wandb', False):
        wandb.log({'test_acc': test_metrics['val_acc']})
        wandb.finish()


def main():
    parser = argparse.ArgumentParser(description="Train SentinelNet")
    parser.add_argument('--config', type=str, default='training/configs/default.yaml')
    parser.add_argument('--wandb', action='store_true', help='Enable wandb logging')
    parser.add_argument('--epochs', type=int, help='Override epochs')
    parser.add_argument('--batch-size', type=int, help='Override batch size')
    parser.add_argument('--lr', type=float, help='Override learning rate')
    args = parser.parse_args()
    
    # Load config
    config_path = Path(args.config)
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
    else:
        config = {}
    
    # Override from CLI
    if args.wandb:
        config['wandb'] = True
    if args.epochs:
        config['epochs'] = args.epochs
    if args.batch_size:
        config['batch_size'] = args.batch_size
    if args.lr:
        config['lr'] = args.lr
    
    train(config)


if __name__ == "__main__":
    main()
