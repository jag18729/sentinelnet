#!/usr/bin/env python3
"""Validate ONNX model on CICIDS2017 dataset."""
import pickle, numpy as np, onnxruntime as ort
from pathlib import Path
import sys
sys.path.insert(0, '.')

with open('data/artifacts/scaler.pkl','rb') as f: scaler = pickle.load(f)
with open('data/artifacts/label_encoder.pkl','rb') as f: le = pickle.load(f)
with open('data/artifacts/feature_names.pkl','rb') as f: fnames = pickle.load(f)

sess = ort.InferenceSession('exports/sentinel.onnx')

from preprocessing.pipeline import load_cicids2017, clean_dataframe
df = load_cicids2017(Path('data'))
df = clean_dataframe(df)

label_col = [c for c in df.columns if 'label' in c.lower()][0]
X = df[[c for c in df.columns if c in fnames]].values
y_true = le.transform(df[label_col].str.strip().values)
X_scaled = scaler.transform(X)

rng = np.random.default_rng(42)
idx = rng.choice(len(X_scaled), size=10000, replace=False)
X_sample = X_scaled[idx].astype(np.float32)
y_sample = y_true[idx]

logits = sess.run(None, {'features': X_sample})[0]
preds = logits.argmax(axis=1)

acc = (preds == y_sample).mean()
print(f"ONNX validation accuracy (10K sample): {acc*100:.2f}%")
print(f"Total dataset size: {len(X):,}")
print(f"Features: {len(fnames)}")
print(f"Classes: {len(le.classes_)}")
print()

header = f"{'Class':<30} {'Correct':>8} {'Total':>8} {'Acc':>8}"
print(header)
print("-" * 58)

correct_by_class = {}
total_by_class = {}
for p, t in zip(preds, y_sample):
    cls = le.classes_[t]
    total_by_class[cls] = total_by_class.get(cls, 0) + 1
    if p == t:
        correct_by_class[cls] = correct_by_class.get(cls, 0) + 1

for cls in sorted(total_by_class.keys()):
    c = correct_by_class.get(cls, 0)
    t = total_by_class[cls]
    print(f"{cls:<30} {c:>8} {t:>8} {c/t*100:>7.2f}%")


# --- Adversarial Robustness Evaluation ---
print("\n" + "=" * 58)
print("Adversarial Robustness Evaluation")
print("=" * 58)

try:
    import torch
    from models.sentinel_net import SentinelNet
    from adversarial.attacks import fgsm_attack, pgd_attack

    # Load PyTorch model for adversarial evaluation
    ckpt = torch.load('checkpoints/best.pt', map_location='cpu', weights_only=False)
    cfg = ckpt.get('config', {})
    pt_model = SentinelNet(
        input_dim=len(fnames),
        num_classes=len(le.classes_),
        hidden_dim=cfg.get('hidden_dim', 128),
        num_layers=cfg.get('num_layers', 2),
        dropout=cfg.get('dropout', 0.3),
    )
    pt_model.load_state_dict(ckpt['model_state_dict'])
    pt_model.eval()

    # Use a smaller sample for adversarial evaluation (expensive)
    adv_idx = rng.choice(len(X_scaled), size=1000, replace=False)
    X_adv_sample = torch.FloatTensor(X_scaled[adv_idx].astype(np.float32))
    y_adv_sample = torch.LongTensor(y_true[adv_idx])

    # Clean accuracy on PyTorch model
    with torch.no_grad():
        clean_preds = pt_model(X_adv_sample).argmax(dim=1)
        clean_acc = (clean_preds == y_adv_sample).float().mean().item()

    # FGSM attack
    x_fgsm = fgsm_attack(pt_model, X_adv_sample, y_adv_sample, epsilon=0.05, clip_min=-5.0, clip_max=5.0)
    with torch.no_grad():
        fgsm_preds = pt_model(x_fgsm).argmax(dim=1)
        fgsm_acc = (fgsm_preds == y_adv_sample).float().mean().item()

    # PGD attack
    x_pgd = pgd_attack(pt_model, X_adv_sample, y_adv_sample, epsilon=0.05, alpha=0.01, num_steps=20, clip_min=-5.0, clip_max=5.0)
    with torch.no_grad():
        pgd_preds = pt_model(x_pgd).argmax(dim=1)
        pgd_acc = (pgd_preds == y_adv_sample).float().mean().item()

    print(f"\n{'Attack':<20} {'Accuracy':>10} {'Drop':>10}")
    print("-" * 42)
    print(f"{'Clean':<20} {clean_acc*100:>9.2f}% {'':>10}")
    print(f"{'FGSM (eps=0.05)':<20} {fgsm_acc*100:>9.2f}% {(clean_acc-fgsm_acc)*100:>+9.2f}%")
    print(f"{'PGD-20 (eps=0.05)':<20} {pgd_acc*100:>9.2f}% {(clean_acc-pgd_acc)*100:>+9.2f}%")

    # Warn if adversarial accuracy is very low
    if pgd_acc < 0.5:
        print(f"\n[!] WARNING: PGD accuracy ({pgd_acc*100:.1f}%) is below 50%.")
        print("    Consider adversarial training before deploying this model.")

except FileNotFoundError:
    print("\n[!] Skipping adversarial evaluation: checkpoints/best.pt not found")
except ImportError as e:
    print(f"\n[!] Skipping adversarial evaluation: {e}")
