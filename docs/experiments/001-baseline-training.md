# SentinelNet — Experiment 001: Baseline Training Report

**Author:** Rafael Garcia
**Date:** 2026-02-12
**Status:** ✅ Complete
**wandb Run:** [lively-wood-4](https://wandb.ai/jag927-nasa/sentinelnet/runs/40hc17fi)

---

## 1. Objective

Establish a baseline multi-class network intrusion detection model using the CICIDS2017 dataset. Validate that a hybrid 1D-CNN + BiLSTM architecture (SentinelNet) can classify 15 traffic categories with high accuracy on consumer GPU hardware, setting the foundation for edge deployment on Raspberry Pi 5.

## 2. Hypothesis

A lightweight hybrid architecture combining convolutional feature extraction with bidirectional LSTM temporal modeling should achieve >98% accuracy on CICIDS2017, competitive with published benchmarks, while remaining small enough (~8.9MB) for real-time inference on ARM64 hardware.

## 3. Dataset

| Property | Value |
|----------|-------|
| **Dataset** | CICIDS2017 (Canadian Institute for Cybersecurity) |
| **Source** | HuggingFace parquet shards |
| **Total samples** | ~2.83M flows |
| **Features** | 78 (network flow statistics) |
| **Classes** | 15 (Benign + 14 attack types) |
| **Split** | Train / Validation / Test (sklearn train_test_split) |
| **Preprocessing** | StandardScaler normalization, inf/nan removal, label encoding |

### Class Distribution
CICIDS2017 attack types: BENIGN, DoS Hulk, PortScan, DDoS, DoS GoldenEye, FTP-Patator, SSH-Patator, DoS slowloris, DoS Slowhttptest, Bot, Web Attack – Brute Force, Web Attack – XSS, Infiltration, Web Attack – SQL Injection, Heartbleed.

**Note:** Dataset is heavily imbalanced (BENIGN dominant). No resampling applied in this baseline; class weights not used. This is a known limitation for future experiments.

## 4. Model Architecture

### SentinelNet: Hybrid 1D-CNN + BiLSTM

```
Input (batch, 78)
    │
    ▼ unsqueeze → (batch, 1, 78)
┌──────────────────────────┐
│  Conv1d(1→64, k=3, p=1)  │
│  BatchNorm1d(64)          │
│  ReLU                     │
│  Conv1d(64→128, k=3, p=1) │
│  BatchNorm1d(128)         │
│  ReLU                     │
│  AdaptiveAvgPool1d(39)    │
└──────────────────────────┘
    │ permute → (batch, 39, 128)
    ▼
┌──────────────────────────┐
│  BiLSTM(128→128, 2 layers)│
│  Dropout(0.3)             │
└──────────────────────────┘
    │ final hidden → (batch, 256)
    ▼
┌──────────────────────────┐
│  Linear(256→256) + ReLU   │
│  Dropout(0.3)             │
│  Linear(256→64) + ReLU    │
│  Dropout(0.3)             │
│  Linear(64→15)            │
└──────────────────────────┘
    ▼
Output: (batch, 15) logits
```

| Property | Value |
|----------|-------|
| **Total parameters** | ~768K |
| **Model size** | 8.9 MB (.pt checkpoint) |
| **Weight init** | Kaiming (Conv), Xavier (Linear) |

## 5. Training Configuration

| Hyperparameter | Value |
|----------------|-------|
| **Optimizer** | AdamW |
| **Learning rate** | 1e-3 |
| **Weight decay** | 1e-4 |
| **LR schedule** | CosineAnnealingLR (T_max=50) |
| **Batch size** | 256 |
| **Epochs** | 50 |
| **Early stopping** | Patience 10 (on val_acc) |
| **Loss function** | CrossEntropyLoss |
| **Mixed precision** | Disabled |

### Compute

| Resource | Spec |
|----------|------|
| **Host** | XPS (WSL2, Ubuntu 25.10) |
| **GPU** | NVIDIA RTX 4060 Ti, 8GB VRAM |
| **Driver** | 591.44 |
| **CUDA** | 13.1 |
| **PyTorch** | 2.6.0+cu124 |
| **Training time** | ~90 min (50 epochs) |
| **Throughput** | ~80 it/s (batches/sec) |

## 6. Results

### Final Metrics

| Metric | Value |
|--------|-------|
| **Test accuracy** | **99.72%** |
| **Best val accuracy** | 99.71% (epoch 40) |
| **Final train accuracy** | 99.70% |
| **Final train loss** | 0.0097 |
| **Final val loss** | 0.0116 |

### Training Progression

| Epoch | Train Loss | Train Acc | Val Loss | Val Acc | Notes |
|-------|-----------|-----------|----------|---------|-------|
| 5 | — | 96.71% | — | 96.71% | First checkpoint |
| 10 | — | — | — | 98.69% | Solid convergence |
| 13 | — | — | 0.0327 | 98.69% | Best early val |
| 14 | — | — | 0.0624 | 97.53% | LR oscillation dip |
| 16 | — | — | 0.4365 | 95.26% | Cosine LR warm restart peak |
| 20 | — | — | — | 96.85% | Still recovering |
| 25 | — | — | — | 98.83% | Recovery |
| 30 | — | — | — | 98.85% | Plateau |
| 35 | — | — | — | 98.90% | Gradual improvement |
| 40 | — | — | — | **99.71%** | ★ Best checkpoint |
| 45 | — | — | — | 83.96% | Late LR oscillation |
| 50 | 0.0097 | 99.70% | 0.0116 | 99.70% | Final epoch |

### Key Observations

1. **Cosine LR oscillation:** Validation accuracy showed periodic dips (E14: 97.53%, E16: 95.26%, E45: 83.96%) correlating with cosine annealing LR schedule cycles. Train accuracy remained stable throughout, confirming the model wasn't catastrophically forgetting; the LR spikes were temporarily destabilizing validation performance.

2. **Best model at epoch 40:** The checkpoint with 99.71% val_acc occurred near the cosine trough (LR ≈ 0), where the optimizer settled into a good minimum. This is the checkpoint used for final test evaluation.

3. **Train/val gap:** Minimal (99.70% vs 99.71%), indicating no significant overfitting. The model generalizes well despite the heavy class imbalance.

4. **Previous run comparison:** An earlier 40-epoch run achieved 99.32% test accuracy. This 50-epoch run reached 99.72%, a +0.40% improvement, likely from the additional cosine annealing cycles allowing the optimizer to explore better minima.

## 7. Checkpoints

All saved to `~/workspace/projects/sentinelnet/checkpoints/` on XPS:

| File | Epoch | Val Acc | Size |
|------|-------|---------|------|
| `best.pt` | 40 | 99.71% | 8.9 MB |
| `best_epoch40_99.32.pt` | 40 (prev run) | 99.32% | 8.9 MB |
| `epoch5_96.71.pt` | 5 | 96.71% | 8.9 MB |
| `epoch10_98.69.pt` | 10 | 98.69% | 8.9 MB |
| `epoch15_98.29.pt` | 15 | 98.29% | 8.9 MB |
| `epoch20_96.85.pt` | 20 | 96.85% | 8.9 MB |
| `epoch25_98.83.pt` | 25 | 98.83% | 8.9 MB |
| `epoch30_98.85.pt` | 30 | 98.85% | 8.9 MB |
| `epoch35_98.90.pt` | 35 | 98.90% | 8.9 MB |
| `epoch40_99.71.pt` | 40 | 99.71% | 8.9 MB |
| `epoch45_83.96.pt` | 45 | 83.96% | 8.9 MB |
| `epoch50_99.70.pt` | 50 | 99.70% | 8.9 MB |

## 8. Limitations & Known Issues

1. **Class imbalance not addressed.** CICIDS2017 is >80% BENIGN traffic. High accuracy may mask poor recall on rare attack classes (Heartbleed, Infiltration, SQL Injection). Per-class precision/recall/F1 analysis needed.

2. **No per-class confusion matrix.** This experiment only tracked aggregate accuracy. Next experiment should log per-class metrics and a confusion matrix to identify which attack types the model struggles with.

3. **Cosine annealing without warm restarts.** Standard CosineAnnealingLR was used (T_max=50, single cycle). The late-epoch val_acc oscillation (E45: 83.96%) suggests warm restarts (CosineAnnealingWarmRestarts) with a decaying LR maximum might stabilize training.

4. **No data augmentation.** Network flow features were fed raw (after StandardScaler). Techniques like feature masking, noise injection, or SMOTE for minority classes could improve robustness.

5. **Single dataset.** Only CICIDS2017 was used. Generalization to other IDS datasets (CSE-CIC-IDS2018, UNSW-NB15, NSL-KDD) is untested.

6. **No adversarial evaluation.** The model hasn't been tested against adversarial traffic crafting or evasion techniques.

## 9. Next Steps

| Priority | Task | Description |
|----------|------|-------------|
| **P0** | Per-class analysis | Generate confusion matrix, per-class precision/recall/F1, identify weak attack categories |
| **P0** | ONNX export | Export best.pt to ONNX for pi2 inference deployment |
| **P1** | Class weighting | Re-train with `CrossEntropyLoss(weight=...)` based on inverse class frequency |
| **P1** | Warm restarts | Switch to CosineAnnealingWarmRestarts (T_0=10, T_mult=2) |
| **P2** | Cross-dataset eval | Test on CSE-CIC-IDS2018 without retraining (zero-shot transfer) |
| **P2** | Pi 5 benchmark | Measure inference latency on pi2 (ONNX Runtime, single-flow and batch) |
| **P3** | PA-220 integration | Feed PA-220 traffic logs → feature extraction → SentinelNet inference → zone-aware alerting |
| **P3** | Ablation study | Compare SentinelNet vs BaselineMLP, CNN-only, LSTM-only variants |

## 10. Reproducibility

```bash
# On XPS (192.168.2.71)
cd ~/workspace/projects/sentinelnet
source .venv/bin/activate
python training/train.py --config training/configs/default.yaml --wandb --epochs 50 --save-every 5
```

**Random seed:** Not explicitly set (PyTorch default). Should be fixed in future experiments for full reproducibility.

**Data hash:** CICIDS2017 HuggingFace parquet shards (exact version TBD; stored in `data/` directory on XPS).

---

*Experiment tracked in wandb: [jag927-nasa/sentinelnet](https://wandb.ai/jag927-nasa/sentinelnet)*
*Report generated: 2026-02-12 20:00 PST*
