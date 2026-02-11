# Pi 5 Training Feasibility Notes

**Date:** 2026-02-11  
**Source:** ML on Raspberry Pi 5 performance report analysis

---

## Confirmed Decisions

| Decision | Validation |
|----------|------------|
| ONNX Runtime for inference | 3-4x faster than native PyTorch on ARM64; QNNPACK backend for INT8 |
| Train off-Pi, deploy frozen ONNX | Correct workflow; full training on Colab, inference on Pi |
| 8.4GB RAM estimate for services | Validated; 13-14GB usable after OS gives headroom |

---

## Required Adjustments

### 1. Skip `torch.compile()` on ARM64

The Inductor backend **degrades performance** on aarch64. Use eager mode only.

```python
# DON'T do this on Pi:
# model = torch.compile(model)

# DO use eager mode (default)
model = SentinelNet(...)
```

### 2. Thread Configuration (Mandatory)

Add to every training script:

```python
import torch
import os

# Optimal for Pi 5 quad-core
os.environ['OMP_NUM_THREADS'] = '4'
torch.set_num_threads(4)
torch.set_num_interop_threads(1)  # Single thread for inter-op parallelism
```

### 3. OS-Level Optimizations

Add to `/boot/firmware/config.txt`:

```ini
# Headless ML server optimizations
gpu_mem=16          # Minimal GPU allocation
dtoverlay=disable-bt # Disable bluetooth
```

Disable avahi:
```bash
sudo systemctl disable avahi-daemon
sudo systemctl stop avahi-daemon
```

---

## Training Time Estimates

### Reference Benchmark (from report)
- 500K param LSTM on 120K samples: **5-15 min/epoch**

### SentinelNet Projections

| Model | Params | Dataset | Est. Time/Epoch | Platform |
|-------|--------|---------|-----------------|----------|
| CNN+BiLSTM | 2-5M | 100 samples (debug) | ~30 sec | Pi 5 |
| CNN+BiLSTM | 2-5M | 2.8M flows (full) | **2-4 hours** | Pi 5 |
| CNN+BiLSTM | 2-5M | 2.8M flows (full) | ~5-10 min | Colab T4 |
| TabNet | 1-5M | 2.8M flows (full) | **30-60 min** | Pi 5 ✓ |

### Implication
- **Full CICIDS2017 training:** Colab mandatory
- **Pipeline debugging:** Pi 5 viable with 100-sample subsets
- **TabNet:** Trainable entirely on Pi 5 (paper angle: edge-deployable training)

---

## Model Comparison Matrix (Updated)

| Model | Params | On-Pi Training | On-Pi Inference | Research Value |
|-------|--------|----------------|-----------------|----------------|
| **SentinelNet (CNN+BiLSTM)** | 2-5M | Debug only | ✓ ONNX | Primary model |
| **BaselineMLP** | ~100K | ✓ Full | ✓ Native | Baseline comparison |
| **XGBoost** | N/A | ✓ Full | ✓ Native | Traditional ML baseline |
| **TabNet** | 1-5M | ✓ Full | ✓ ONNX | Edge training angle |

---

## TabNet Addition Rationale

TabNet (Arik & Pfister, 2019) is a DL architecture for tabular data:
- Attention-based feature selection
- Interpretable (feature importance built-in)
- Lightweight enough for full Pi training
- **Paper angle:** Demonstrate edge-deployable training, not just inference

### Implementation

```bash
pip install pytorch-tabnet
```

```python
from pytorch_tabnet.tab_model import TabNetClassifier

clf = TabNetClassifier(
    n_d=8, n_a=8,           # Reduced for Pi
    n_steps=3,
    gamma=1.3,
    optimizer_params=dict(lr=2e-2),
    device_name='cpu'
)

clf.fit(X_train, y_train, eval_set=[(X_val, y_val)])
```

---

## Updated Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    DEVELOPMENT CYCLE                         │
│                                                              │
│  1. Pipeline Debug (Pi 5)                                   │
│     - 100-sample subset                                     │
│     - Verify data loading, model forward pass               │
│     - ~30 sec per epoch                                     │
│                                                              │
│  2. Full Training (Colab T4/A100)                          │
│     - 2.8M flows, 50 epochs                                 │
│     - ~5-10 min per epoch                                   │
│     - Export to ONNX                                        │
│                                                              │
│  3. Production Inference (Pi 5)                             │
│     - ONNX Runtime + QNNPACK INT8                          │
│     - <50ms latency target                                  │
│     - PA-220 syslog integration                             │
│                                                              │
│  4. TabNet Comparison (Pi 5 Full)                          │
│     - Train entirely on-device                              │
│     - 30-60 min per epoch                                   │
│     - Demonstrates edge training capability                 │
└─────────────────────────────────────────────────────────────┘
```

---

## References

- Arik, S. Ö., & Pfister, T. (2019). TabNet: Attentive Interpretable Tabular Learning
- Raspberry Pi 5 ML Performance Report (internal)
