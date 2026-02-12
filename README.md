# SentinelNet

**PyTorch-based Network Intrusion Detection with Adversarial Robustness Research**

A 1D-CNN + BiLSTM hybrid model for classifying network intrusion traffic, with adversarial robustness evaluation (FGSM, PGD, C&W). Built on CICIDS2017 (2.83M flows, 15 classes, 78 features). Training on CUDA, inference on ONNX Runtime (ARM64).

## Architecture

```
Input (78 features)
    ↓
1D-CNN (feature extraction)
    ↓
BiLSTM (temporal patterns)
    ↓
Dense → Softmax (15 classes)

Parameters: 768K
```

## Infrastructure

| Role | Host | Hardware | Stack |
|------|------|----------|-------|
| **Training** | XPS (WSL2) | RTX 4060 Ti, 8GB VRAM | PyTorch 2.6 + CUDA 12.4 |
| **Inference** | pi2 (Pi 5) | 16GB RAM, ARM64 | ONNX Runtime + FastAPI |
| **Monitoring** | pi1 | Grafana + Prometheus | wandb dashboard |

## Quick Start

```bash
# Clone and install
git clone https://github.com/jag18729/sentinelnet.git
cd sentinelnet
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# Download CICIDS2017 (parquet, ~444MB)
mkdir -p data
for i in 0 1 2 3; do
  wget -O data/train-${i}.parquet \
    "https://huggingface.co/api/datasets/c01dsnap/CIC-IDS2017/parquet/default/train/${i}.parquet"
done

# Train
python -m training.train --epochs 50 --batch-size 256 --wandb

# Serve (ONNX inference)
MODEL_PATH=models/sentinel.onnx python -m inference.serve
```

## Status

- [x] Project structure scaffolded
- [x] Data pipeline implemented (parquet + CSV loading, stratified split)
- [x] CICIDS2017 downloaded (4 parquet shards, 2.83M rows)
- [x] Model verified on CUDA (768K params, 78→15)
- [x] Training running — **Epoch 8/50, 98.43% accuracy, loss 0.039**
- [x] wandb experiment tracking ([dashboard](https://wandb.ai/jag927-nasa/sentinelnet/runs/rp9sfghv))
- [x] Pi2 inference server running (ONNX Runtime + FastAPI on :8000)
- [ ] Export trained model to ONNX
- [ ] Deploy real model to pi2
- [ ] Adversarial attacks (FGSM, PGD, C&W)
- [ ] Adversarial training
- [ ] PA-220 syslog integration
- [ ] Research paper draft

## Training

**Dataset:** CICIDS2017 (`c01dsnap/CIC-IDS2017` on HuggingFace)
- 2,827,876 total flows → train 1,979,513 / val 424,181 / test 424,182
- 15 classes: BENIGN, DDoS, PortScan, Bot, FTP-Patator, SSH-Patator, DoS variants, Web attacks, etc.

**Current Run (2026-02-11):**
| Epoch | Loss | Accuracy |
|-------|------|----------|
| 1 | 0.170 | 96.8% |
| 2 | 0.058 | 97.9% |
| 4 | 0.045 | 98.1% |
| 7 | 0.040 | 98.3% |
| 8 | 0.039 | 98.4% |

**wandb:** https://wandb.ai/jag927-nasa/sentinelnet/runs/rp9sfghv

## Key Commands

```bash
# Training with wandb (offline mode for DNS-restricted hosts)
WANDB_MODE=offline WANDB_PROJECT=sentinelnet \
  python -m training.train --epochs 50 --batch-size 256 --wandb

# Sync offline wandb run
wandb sync wandb/offline-run-*/ --project sentinelnet --entity jag927-nasa

# Inference server
MODEL_PATH=models/sentinel.onnx ARTIFACTS_PATH=data/artifacts \
  python -m inference.serve

# Health check
curl http://localhost:8000/health

# Predict
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [0.0, 1.0, ...]}'
```

## Pipeline

```
PA-220 syslog → pi0 rsyslog → pi2 inference → pi1 Grafana
                                    ↑
XPS (train) → ONNX export → pi2 (serve)
```

## Integration Points

| System | Integration |
|--------|-------------|
| PA-220 | Syslog → rsyslog (pi0) → flow parser → inference |
| Grafana | Prometheus metrics from inference server |
| wandb | Experiment tracking, loss/accuracy curves |
| PostgreSQL | Prediction logging, experiment metadata |

## Docs

- [PROPOSAL.md](./PROPOSAL.md) — Full research proposal
- [docs/journal/](./docs/journal/) — Development journal
- [training/configs/default.yaml](./training/configs/default.yaml) — Training hyperparameters

## License

MIT
