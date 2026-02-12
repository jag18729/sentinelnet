# SentinelNet

**AI-powered network intrusion detection that learns to spot attacks, then learns to survive them.**

## What Is This?

Every time data moves across a network, it leaves a trail: packet sizes, durations, byte counts, flags. SentinelNet takes those raw network flow measurements and classifies them as either normal traffic or one of 14 attack types (DDoS, port scans, brute force, botnets, web exploits, etc.).

What makes this different from a traditional firewall or signature-based IDS is that SentinelNet *learns* patterns from data rather than relying on hand-written rules. A firewall blocks known-bad IPs; SentinelNet can flag a novel attack it's never seen before, as long as the traffic pattern looks anomalous.

The research angle is **adversarial robustness**: after training the model to detect attacks, we deliberately try to fool it with adversarial examples (tiny, calculated modifications to network flows that trick the model into misclassifying malicious traffic as benign). Then we retrain the model to resist those tricks. The goal is an IDS that holds up not just against attackers, but against attackers who know the model exists and are actively trying to evade it.

## How It Works (Plain English)

1. **Data in:** 2.83 million real network flows from the [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset, each described by 78 measurements (packet length, flow duration, flag counts, etc.)
2. **Model learns:** A neural network trains on labeled examples ("this flow is a DDoS attack," "this flow is normal") until it can classify unseen flows with ~98% accuracy
3. **Adversarial stress test:** We generate adversarial inputs designed to fool the model, measure how much accuracy drops, then retrain with those adversarial examples mixed in
4. **Deploy:** The trained model exports to ONNX format and runs on a Raspberry Pi 5, classifying live network flows from a Palo Alto PA-220 firewall in real time

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
