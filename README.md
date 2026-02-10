# SentinelNet

**PyTorch-based Network Intrusion Detection with Adversarial Robustness Research**

## Quick Start

```bash
# Setup (when ready)
cd ~/workspace/projects/sentinelnet
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Download datasets
python data/download_datasets.py

# Train baseline
python training/train.py --config configs/default.yaml

# Evaluate robustness
python adversarial/evaluate_robustness.py --model checkpoints/best.pt
```

## Status

- [x] Proposal written
- [ ] Project structure scaffolded
- [ ] Data pipeline implemented
- [ ] Baseline model trained
- [ ] Adversarial attacks implemented
- [ ] Adversarial training complete
- [ ] ONNX export + Pi1 deployment
- [ ] PA-220 syslog integration
- [ ] Research paper draft

## Docs

- [PROPOSAL.md](./PROPOSAL.md) - Full project proposal
- [data/README.md](./data/README.md) - Dataset documentation (TBD)

## Key Commands (Future)

```bash
# Training with wandb
wandb login
python training/train.py --wandb

# Hyperparameter search
python training/hyperparameter_search.py --n-trials 50

# Adversarial evaluation
python adversarial/evaluate_robustness.py \
  --model checkpoints/best.pt \
  --attacks fgsm,pgd,cw \
  --epsilon 0.05

# Export to ONNX
python models/export_onnx.py --model checkpoints/best.pt

# Serve on Pi1
python inference/serve.py --port 8000 --model models/sentinel.onnx
```

## Integration Points

| System | Integration |
|--------|-------------|
| PA-220 | Syslog → rsyslog (pi0) → flow parser → inference |
| Grafana | Prometheus metrics from inference server |
| PostgreSQL | Prediction logging, experiment metadata |
| GuardQuote | Shared patterns: FastAPI, MLflow, Docker |
