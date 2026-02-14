# SentinelNet

**Network Intrusion Detection with Adversarial Robustness — Deployed on Bare Metal**

A PyTorch-based multi-class network intrusion detection system running on physically microsegmented infrastructure. Suricata IDS feeds real-time traffic telemetry through an ONNX inference pipeline for 15-class flow classification, deployed behind a Palo Alto PA-220 firewall with per-device security zones.

This is not a notebook exercise. The model classifies live traffic on production hardware.

## Architecture

```
Internet → UDM → PA-220 (9 policies, 3 NAT rules)
                    │
         ┌──────────┼──────────┐
         │          │          │
      dmz-mgmt  dmz-svc  dmz-security
      (pi0)     (pi1)     (pi2: SentinelNet)
                           ├── Suricata 8.0 (IDS)
                           ├── Bridge (EVE → features)
                           └── ONNX Runtime (inference)
```

Physical port isolation per device. No VLANs. Every inter-zone packet logged.

## Status

- [x] Project structure scaffolded
- [x] ONNX inference server deployed (pi2, port 8000)
- [x] Suricata 8.0.3 capturing live traffic (AF_PACKET, ET Open)
- [x] Real-time bridge: EVE JSON → CICIDS2017 features → classification
- [x] PA-220 microsegmentation (dmz-security zone, 192.168.22.0/24)
- [x] NVMe storage (Samsung PM9C1a, 962K random IOPS)
- [ ] CICIDS2017 dataset download (in progress, XPS GPU)
- [ ] Baseline model training (RTX 4060 Ti)
- [ ] Full 78-feature extraction (NFStream integration)
- [ ] Adversarial robustness evaluation (FGSM, PGD, C&W)
- [ ] Multi-sensor architecture (Orange Pi RV2, RISC-V edge IDS)
- [ ] Research paper draft

## Quick Start

```bash
# Inference server (pi2)
cd ~/workspace/projects/sentinelnet
source .venv/bin/activate
uvicorn inference.serve:app --host 0.0.0.0 --port 8000

# Bridge (tails Suricata EVE, classifies flows)
python -m inference.suricata_bridge

# Health check
curl http://localhost:8000/health

# Single prediction
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [80, 1000000, 10, 8, 5000, 3000, ...]}'  # 78 CICIDS features
```

## Training (future, on XPS GPU)

```bash
# Download CICIDS2017
python data/download_datasets.py

# Train baseline
python training/train.py --config configs/default.yaml

# Adversarial evaluation
python adversarial/attacks.py --model checkpoints/best.pt \
  --attacks fgsm,pgd,cw --epsilon 0.05

# Export to ONNX and deploy
python models/export_onnx.py --model checkpoints/best.pt
scp models/sentinel.onnx pi2:~/workspace/projects/sentinelnet/models/
sudo systemctl restart sentinelnet
```

## Services (pi2)

| Service | Port | Status |
|---------|------|--------|
| sentinelnet.service | 8000 | `systemctl status sentinelnet` |
| sentinelnet-bridge.service | — | `systemctl status sentinelnet-bridge` |
| suricata (Docker) | — | `docker ps \| grep suricata` |

## Docs

- [PROPOSAL.md](./PROPOSAL.md) — Research proposal
- [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) — Full deployment architecture, feature mapping, firewall policy, benchmarks

## Hardware

| Node | Role | Specs |
|------|------|-------|
| pi2 | Inference + IDS | Pi 5, 16GB, 256GB NVMe, ARM Cortex-A76 |
| XPS | Training | RTX 4060 Ti 8GB, CUDA 12.4 |
| Orange Pi RV2 | Edge sensor (planned) | RISC-V, 4GB, 4×Ethernet |
| PA-220 | Firewall | PAN-OS 10.2, physical microsegmentation |

## Research Direction

The core research question: **how robust are neural network-based NIDS against adversarial perturbations in network flow features?**

We evaluate adversarial attacks (FGSM, PGD, C&W) against a PyTorch classifier trained on CICIDS2017, then measure defense effectiveness through adversarial training with ε-bounded perturbations. The deployed pipeline enables evaluation on both synthetic attacks and real traffic, bridging the gap between academic adversarial ML and operational network security.

---

*Rafael Garcia — CSUN CIT 2026*
*Network Security Engineer | AI Security Researcher*
