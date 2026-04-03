# SentinelNet

**Network Intrusion Detection with Adversarial Robustness — Deployed on Bare Metal**

A production network intrusion detection system running on physically microsegmented infrastructure. PyTorch/ONNX models classify live network flows via a scapy-based traffic feeder on RISC-V edge hardware, with Suricata IDS providing signature-based detection. Deployed behind a Palo Alto PA-220 firewall with per-device security zones.

Designed from need, not flash. This system classifies live traffic on production hardware -- 1M+ predictions and counting. Recent upgrade (April 2026) added adversarial training support, class-weighted loss, data leakage fix, model versioning, and production hardening.

## Architecture

```
Internet → UDM → USW-Lite-8-PoE ──┐
                    │          SPAN mirror (port 7→8)
                    │               │
                 PA-220          Orange Pi RV2
              (4 DMZ zones)     ├── scapy feeder (end1, promiscuous)
                    │           └── 78-feature extraction → Pi2 API
         ┌──────────┼──────────┐
         │          │          │
      dmz-mgmt  dmz-svc  dmz-security
      (pi0)     (pi1)     (pi2: SentinelNet API)
                           ├── K3s inference (port 30800)
                           ├── Suricata 7.0.5 (74K rules)
                           └── Wazuh HIDS (4.14.3)
```

Physical port isolation per device. SPAN mirror captures all LAN uplink traffic for ML classification.

## Status

- [x] Project structure scaffolded
- [x] SentinelNet inference API deployed on K3s (Pi2, port 30800)
- [x] Suricata 7.0.5 capturing live traffic (74K rules, ET Open + community)
- [x] PA-220 microsegmentation (4 DMZ zones, physical port isolation)
- [x] CICIDS2017 model trained (99.71% accuracy on 2.8M flows)
- [x] Full 78-feature extraction (scapy-based on RISC-V, nfstream on aarch64)
- [x] Orange Pi RV2 edge sensor deployed (RISC-V, SPAN mirror feed)
- [x] USW-Lite-8-PoE SPAN port configured (port 7 mirrors uplink)
- [x] Full LAN traffic SPAN coverage (1M+ predictions in production)
- [x] Grafana dashboard with prediction metrics
- [x] FastAPI lifespan migration + ONNX warm-up + feature dimension validation
- [x] Data leakage fix (scaler fit on train only) + class weighting for imbalanced data
- [x] Feature manifest (single source of truth for 78/25-feature mappings)
- [x] Reduced-feature training config for Suricata bridge path
- [x] SHA256 model versioning on export and load
- [x] Adversarial training loop (PGD augmentation, configurable)
- [x] Robustness evaluation in ONNX export (FGSM + PGD-20)
- [x] Prometheus alerting rules + K3s HPA + PodDisruptionBudget
- [x] Hard-coded IPs replaced with env vars across feeder/bridge
- [ ] Integration tests + feature contract tests (coverage 63% → 85%+)
- [ ] Retrain with class weighting + data leakage fix on XPS GPU
- [ ] Adversarial robustness evaluation on retrained model
- [ ] NFStream evaluation on ARM64 for full 78-feature Suricata path
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

## Training

```bash
# Download CICIDS2017
python data/download_datasets.py

# Train baseline (with class weighting, scaler fit on train only)
python training/train.py --config training/configs/default.yaml

# Train reduced-feature model for Suricata bridge path
python training/train.py --config training/configs/suricata_reduced.yaml

# Train with adversarial augmentation (PGD)
python training/train.py --config training/configs/default.yaml \
  --epochs 50  # set adversarial_training: true in config

# Export to ONNX (generates SHA256 checksum)
python exports/export_onnx.py

# Validate ONNX + adversarial robustness
python exports/validate_onnx.py

# Deploy
scp exports/sentinel.onnx pi2:~/workspace/projects/sentinelnet/models/
scp exports/sentinel.onnx.sha256 pi2:~/workspace/projects/sentinelnet/models/
sudo systemctl restart sentinelnet
```

## Services

| Host | Service | Port | Check |
|------|---------|------|-------|
| Pi2 (K3s) | sentinelnet-api | 30800 | `curl http://100.111.113.35:30800/health` |
| Pi2 (K3s) | sentinelnet metrics | 30800 | `curl http://100.111.113.35:30800/metrics` |
| RV2 | sentinelnet-feeder | -- | `systemctl status sentinelnet-feeder` |
| RV2 | Suricata IDS | -- | 74K rules, EVE JSON to Loki |

## Docs

- [PROPOSAL.md](./PROPOSAL.md) — Research proposal
- [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) — Full deployment architecture, feature mapping, firewall policy, benchmarks
- [docs/experiments/001-baseline-training.md](./docs/experiments/001-baseline-training.md) — Baseline training report (99.72% test accuracy)
- [pipeline/README.md](./pipeline/README.md) — Exfil detection pipeline
- [feeder/README.md](./feeder/README.md) — RISC-V edge feeder
- [data/artifacts/feature_manifest.json](./data/artifacts/feature_manifest.json) — Feature name/index contract

## Hardware

| Node | Role | Specs |
|------|------|-------|
| Pi2 | K3s inference API + Wazuh HIDS | Pi 5, 16GB, ARM Cortex-A76 |
| Orange Pi RV2 | Edge sensor + scapy feeder | RISC-V, 4GB, SPAN on USW-Lite-8-PoE port 7 |
| PA-220 | Firewall | PAN-OS 10.2, 4 DMZ zones, physical microsegmentation |
| USW-Lite-8-PoE | SPAN switch | Port 7 mirrors port 8 (UDM uplink) |

## Production Stats (April 2026)

| Metric | Value |
|--------|-------|
| Total predictions | 1,077,000+ |
| BENIGN | 1,077,418 |
| DoS Hulk | 10 |
| DoS Slowhttptest | 1,042 |
| Training accuracy | 99.71% (CICIDS2017, 2.8M flows) |
| Inference latency | <500ms (RISC-V edge) |
| Suricata rules | 74,096 (ET Open + community) |
| Test suite | 96/96 passing (64% coverage) |
| Adversarial training | Implemented (PGD augmentation) |
| Model versioning | SHA256 checksum on export/load |

## Research Direction

The core research question: **how robust are neural network-based NIDS against adversarial perturbations in network flow features?**

We evaluate adversarial attacks (FGSM, PGD, C&W) against a classifier trained on CICIDS2017, then measure defense effectiveness through adversarial training with epsilon-bounded perturbations. The deployed pipeline enables evaluation on both synthetic attacks and real traffic, bridging the gap between academic adversarial ML and operational network security.

---

*Rafael Garcia -- CSUN CIT 2026*
