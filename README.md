# SentinelNet

**Network Intrusion Detection with Adversarial Robustness — Deployed on Bare Metal**

A production network intrusion detection system running on physically microsegmented infrastructure. scikit-learn models classify live network flows via a scapy-based traffic feeder on RISC-V edge hardware, with Suricata IDS providing signature-based detection. Deployed behind a Palo Alto PA-220 firewall with per-device security zones.

Designed from need, not flash. This system classifies live traffic on production hardware -- 1M+ predictions and counting.

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
- [ ] Adversarial robustness evaluation (FGSM, PGD, C&W)
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

## Hardware

| Node | Role | Specs |
|------|------|-------|
| Pi2 | K3s inference API + Wazuh HIDS | Pi 5, 16GB, ARM Cortex-A76 |
| Orange Pi RV2 | Edge sensor + scapy feeder | RISC-V, 4GB, SPAN on USW-Lite-8-PoE port 7 |
| PA-220 | Firewall | PAN-OS 10.2, 4 DMZ zones, physical microsegmentation |
| USW-Lite-8-PoE | SPAN switch | Port 7 mirrors port 8 (UDM uplink) |

## Production Stats (March 2026)

| Metric | Value |
|--------|-------|
| Total predictions | 1,077,000+ |
| BENIGN | 1,077,418 |
| DoS Hulk | 10 |
| DoS Slowhttptest | 1,042 |
| Training accuracy | 99.71% (CICIDS2017, 2.8M flows) |
| Inference latency | <500ms (RISC-V edge) |
| Suricata rules | 74,096 (ET Open + community) |

## Research Direction

The core research question: **how robust are neural network-based NIDS against adversarial perturbations in network flow features?**

We evaluate adversarial attacks (FGSM, PGD, C&W) against a classifier trained on CICIDS2017, then measure defense effectiveness through adversarial training with epsilon-bounded perturbations. The deployed pipeline enables evaluation on both synthetic attacks and real traffic, bridging the gap between academic adversarial ML and operational network security.

---

*Rafael Garcia -- CSUN CIT 2026*
