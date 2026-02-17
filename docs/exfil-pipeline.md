# Exfiltration Detection Pipeline

## Overview

SentinelNet v0.4.0 includes a dual-model architecture:
1. **Multi-class classifier** (15 categories, 99.71% accuracy) — supervised, trained on full CICIDS2017
2. **Exfil autoencoder** (anomaly detection) — unsupervised, trained on 1.82M benign flows only

The exfil autoencoder detects data exfiltration by learning the reconstruction of normal traffic patterns. Flows that reconstruct poorly (high MSE) are flagged as anomalous.

## Why Anomaly Detection Over Supervised

- CICIDS2017 has only 1,992 exfil-relevant samples (Bot: 1,956, Infiltration: 36) vs 2.27M benign
- 1,139:1 class imbalance makes supervised binary classification fragile
- Anomaly detection catches **novel** exfil techniques not in training data
- Works regardless of encryption (flow-level behavioral signals only)

## Model Architecture

```
Input (25 features) → Dense(16, ReLU) → Dense(8, ReLU) → Dense(4, ReLU)
    → Dense(8, ReLU) → Dense(16, ReLU) → Dense(25, Linear)
```

- **Loss:** MSE (reconstruction error)
- **Threshold:** p95 of benign validation reconstruction error = 0.1245
- **Separation:** 8.5x ratio between benign mean error and attack mean error

## Training Results

| Metric | Value |
|--------|-------|
| Training samples | 1,817,693 benign flows |
| Validation samples | 227,212 benign flows |
| Threshold (p95) | 0.1245 |
| Benign mean error | 0.0156 |
| Attack mean error | 0.1327 |
| Separation ratio | 8.5x |
| Attack recall (p95) | 3.9% |
| False positive rate | 5.1% |

## Live Pipeline

The `pipeline/` directory contains a production pipeline that:
1. Tails Suricata EVE JSON in real-time
2. Extracts 25 CICIDS2017-compatible features per flow
3. Batches and sends to SentinelNet `/exfil/detect/batch`
4. Routes alerts to Loki and Wazuh based on severity

### Feature Quality

16 of 25 features are grounded in real Suricata data (10 exact, 6 derived).
9 features require packet-level capture and are set to 0 (constant after normalization).
See `pipeline/flow_extractor.py` for the complete feature mapping.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/exfil/detect` | POST | Score single flow |
| `/exfil/detect/batch` | POST | Score batch of flows |
| `/exfil/info` | GET | Model metadata and threshold |

## Deployment

Running on Raspberry Pi 5 (16GB) as K3s pod in `sentinel` namespace.
Pipeline runs as systemd service (`sentinelnet-pipeline.service`) on same host.

## Future Improvements

1. Lower threshold to p90/p85 for better recall
2. Add flag count and packet length variance features
3. Deeper architecture (25→32→16→8→4)
4. Zeek integration for full per-packet feature coverage
5. Orange Pi RV2 SPAN port sensor for passive capture
