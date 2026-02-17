# SentinelNet Exfil Detection Pipeline

Real-time anomaly-based exfiltration detection using Suricata flow records and an autoencoder trained exclusively on benign CICIDS2017 traffic.

## Architecture

```
Suricata EVE JSON ──► Flow Feature Extractor ──► SentinelNet API ──► Alert Router
   (flow records)       (25 CICIDS2017 features)    (ONNX autoencoder)    ├── Loki
                                                                          ├── Wazuh (syslog)
                                                                          └── journald
```

## Components

| File | Purpose |
|------|---------|
| `flow_extractor.py` | Converts Suricata EVE flow records to 25 CICIDS2017-compatible features |
| `pipeline.py` | Real-time pipeline: tails EVE, batches flows, sends to SentinelNet, routes alerts |
| `whitelist.json` | Infrastructure flow whitelist (SSH, Prometheus, DNS, etc.) |
| `sentinelnet-pipeline.service` | systemd unit for production deployment |

## Feature Mapping

The extractor maps Suricata flow-level data to 25 CICIDS2017 features:

- **10 EXACT** — computed directly from Suricata fields (packet counts, byte counts, duration, ratios)
- **6 DERIVED** — reasonable approximations (mean packet size, IAT mean, bytes/s)
- **9 UNAVAILABLE** — require packet-level capture (IAT std/max/min, packet length std, active/idle times)

Unavailable features are set to 0 and produce constant normalized values. This is documented and validated at startup. For full feature coverage, packet-level capture via Zeek or a SPAN port sensor is needed.

## Alert Tiers

| Severity | Condition | Actions |
|----------|-----------|---------|
| WARNING | score > threshold × 0.8 | Log only |
| CRITICAL | score > threshold | Log + Loki + Wazuh syslog |
| EMERGENCY | score > threshold × 2.0 | Log + Loki + Wazuh syslog (high confidence) |

## Rate Limiting

- Per source/destination pair: 1 alert per 60 seconds
- Global: max 20 alerts per minute
- Whitelisted flows are scored but never alerted

## Deployment

```bash
# Install on pi2 (same host as Suricata + SentinelNet)
cp -r pipeline/ ~/sentinelnet-pipeline/
pip3 install -r pipeline/requirements.txt

# Install and start service
sudo cp pipeline/sentinelnet-pipeline.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet-pipeline

# Check logs
journalctl -u sentinelnet-pipeline -f
```

## Configuration

Environment variables (set in systemd unit or shell):

| Variable | Default | Description |
|----------|---------|-------------|
| `EVE_PATH` | `/var/log/suricata/eve.json` | Suricata EVE log path |
| `SENTINELNET_URL` | `http://localhost:30800` | SentinelNet API endpoint |
| `LOKI_URL` | `http://192.168.20.10:3100` | Loki push endpoint |
| `SCALER_PATH` | `~/sentinelnet-models/exfil_scaler.json` | StandardScaler params |
| `BATCH_SIZE` | `50` | Flows per API batch |
| `BATCH_TIMEOUT_S` | `5.0` | Max seconds before sending partial batch |
| `MIN_PACKETS` | `3` | Minimum packets for a flow to be analyzed |

## Standalone Validation

Run the feature extractor directly to audit feature quality:

```bash
python3 flow_extractor.py /var/log/suricata/eve.json /path/to/exfil_scaler.json
```

This prints:
- Feature source audit (EXACT/DERIVED/UNAVAILABLE)
- Zero-feature normalization impact
- Extraction statistics
- Sample flow validation against training distribution
