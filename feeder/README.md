# SentinelNet Edge Feeder (RV2 / RISC-V)

Scapy-based traffic feeder that captures packets from a SPAN mirror port, extracts 78 CICFlowMeter-compatible features per flow, and POSTs them to the SentinelNet inference API on Pi2.

## Deployment

Runs on Orange Pi RV2 (RISC-V), connected to USW-Lite-8-PoE port 7 (SPAN mirror of uplink).

### Prerequisites
```bash
sudo apt install python3-scapy python3-requests
```

### Install
```bash
mkdir -p /home/rafaeljg/sentinelnet-feeder
cp feeder.py /home/rafaeljg/sentinelnet-feeder/
sudo cp sentinelnet-feeder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet-feeder
```

### Check
```bash
systemctl status sentinelnet-feeder
journalctl -u sentinelnet-feeder -f
```

## Configuration

Edit constants at the top of `feeder.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | `end1` | Network interface to sniff (SPAN port) |
| `INFER_URL` | `http://100.111.113.35:30800/predict` | Pi2 SentinelNet API via Tailscale |
| `IDLE_TO` | `15` | Seconds before expiring idle flows |
| `ACTIVE_TO` | `600` | Max flow duration before forced export |

## Architecture

```
USW-Lite-8-PoE port 8 (UDM uplink)
        │ SPAN mirror
        ▼
USW-Lite-8-PoE port 7 → RV2 end1 (promiscuous, no IP)
        │
   scapy sniff → FlowState table → 78 features → POST /predict
        │
   SentinelNet API (Pi2 K3s, port 30800) → Prometheus metrics → Grafana
```
