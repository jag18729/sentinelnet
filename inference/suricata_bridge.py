#!/usr/bin/env python3
"""
Suricata EVE → SentinelNet bridge.

Tails Suricata's eve.json, extracts flow features, maps them to
CICIDS2017 feature format, and feeds to SentinelNet ONNX model
for real-time classification.

Phase 1: Direct EVE flow mapping (~20/78 features, rest zeroed)
Phase 2: NFStream integration for full 78-feature extraction
"""

import json
import time
import sys
import os
import logging
import requests
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Config
SURICATA_EVE = os.getenv("SURICATA_EVE", "/home/rafaeljg/suricata/logs/eve.json")
SENTINELNET_URL = os.getenv("SENTINELNET_URL", "http://localhost:8000")
BRIDGE_LOG = os.getenv("BRIDGE_LOG", "/home/rafaeljg/sentinelnet-bridge.json")
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "0.7"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.0"))
CLASSIFY_FLOWS = os.getenv("CLASSIFY_FLOWS", "true").lower() == "true"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("suricata-bridge")

# Stats
stats = defaultdict(int)
classification_stats = defaultdict(int)

# CICIDS2017 feature names (78 features, ordered)
CICIDS_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]


def eve_flow_to_cicids(event: dict) -> np.ndarray:
    """
    Map Suricata EVE flow event to CICIDS2017 78-feature vector.
    
    Phase 1: Maps ~20 features from EVE flow stats, zeros the rest.
    The scaler will normalize zeros to the training mean, which is
    imperfect but gives the model something to work with.
    
    Phase 2 (TODO): Use NFStream for full per-packet feature extraction.
    """
    flow = event.get("flow", {})
    
    pkts_fwd = flow.get("pkts_toserver", 0)
    pkts_bwd = flow.get("pkts_toclient", 0)
    bytes_fwd = flow.get("bytes_toserver", 0)
    bytes_bwd = flow.get("bytes_toclient", 0)
    age = flow.get("age", 0)
    duration_us = age * 1_000_000  # seconds → microseconds
    
    total_pkts = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd
    
    # Derived stats
    fwd_pkt_mean = bytes_fwd / pkts_fwd if pkts_fwd > 0 else 0
    bwd_pkt_mean = bytes_bwd / pkts_bwd if pkts_bwd > 0 else 0
    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0
    flow_bytes_s = total_bytes / age if age > 0 else 0
    flow_pkts_s = total_pkts / age if age > 0 else 0
    fwd_pkts_s = pkts_fwd / age if age > 0 else 0
    bwd_pkts_s = pkts_bwd / age if age > 0 else 0
    down_up_ratio = pkts_bwd / pkts_fwd if pkts_fwd > 0 else 0
    
    features = np.zeros(78, dtype=np.float32)
    
    # Map what we can from EVE flow data
    features[0] = event.get("dest_port", 0)             # Destination Port
    features[1] = duration_us                             # Flow Duration
    features[2] = pkts_fwd                                # Total Fwd Packets
    features[3] = pkts_bwd                                # Total Backward Packets
    features[4] = bytes_fwd                               # Total Length of Fwd Packets
    features[5] = bytes_bwd                               # Total Length of Bwd Packets
    features[8] = fwd_pkt_mean                            # Fwd Packet Length Mean
    features[12] = bwd_pkt_mean                           # Bwd Packet Length Mean
    features[14] = flow_bytes_s                           # Flow Bytes/s
    features[15] = flow_pkts_s                            # Flow Packets/s
    features[36] = fwd_pkts_s                             # Fwd Packets/s
    features[37] = bwd_pkts_s                             # Bwd Packets/s
    features[40] = avg_pkt_size                           # Packet Length Mean
    features[51] = down_up_ratio                          # Down/Up Ratio
    features[52] = avg_pkt_size                           # Average Packet Size
    features[53] = fwd_pkt_mean                           # Avg Fwd Segment Size
    features[54] = bwd_pkt_mean                           # Avg Bwd Segment Size
    features[62] = pkts_fwd                               # Subflow Fwd Packets
    features[63] = bytes_fwd                              # Subflow Fwd Bytes
    features[64] = pkts_bwd                               # Subflow Bwd Packets
    features[65] = bytes_bwd                              # Subflow Bwd Bytes
    
    return features


def tail_eve(path: str):
    """Tail EVE JSON file, yielding new lines."""
    with open(path, "r") as f:
        f.seek(0, 2)  # Seek to end
        while True:
            line = f.readline()
            if line:
                try:
                    yield json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
            else:
                time.sleep(POLL_INTERVAL)


def classify_flow(features: np.ndarray) -> dict | None:
    """Send features to SentinelNet for classification."""
    try:
        r = requests.post(
            f"{SENTINELNET_URL}/predict",
            json={"features": features.tolist()},
            timeout=5,
        )
        if r.status_code == 200:
            return r.json()
        else:
            return None
    except Exception:
        return None


def log_event(record: dict):
    """Append to bridge log (JSON lines)."""
    try:
        with open(BRIDGE_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        log.error(f"Failed to write bridge log: {e}")


def check_sentinelnet() -> bool:
    """Verify SentinelNet API is up."""
    try:
        r = requests.get(f"{SENTINELNET_URL}/health", timeout=5)
        health = r.json()
        if health.get("model_loaded"):
            classes = health.get("classes", [])
            log.info(f"SentinelNet connected: {len(classes)} classes loaded")
            return True
        else:
            log.warning("SentinelNet model not loaded")
            return False
    except Exception as e:
        log.error(f"SentinelNet unreachable: {e}")
        return False


def main():
    log.info("=" * 60)
    log.info("Suricata EVE → SentinelNet Bridge v0.2")
    log.info(f"  EVE source:     {SURICATA_EVE}")
    log.info(f"  SentinelNet:    {SENTINELNET_URL}")
    log.info(f"  Bridge log:     {BRIDGE_LOG}")
    log.info(f"  Classification: {'enabled' if CLASSIFY_FLOWS else 'log-only'}")
    log.info(f"  Threshold:      {ALERT_THRESHOLD}")
    log.info("=" * 60)

    if not Path(SURICATA_EVE).exists():
        log.error(f"EVE file not found: {SURICATA_EVE}")
        sys.exit(1)

    sentinelnet_ok = check_sentinelnet()
    if not sentinelnet_ok:
        log.warning("Starting in log-only mode (no classification)")
        classify = False
    else:
        classify = CLASSIFY_FLOWS

    log.info("Tailing EVE JSON for flow/alert events...")
    
    for event in tail_eve(SURICATA_EVE):
        etype = event.get("event_type")
        stats[etype] += 1

        if etype == "alert":
            alert = event.get("alert", {})
            record = {
                "timestamp": event.get("timestamp"),
                "type": "suricata_alert",
                "severity": alert.get("severity"),
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "category": alert.get("category"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "community_id": event.get("community_id"),
            }
            log.warning(
                f"ALERT [{alert.get('severity', '?')}] "
                f"{alert.get('signature', 'unknown')} | "
                f"{event.get('src_ip')}:{event.get('src_port', '?')} → "
                f"{event.get('dest_ip')}:{event.get('dest_port', '?')}"
            )
            log_event(record)

        elif etype == "flow" and classify:
            features = eve_flow_to_cicids(event)
            result = classify_flow(features)
            
            if result and result.get("confidence", 0) >= ALERT_THRESHOLD:
                pred = result["prediction"]
                conf = result["confidence"]
                classification_stats[pred] += 1

                record = {
                    "timestamp": event.get("timestamp"),
                    "type": "sentinelnet_classification",
                    "prediction": pred,
                    "confidence": conf,
                    "src_ip": event.get("src_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto"),
                    "community_id": event.get("community_id"),
                    "flow_duration": event.get("flow", {}).get("age", 0),
                }
                
                if pred != "BENIGN":
                    log.warning(
                        f"ML DETECT [{conf:.2%}] {pred} | "
                        f"{event.get('src_ip')} → {event.get('dest_ip')}:{event.get('dest_port')}"
                    )
                
                log_event(record)

        # Periodic stats every 500 events
        total = sum(stats.values())
        if total % 500 == 0 and total > 0:
            log.info(f"Processed {total} events | Types: {dict(stats)}")
            if classification_stats:
                log.info(f"Classifications: {dict(classification_stats)}")


if __name__ == "__main__":
    main()
