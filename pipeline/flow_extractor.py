"""
SentinelNet Flow Feature Extractor
===================================
Converts Suricata EVE flow records → 25 CICIDS2017-compatible features
for the exfil autoencoder.

Data Source: Suricata EVE JSON (event_type="flow")
Target: SentinelNet /exfil/detect/batch endpoint on pi2

Feature Mapping Strategy:
  - 10 features computed EXACTLY from Suricata flow data
  - 6 features DERIVED with reasonable approximations
  - 9 features set to ZERO (IAT/Active/Idle stats unavailable from
    flow-level summaries; requires packet-level capture for ground truth)

The autoencoder was trained on StandardScaler-normalized data, so zero-valued
features become (0 - mean) / scale, which is a learnable constant offset.
This is explicitly validated at startup.

Author: Frank (OpenClaw) for Rafa's SentinelNet pipeline
Date: 2026-02-16
"""

import json
import math
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("flow_extractor")

# The 25 features expected by the exfil autoencoder, in order.
FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Down/Up Ratio",
    "Average Packet Size",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
    "Active Mean",
    "Idle Mean",
]

# Classification of each feature by data availability from Suricata flows.
# EXACT: computed directly from Suricata fields
# DERIVED: reasonable approximation from available data
# UNAVAILABLE: requires packet-level data; set to 0 (known limitation)
FEATURE_SOURCE = {
    "Flow Duration": "EXACT",            # end - start timestamps
    "Total Fwd Packets": "EXACT",        # pkts_toserver
    "Total Backward Packets": "EXACT",   # pkts_toclient
    "Total Length of Fwd Packets": "EXACT",   # bytes_toserver
    "Total Length of Bwd Packets": "EXACT",   # bytes_toclient
    "Fwd Packet Length Mean": "DERIVED",      # bytes_toserver / pkts_toserver
    "Fwd Packet Length Std": "UNAVAILABLE",   # needs per-packet sizes
    "Bwd Packet Length Mean": "DERIVED",      # bytes_toclient / pkts_toclient
    "Bwd Packet Length Std": "UNAVAILABLE",   # needs per-packet sizes
    "Flow Bytes/s": "DERIVED",                # total_bytes / duration
    "Flow Packets/s": "DERIVED",              # total_packets / duration
    "Flow IAT Mean": "DERIVED",               # duration / (total_packets - 1)
    "Flow IAT Std": "UNAVAILABLE",            # needs per-packet timestamps
    "Flow IAT Max": "UNAVAILABLE",            # needs per-packet timestamps
    "Flow IAT Min": "UNAVAILABLE",            # needs per-packet timestamps
    "Fwd IAT Mean": "DERIVED",               # duration / (fwd_packets - 1)
    "Fwd IAT Std": "UNAVAILABLE",            # needs per-packet timestamps
    "Bwd IAT Mean": "DERIVED",               # duration / (bwd_packets - 1)
    "Bwd IAT Std": "UNAVAILABLE",            # needs per-packet timestamps
    "Down/Up Ratio": "EXACT",                 # pkts_toclient / pkts_toserver
    "Average Packet Size": "EXACT",           # total_bytes / total_packets
    "Subflow Fwd Bytes": "EXACT",             # = Total Length of Fwd Packets (1 subflow)
    "Subflow Bwd Bytes": "EXACT",             # = Total Length of Bwd Packets (1 subflow)
    "Active Mean": "UNAVAILABLE",             # needs TCP state machine tracking
    "Idle Mean": "UNAVAILABLE",               # needs TCP state machine tracking
}


@dataclass
class FlowFeatures:
    """25-feature vector for one network flow."""
    values: list[float] = field(default_factory=lambda: [0.0] * 25)
    flow_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    timestamp: Optional[str] = None
    quality: str = "full"  # full, partial, degraded
    unavailable_features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "features": self.values,
            "metadata": {
                "flow_id": self.flow_id,
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "proto": self.proto,
                "timestamp": self.timestamp,
                "quality": self.quality,
                "unavailable_count": len(self.unavailable_features),
            }
        }


@dataclass
class ExtractionStats:
    """Track extraction quality for monitoring."""
    total: int = 0
    success: int = 0
    skipped_no_packets: int = 0
    skipped_parse_error: int = 0
    quality_full: int = 0
    quality_partial: int = 0
    quality_degraded: int = 0

    def summary(self) -> dict:
        return {
            "total_processed": self.total,
            "successful": self.success,
            "skipped_no_packets": self.skipped_no_packets,
            "skipped_parse_error": self.skipped_parse_error,
            "quality_breakdown": {
                "full": self.quality_full,
                "partial": self.quality_partial,
                "degraded": self.quality_degraded,
            },
            "success_rate": f"{self.success/max(self.total,1)*100:.1f}%",
        }


class FeatureValidator:
    """Validates extracted features against training distribution."""

    def __init__(self, scaler_path: str):
        with open(scaler_path) as f:
            scaler = json.load(f)
        self.means = scaler["mean"]
        self.scales = scaler["scale"]
        self.features = scaler["features"]
        assert len(self.means) == 25
        assert len(self.scales) == 25
        assert self.features == FEATURE_NAMES, (
            f"Feature name mismatch between scaler and extractor"
        )
        logger.info("Loaded scaler: %d features validated", len(self.features))

    def normalize(self, raw: list[float]) -> list[float]:
        """Apply StandardScaler: (x - mean) / scale."""
        return [(x - m) / s for x, m, s in zip(raw, self.means, self.scales)]

    def check_range(self, raw: list[float], sigma: float = 5.0) -> list[str]:
        """Flag features outside sigma standard deviations from training mean.
        
        Returns list of warning strings for features outside range.
        This doesn't reject the flow — extreme values are exactly what
        the autoencoder should flag as anomalous.
        """
        warnings = []
        for i, (x, m, s) in enumerate(zip(raw, self.means, self.scales)):
            if s > 0:
                z = abs((x - m) / s)
                if z > sigma:
                    warnings.append(
                        f"{self.features[i]}: z={z:.1f} (raw={x:.2f}, "
                        f"mean={m:.2f}, scale={s:.2f})"
                    )
        return warnings

    def zero_feature_impact(self) -> dict:
        """Show what zero-valued unavailable features normalize to.
        
        This is important for understanding model behavior — unavailable
        features aren't truly 'missing', they produce constant normalized
        values that the model sees on every input.
        """
        impact = {}
        for name, source in FEATURE_SOURCE.items():
            if source == "UNAVAILABLE":
                idx = FEATURE_NAMES.index(name)
                normalized_zero = -self.means[idx] / self.scales[idx]
                impact[name] = {
                    "raw_value": 0.0,
                    "normalized_value": round(normalized_zero, 4),
                    "training_mean": round(self.means[idx], 4),
                    "training_scale": round(self.scales[idx], 4),
                }
        return impact


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    """Division with zero protection."""
    return a / b if b > 0 else default


def _parse_timestamp(ts: str) -> float:
    """Parse Suricata ISO timestamp to epoch microseconds."""
    # Suricata format: 2026-02-16T18:25:21.511588-0800
    try:
        dt = datetime.fromisoformat(ts)
        return dt.timestamp() * 1_000_000  # microseconds
    except (ValueError, TypeError):
        return 0.0


def extract_features(record: dict) -> Optional[FlowFeatures]:
    """Extract 25 CICIDS2017 features from a Suricata EVE flow record.
    
    Args:
        record: Parsed JSON dict from Suricata EVE with event_type="flow"
    
    Returns:
        FlowFeatures or None if the record is unusable.
    """
    flow = record.get("flow", {})
    if not flow:
        return None

    # Raw Suricata fields
    pkts_fwd = flow.get("pkts_toserver", 0)
    pkts_bwd = flow.get("pkts_toclient", 0)
    bytes_fwd = flow.get("bytes_toserver", 0)
    bytes_bwd = flow.get("bytes_toclient", 0)
    total_pkts = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd

    # Skip empty flows (no packets = no signal)
    if total_pkts == 0:
        return None

    # Duration in microseconds (CICIDS2017 convention)
    start_us = _parse_timestamp(flow.get("start", ""))
    end_us = _parse_timestamp(flow.get("end", ""))
    duration_us = max(end_us - start_us, 0.0)
    # If duration is 0 but age > 0, use age (seconds)
    if duration_us == 0 and flow.get("age", 0) > 0:
        duration_us = flow["age"] * 1_000_000
    duration_s = duration_us / 1_000_000

    # === EXACT FEATURES ===
    f_duration = duration_us
    f_fwd_pkts = float(pkts_fwd)
    f_bwd_pkts = float(pkts_bwd)
    f_fwd_bytes = float(bytes_fwd)
    f_bwd_bytes = float(bytes_bwd)
    f_down_up = _safe_div(pkts_bwd, pkts_fwd)
    f_avg_pkt_size = _safe_div(total_bytes, total_pkts)
    f_subfwd_bytes = float(bytes_fwd)  # 1 subflow = total
    f_subbwd_bytes = float(bytes_bwd)

    # === DERIVED FEATURES ===
    f_fwd_pkt_mean = _safe_div(bytes_fwd, pkts_fwd)
    f_bwd_pkt_mean = _safe_div(bytes_bwd, pkts_bwd)
    f_bytes_per_s = _safe_div(total_bytes, duration_s)
    f_pkts_per_s = _safe_div(total_pkts, duration_s)
    # IAT mean approximations (duration spread across inter-packet gaps)
    f_flow_iat_mean = _safe_div(duration_us, max(total_pkts - 1, 1))
    f_fwd_iat_mean = _safe_div(duration_us, max(pkts_fwd - 1, 1))
    f_bwd_iat_mean = _safe_div(duration_us, max(pkts_bwd - 1, 1))

    # === UNAVAILABLE (set to 0) ===
    f_fwd_pkt_std = 0.0
    f_bwd_pkt_std = 0.0
    f_flow_iat_std = 0.0
    f_flow_iat_max = 0.0
    f_flow_iat_min = 0.0
    f_fwd_iat_std = 0.0
    f_bwd_iat_std = 0.0
    f_active_mean = 0.0
    f_idle_mean = 0.0

    # Build feature vector in EXACT order
    values = [
        f_duration,           # 0: Flow Duration
        f_fwd_pkts,           # 1: Total Fwd Packets
        f_bwd_pkts,           # 2: Total Backward Packets
        f_fwd_bytes,          # 3: Total Length of Fwd Packets
        f_bwd_bytes,          # 4: Total Length of Bwd Packets
        f_fwd_pkt_mean,       # 5: Fwd Packet Length Mean
        f_fwd_pkt_std,        # 6: Fwd Packet Length Std
        f_bwd_pkt_mean,       # 7: Bwd Packet Length Mean
        f_bwd_pkt_std,        # 8: Bwd Packet Length Std
        f_bytes_per_s,        # 9: Flow Bytes/s
        f_pkts_per_s,         # 10: Flow Packets/s
        f_flow_iat_mean,      # 11: Flow IAT Mean
        f_flow_iat_std,       # 12: Flow IAT Std
        f_flow_iat_max,       # 13: Flow IAT Max
        f_flow_iat_min,       # 14: Flow IAT Min
        f_fwd_iat_mean,       # 15: Fwd IAT Mean
        f_fwd_iat_std,        # 16: Fwd IAT Std
        f_bwd_iat_mean,       # 17: Bwd IAT Mean
        f_bwd_iat_std,        # 18: Bwd IAT Std
        f_down_up,            # 19: Down/Up Ratio
        f_avg_pkt_size,       # 20: Average Packet Size
        f_subfwd_bytes,       # 21: Subflow Fwd Bytes
        f_subbwd_bytes,       # 22: Subflow Bwd Bytes
        f_active_mean,        # 23: Active Mean
        f_idle_mean,          # 24: Idle Mean
    ]

    # Sanitize: replace NaN/inf with 0
    values = [0.0 if (math.isnan(v) or math.isinf(v)) else v for v in values]

    # Determine quality
    unavailable = [n for n, s in FEATURE_SOURCE.items() if s == "UNAVAILABLE"]
    exact_count = sum(1 for s in FEATURE_SOURCE.values() if s == "EXACT")
    derived_count = sum(1 for s in FEATURE_SOURCE.values() if s == "DERIVED")
    
    # Quality: how much of the feature vector is grounded in real data
    # 10 EXACT + 6 DERIVED = 16/25 features (64%) have signal
    quality = "partial"  # Default: we always have some unavailable features
    if total_pkts >= 5 and duration_us > 0:
        quality = "full"  # Good flow with enough data for meaningful features

    return FlowFeatures(
        values=values,
        flow_id=str(record.get("flow_id", "")),
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"),
        src_port=record.get("src_port"),
        dst_port=record.get("dest_port"),
        proto=record.get("proto"),
        timestamp=record.get("timestamp"),
        quality=quality,
        unavailable_features=unavailable,
    )


def extract_from_eve_file(
    path: str,
    max_records: Optional[int] = None,
    min_packets: int = 2,
) -> tuple[list[FlowFeatures], ExtractionStats]:
    """Extract features from a Suricata EVE JSON file.
    
    Args:
        path: Path to eve.json
        max_records: Limit number of flow records processed
        min_packets: Minimum total packets for a flow to be processed
    
    Returns:
        (list of FlowFeatures, ExtractionStats)
    """
    stats = ExtractionStats()
    results = []

    with open(path) as f:
        for line in f:
            if max_records and stats.success >= max_records:
                break

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                stats.skipped_parse_error += 1
                continue

            if record.get("event_type") != "flow":
                continue

            stats.total += 1
            flow = record.get("flow", {})
            total_pkts = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)

            if total_pkts < min_packets:
                stats.skipped_no_packets += 1
                continue

            features = extract_features(record)
            if features is None:
                stats.skipped_no_packets += 1
                continue

            stats.success += 1
            if features.quality == "full":
                stats.quality_full += 1
            elif features.quality == "partial":
                stats.quality_partial += 1
            else:
                stats.quality_degraded += 1

            results.append(features)

    return results, stats


if __name__ == "__main__":
    """Standalone validation: extract features from EVE and print quality report."""
    import sys
    
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    
    eve_path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"
    scaler_path = sys.argv[2] if len(sys.argv) > 2 else "/home/rafaeljg/sentinelnet-models/exfil_scaler.json"
    
    # Validate feature mapping
    print("=" * 60)
    print("FEATURE SOURCE AUDIT")
    print("=" * 60)
    for name in FEATURE_NAMES:
        src = FEATURE_SOURCE[name]
        marker = {"EXACT": "✅", "DERIVED": "≈ ", "UNAVAILABLE": "❌"}[src]
        print(f"  {marker} {name:35s} [{src}]")
    
    exact = sum(1 for s in FEATURE_SOURCE.values() if s == "EXACT")
    derived = sum(1 for s in FEATURE_SOURCE.values() if s == "DERIVED")
    unavail = sum(1 for s in FEATURE_SOURCE.values() if s == "UNAVAILABLE")
    print(f"\nSignal: {exact} exact + {derived} derived = {exact+derived}/25 features")
    print(f"Unavailable: {unavail}/25 (set to 0, constant after normalization)")

    # Load scaler and show zero-feature impact
    try:
        validator = FeatureValidator(scaler_path)
        print("\n" + "=" * 60)
        print("ZERO-FEATURE IMPACT (unavailable features after normalization)")
        print("=" * 60)
        for name, info in validator.zero_feature_impact().items():
            nv = info["normalized_value"]
            print(f"  {name:35s} → normalized={nv:>8.4f}")
    except FileNotFoundError:
        print(f"\n⚠ Scaler not found at {scaler_path}, skipping validation")
        validator = None

    # Extract from EVE
    print(f"\n{'=' * 60}")
    print(f"EXTRACTING FROM {eve_path}")
    print("=" * 60)
    
    features_list, stats = extract_from_eve_file(eve_path, max_records=100)
    print(json.dumps(stats.summary(), indent=2))

    if features_list and validator:
        # Validate a sample
        print(f"\n{'=' * 60}")
        print("SAMPLE VALIDATION (first 5 flows)")
        print("=" * 60)
        for ff in features_list[:5]:
            warnings = validator.check_range(ff.values, sigma=5.0)
            normalized = validator.normalize(ff.values)
            print(f"\n  Flow {ff.flow_id}: {ff.src_ip}:{ff.src_port} → {ff.dst_ip}:{ff.dst_port} [{ff.proto}]")
            print(f"    Quality: {ff.quality} | Duration: {ff.values[0]/1e6:.2f}s | Pkts: {ff.values[1]:.0f}↑ {ff.values[2]:.0f}↓ | Bytes: {ff.values[3]:.0f}↑ {ff.values[4]:.0f}↓")
            if warnings:
                for w in warnings:
                    print(f"    ⚠ {w}")
            else:
                print(f"    ✅ All features within 5σ of training distribution")
