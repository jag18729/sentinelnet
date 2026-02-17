"""
SentinelNet Exfil Detection Pipeline
=====================================
Real-time flow analysis pipeline:
  Suricata EVE → Feature Extraction → SentinelNet API → Alert Routing

Runs as a systemd service on pi2 (same host as Suricata + SentinelNet).
Tails Suricata EVE JSON, batches flow records, and sends to the
/exfil/detect/batch endpoint for anomaly scoring.

Alert routing:
  - WARNING (score > threshold * 0.8): log only
  - CRITICAL (score > threshold): push to Loki + Wazuh syslog
  - EMERGENCY (score > threshold * 2): all of above + immediate log

Author: Frank (OpenClaw) for Rafa's SentinelNet pipeline
Date: 2026-02-16
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp

from flow_extractor import (
    ExtractionStats,
    FeatureValidator,
    FlowFeatures,
    extract_features,
)

# ── Configuration ────────────────────────────────────────────
SURICATA_EVE = os.getenv("EVE_PATH", "/var/log/suricata/eve.json")
SENTINELNET_URL = os.getenv("SENTINELNET_URL", "http://localhost:30800")
LOKI_URL = os.getenv("LOKI_URL", "http://192.168.20.10:3100")
SCALER_PATH = os.getenv("SCALER_PATH", "/home/rafaeljg/sentinelnet-models/exfil_scaler.json")

# Batching
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
BATCH_TIMEOUT_S = float(os.getenv("BATCH_TIMEOUT_S", "5.0"))
MIN_PACKETS = int(os.getenv("MIN_PACKETS", "3"))

# Alert thresholds (relative to model threshold from exfil_meta.json)
WARN_FACTOR = 0.8    # 80% of threshold = early warning
CRIT_FACTOR = 1.0    # 100% = anomalous
EMERG_FACTOR = 2.0   # 200% = high-confidence exfil

# Rate limiting: don't spam alerts
ALERT_COOLDOWN_S = 60  # Min seconds between alerts for same src_ip+dst_ip pair
MAX_ALERTS_PER_MIN = 20

# Metrics
METRICS_LOG_INTERVAL_S = 300  # Log pipeline stats every 5 min
WHITELIST_PATH = os.getenv("WHITELIST_PATH", "/home/rafaeljg/sentinelnet-pipeline/whitelist.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pipeline")


@dataclass
class PipelineMetrics:
    """Pipeline performance and quality metrics."""
    started_at: float = field(default_factory=time.time)
    flows_read: int = 0
    flows_extracted: int = 0
    flows_skipped: int = 0
    batches_sent: int = 0
    api_errors: int = 0
    alerts_warning: int = 0
    alerts_critical: int = 0
    alerts_emergency: int = 0
    alerts_suppressed: int = 0
    last_batch_latency_ms: float = 0.0

    def summary(self) -> dict:
        uptime = time.time() - self.started_at
        return {
            "uptime_s": round(uptime),
            "flows_read": self.flows_read,
            "flows_extracted": self.flows_extracted,
            "flows_skipped": self.flows_skipped,
            "batches_sent": self.batches_sent,
            "api_errors": self.api_errors,
            "alerts": {
                "warning": self.alerts_warning,
                "critical": self.alerts_critical,
                "emergency": self.alerts_emergency,
                "suppressed": self.alerts_suppressed,
            },
            "whitelisted": self.alerts_suppressed,  # reuse field
            "flows_per_sec": round(self.flows_read / max(uptime, 1), 2),
            "last_batch_latency_ms": round(self.last_batch_latency_ms, 1),
        }


class Whitelist:
    """Flow whitelist for known infrastructure traffic."""

    def __init__(self, path: str):
        self.rules = []
        try:
            with open(path) as f:
                data = json.load(f)
            self.rules = data.get("rules", [])
            logger.info("Loaded %d whitelist rules", len(self.rules))
            for r in self.rules:
                logger.info("  Whitelist: %s — %s", r["name"], r.get("description", ""))
        except FileNotFoundError:
            logger.warning("No whitelist at %s, all flows will be scored", path)

    def matches(self, flow: FlowFeatures) -> Optional[str]:
        """Check if flow matches any whitelist rule. Returns rule name or None."""
        for rule in self.rules:
            match = True
            if "src_ip" in rule and flow.src_ip != rule["src_ip"]:
                match = False
            if "dst_ip" in rule and flow.dst_ip != rule["dst_ip"]:
                match = False
            if "src_port" in rule and flow.src_port != rule["src_port"]:
                match = False
            if "dst_port" in rule and flow.dst_port != rule["dst_port"]:
                match = False
            if "proto" in rule and flow.proto != rule["proto"]:
                match = False
            if match:
                return rule["name"]
        return None


class AlertRouter:
    """Routes anomaly alerts to appropriate destinations with rate limiting."""

    def __init__(self, loki_url: str, threshold: float):
        self.loki_url = loki_url
        self.threshold = threshold
        self.cooldown: dict[str, float] = {}  # "src:dst" → last alert time
        self.alert_count_window: deque = deque()  # timestamps of recent alerts
        self.metrics = PipelineMetrics()
        self.whitelist = Whitelist(WHITELIST_PATH)
        self.whitelisted_count = 0

    def _rate_ok(self, flow_key: str) -> bool:
        """Check rate limits for this flow pair."""
        now = time.time()
        # Per-pair cooldown
        if flow_key in self.cooldown:
            if now - self.cooldown[flow_key] < ALERT_COOLDOWN_S:
                self.metrics.alerts_suppressed += 1
                return False
        # Global rate limit
        while self.alert_count_window and self.alert_count_window[0] < now - 60:
            self.alert_count_window.popleft()
        if len(self.alert_count_window) >= MAX_ALERTS_PER_MIN:
            self.metrics.alerts_suppressed += 1
            return False
        self.cooldown[flow_key] = now
        self.alert_count_window.append(now)
        return True

    async def route_alert(
        self,
        session: aiohttp.ClientSession,
        flow: FlowFeatures,
        score: float,
        severity: str,
    ):
        """Route an alert based on severity."""
        flow_key = f"{flow.src_ip}:{flow.dst_ip}"
        
        if severity == "warning":
            self.metrics.alerts_warning += 1
            # Warnings: log only, no rate limit check
            logger.warning(
                "EXFIL WARNING: %s:%s → %s:%s [%s] score=%.4f (threshold=%.4f)",
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                flow.proto, score, self.threshold,
            )
            return

        if not self._rate_ok(flow_key):
            return

        if severity == "critical":
            self.metrics.alerts_critical += 1
        elif severity == "emergency":
            self.metrics.alerts_emergency += 1

        alert_data = {
            "severity": severity,
            "score": round(score, 6),
            "threshold": round(self.threshold, 6),
            "ratio": round(score / self.threshold, 2),
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "proto": flow.proto,
            "flow_id": flow.flow_id,
            "timestamp": flow.timestamp,
            "duration_s": round(flow.values[0] / 1e6, 3),
            "fwd_bytes": flow.values[3],
            "bwd_bytes": flow.values[4],
            "fwd_pkts": flow.values[1],
            "bwd_pkts": flow.values[2],
        }

        logger.critical(
            "EXFIL %s: %s:%s → %s:%s [%s] score=%.4f (%.1fx threshold) "
            "bytes=%d↑/%d↓ pkts=%d↑/%d↓",
            severity.upper(),
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
            flow.proto, score, score / self.threshold,
            flow.values[3], flow.values[4], flow.values[1], flow.values[2],
        )

        # Push to Loki
        await self._push_loki(session, alert_data)

        # Push to Wazuh via syslog (UDP 514 on pi2 localhost)
        self._push_syslog(alert_data)

    async def _push_loki(self, session: aiohttp.ClientSession, alert: dict):
        """Push alert to Loki for Grafana dashboards."""
        try:
            payload = {
                "streams": [{
                    "stream": {
                        "job": "sentinelnet-exfil",
                        "severity": alert["severity"],
                        "src_ip": alert["src_ip"] or "unknown",
                        "dst_ip": alert["dst_ip"] or "unknown",
                    },
                    "values": [[
                        str(int(time.time() * 1e9)),
                        json.dumps(alert),
                    ]]
                }]
            }
            async with session.post(
                f"{self.loki_url}/loki/api/v1/push",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status not in (200, 204):
                    logger.error("Loki push failed: %d", resp.status)
        except Exception as e:
            logger.error("Loki push error: %s", e)

    def _push_syslog(self, alert: dict):
        """Push alert to Wazuh via local syslog (UDP 514)."""
        import socket
        try:
            msg = (
                f"<134>sentinelnet-exfil: severity={alert['severity']} "
                f"score={alert['score']} threshold={alert['threshold']} "
                f"src={alert['src_ip']}:{alert['src_port']} "
                f"dst={alert['dst_ip']}:{alert['dst_port']} "
                f"proto={alert.get('proto','unknown')} "
                f"fwd_bytes={alert['fwd_bytes']:.0f} bwd_bytes={alert['bwd_bytes']:.0f}"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), ("127.0.0.1", 514))
            sock.close()
        except Exception as e:
            logger.error("Syslog push error: %s", e)


class EVETailer:
    """Tail Suricata EVE JSON file, yielding new flow records.
    
    Handles log rotation by detecting file truncation/inode change.
    """

    def __init__(self, path: str):
        self.path = path
        self._offset = 0
        self._inode = 0

    async def tail(self):
        """Async generator yielding parsed flow records."""
        # Start at end of file (only process new flows)
        try:
            stat = os.stat(self.path)
            self._offset = stat.st_size
            self._inode = stat.st_ino
            logger.info("Starting tail at offset %d (%.1f MB)", self._offset, self._offset/1e6)
        except FileNotFoundError:
            logger.warning("EVE file not found, waiting: %s", self.path)
            self._offset = 0

        while True:
            try:
                stat = os.stat(self.path)
            except FileNotFoundError:
                await asyncio.sleep(1)
                continue

            # Detect rotation (inode changed or file shrunk)
            if stat.st_ino != self._inode or stat.st_size < self._offset:
                logger.info("EVE rotated, resetting offset")
                self._offset = 0
                self._inode = stat.st_ino

            if stat.st_size > self._offset:
                with open(self.path) as f:
                    f.seek(self._offset)
                    for line in f:
                        try:
                            record = json.loads(line)
                            if record.get("event_type") == "flow":
                                yield record
                        except json.JSONDecodeError:
                            continue
                    self._offset = f.tell()
            else:
                await asyncio.sleep(0.5)


class Pipeline:
    """Main pipeline: EVE tail → feature extraction → SentinelNet → alerts."""

    def __init__(self):
        self.tailer = EVETailer(SURICATA_EVE)
        self.validator: Optional[FeatureValidator] = None
        self.router: Optional[AlertRouter] = None
        self.metrics = PipelineMetrics()
        self._shutdown = asyncio.Event()

    async def start(self):
        """Initialize and run the pipeline."""
        logger.info("=" * 60)
        logger.info("SentinelNet Exfil Detection Pipeline")
        logger.info("=" * 60)
        logger.info("EVE source: %s", SURICATA_EVE)
        logger.info("SentinelNet: %s", SENTINELNET_URL)
        logger.info("Loki: %s", LOKI_URL)
        logger.info("Batch: %d flows / %.1fs timeout", BATCH_SIZE, BATCH_TIMEOUT_S)
        logger.info("Min packets per flow: %d", MIN_PACKETS)

        # Load scaler for validation
        try:
            self.validator = FeatureValidator(SCALER_PATH)
        except FileNotFoundError:
            logger.error("Scaler not found at %s — cannot validate features", SCALER_PATH)
            sys.exit(1)

        # Get model threshold from SentinelNet
        threshold = await self._get_threshold()
        logger.info("Model threshold: %.6f", threshold)
        self.router = AlertRouter(LOKI_URL, threshold)
        self.router.metrics = self.metrics

        # Log zero-feature impact
        impact = self.validator.zero_feature_impact()
        logger.info("Unavailable features (set to 0 → constant after normalization):")
        for name, info in impact.items():
            logger.info("  %s → normalized=%.4f", name, info["normalized_value"])

        # Run pipeline + metrics logger concurrently
        await asyncio.gather(
            self._process_loop(),
            self._metrics_logger(),
        )

    async def _get_threshold(self) -> float:
        """Fetch exfil threshold from SentinelNet API."""
        async with aiohttp.ClientSession() as session:
            for attempt in range(5):
                try:
                    async with session.get(
                        f"{SENTINELNET_URL}/exfil/info",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data["threshold"]
                except Exception as e:
                    logger.warning("Failed to get threshold (attempt %d): %s", attempt + 1, e)
                    await asyncio.sleep(2 ** attempt)
        logger.error("Could not fetch threshold after 5 attempts, using default")
        return 0.1245  # Fallback from training

    async def _process_loop(self):
        """Main processing loop: batch flows and send to SentinelNet."""
        batch: list[FlowFeatures] = []
        last_send = time.time()

        async with aiohttp.ClientSession() as session:
            async for record in self.tailer.tail():
                if self._shutdown.is_set():
                    break

                self.metrics.flows_read += 1
                flow = record.get("flow", {})
                total_pkts = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)

                if total_pkts < MIN_PACKETS:
                    self.metrics.flows_skipped += 1
                    continue

                features = extract_features(record)
                if features is None:
                    self.metrics.flows_skipped += 1
                    continue

                self.metrics.flows_extracted += 1
                batch.append(features)

                # Send batch when full or timeout
                now = time.time()
                if len(batch) >= BATCH_SIZE or (now - last_send > BATCH_TIMEOUT_S and batch):
                    await self._send_batch(session, batch)
                    batch = []
                    last_send = now

    async def _send_batch(self, session: aiohttp.ClientSession, batch: list[FlowFeatures]):
        """Send a batch of flows to SentinelNet for scoring."""
        if not batch:
            return

        payload = {
            "flows": [ff.values for ff in batch]
        }

        t0 = time.time()
        try:
            async with session.post(
                f"{SENTINELNET_URL}/exfil/detect/batch",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                latency_ms = (time.time() - t0) * 1000
                self.metrics.last_batch_latency_ms = latency_ms
                self.metrics.batches_sent += 1

                if resp.status != 200:
                    self.metrics.api_errors += 1
                    logger.error("SentinelNet API error: %d", resp.status)
                    return

                results = await resp.json()

        except Exception as e:
            self.metrics.api_errors += 1
            logger.error("SentinelNet API error: %s", e)
            return

        # Process results
        for ff, result in zip(batch, results.get("results", [])):
            score = result.get("reconstruction_error", 0)
            is_anomaly = result.get("anomaly", False)

            # Check whitelist before alerting
            wl_match = self.router.whitelist.matches(ff)
            if wl_match:
                self.router.whitelisted_count += 1
                continue

            if score >= self.router.threshold * EMERG_FACTOR:
                await self.router.route_alert(session, ff, score, "emergency")
            elif is_anomaly:
                await self.router.route_alert(session, ff, score, "critical")
            elif score >= self.router.threshold * WARN_FACTOR:
                await self.router.route_alert(session, ff, score, "warning")

    async def _metrics_logger(self):
        """Periodically log pipeline metrics."""
        while not self._shutdown.is_set():
            await asyncio.sleep(METRICS_LOG_INTERVAL_S)
            logger.info("Pipeline metrics: %s", json.dumps(self.metrics.summary()))

    def shutdown(self):
        """Signal graceful shutdown."""
        logger.info("Shutdown requested")
        self._shutdown.set()


def main():
    pipeline = Pipeline()

    def handle_signal(sig, frame):
        pipeline.shutdown()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        asyncio.run(pipeline.start())
    except KeyboardInterrupt:
        pipeline.shutdown()
    finally:
        logger.info("Final metrics: %s", json.dumps(pipeline.metrics.summary()))


if __name__ == "__main__":
    main()
