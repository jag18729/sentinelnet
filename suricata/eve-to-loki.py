#!/usr/bin/env python3
"""
Suricata EVE JSON → Loki shipper for RV2 (RISC-V).

Tails /var/log/suricata/eve.json and pushes entries to Loki via the HTTP
push API. Lightweight alternative to Vector/Promtail for platforms without
pre-built binaries (RISC-V).

Designed from need: no binary dependencies, just Python stdlib + requests.
"""

import json
import time
import os
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone

import requests

LOKI_URL = os.getenv("LOKI_URL", "http://100.77.26.41:3100/loki/api/v1/push")
EVE_PATH = os.getenv("EVE_PATH", "/var/log/suricata/eve.json")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
FLUSH_INTERVAL = float(os.getenv("FLUSH_INTERVAL", "5"))
LABELS = {
    "job": "suricata",
    "host": "rv2",
    "source": "eve.json",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("eve-to-loki")


def push_to_loki(entries: list[tuple[str, str]]) -> bool:
    """Push a batch of (timestamp_ns, line) entries to Loki."""
    if not entries:
        return True

    payload = {
        "streams": [
            {
                "stream": LABELS,
                "values": entries,
            }
        ]
    }

    try:
        resp = requests.post(
            LOKI_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 204:
            return True
        log.warning("Loki returned %d: %s", resp.status_code, resp.text[:200])
        return False
    except requests.RequestException as e:
        log.error("Loki push failed: %s", e)
        return False


def parse_eve_timestamp(line: str) -> str:
    """Extract timestamp from EVE JSON and convert to nanosecond epoch string."""
    try:
        obj = json.loads(line)
        ts = obj.get("timestamp", "")
        # EVE format: 2026-03-31T18:45:57.973895-0700
        dt = datetime.fromisoformat(ts)
        ns = int(dt.timestamp() * 1_000_000_000)
        return str(ns)
    except (json.JSONDecodeError, ValueError):
        # Fallback to current time
        return str(int(time.time() * 1_000_000_000))


def enrich_line(line: str) -> str:
    """Add event_type as a top-level field for easier Loki filtering."""
    try:
        obj = json.loads(line)
        # Keep the raw JSON but ensure event_type is visible
        return line.strip()
    except json.JSONDecodeError:
        return line.strip()


def tail_and_ship(path: str):
    """Tail EVE JSON file and ship to Loki in batches."""
    log.info("Starting EVE → Loki shipper: %s → %s", path, LOKI_URL)

    # Start at end of file
    f = open(path, "r")
    f.seek(0, 2)
    log.info("Tailing from end of file (size=%d bytes)", f.tell())

    batch: list[tuple[str, str]] = []
    last_flush = time.time()
    total_shipped = 0
    total_errors = 0

    while True:
        line = f.readline()

        if line:
            line = line.strip()
            if line:
                ts = parse_eve_timestamp(line)
                batch.append((ts, enrich_line(line)))

        # Flush on batch size or time interval
        should_flush = (
            len(batch) >= BATCH_SIZE
            or (batch and time.time() - last_flush >= FLUSH_INTERVAL)
        )

        if should_flush:
            if push_to_loki(batch):
                total_shipped += len(batch)
                if total_shipped % 500 == 0:
                    log.info("Shipped %d entries to Loki (%d errors)", total_shipped, total_errors)
            else:
                total_errors += len(batch)
            batch.clear()
            last_flush = time.time()

        if not line:
            # No new data, brief sleep
            time.sleep(0.5)

            # Handle file rotation (logrotate)
            try:
                current_inode = os.stat(path).st_ino
                open_inode = os.fstat(f.fileno()).st_ino
                if current_inode != open_inode:
                    log.info("File rotated, reopening %s", path)
                    f.close()
                    f = open(path, "r")
            except OSError:
                pass


if __name__ == "__main__":
    eve_path = sys.argv[1] if len(sys.argv) > 1 else EVE_PATH

    if not Path(eve_path).exists():
        log.error("EVE file not found: %s", eve_path)
        sys.exit(1)

    # Test Loki connectivity
    try:
        resp = requests.get(LOKI_URL.replace("/loki/api/v1/push", "/ready"), timeout=5)
        log.info("Loki ready: %s", resp.status_code == 200)
    except requests.RequestException:
        log.warning("Loki not reachable at %s, will retry on push", LOKI_URL)

    tail_and_ship(eve_path)
