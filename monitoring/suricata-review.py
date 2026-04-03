#!/usr/bin/env python3
"""Suricata Alert Review & Classification Tool for Pi2.

Usage:
    suricata-review              # Show today's unsuppressed alerts
    suricata-review --all        # Show all alerts (including suppressed SIDs)
    suricata-review --hours 4    # Last N hours
    suricata-review --severity 1 # Filter by severity (1=high, 2=med, 3=low)
    suricata-review --top 20     # Top N signatures
    suricata-review --detail     # Show full alert details
    suricata-review --export     # Export actionable alerts as JSON
"""

import json
import sys
import argparse
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
from pathlib import Path

EVE_LOG = "/var/log/suricata/eve.json"

# Known-good SIDs (suppressed in threshold.config, kept here for --all mode labeling)
KNOWN_GOOD = {
    2016149: "Tailscale STUN Request",
    2016150: "Tailscale STUN Response",
    2033966: "Telegram DNS (OpenClaw bot)",
    2033967: "Telegram TLS (OpenClaw bot)",
    2047122: "Cloudflare Tunnel DNS (cloudflared)",
}

SEVERITY_LABELS = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
SEVERITY_COLORS = {1: "\033[91m", 2: "\033[93m", 3: "\033[90m"}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"


def load_alerts(eve_path, hours=None, since=None):
    alerts = []
    cutoff = None
    if hours:
        cutoff = datetime.now().astimezone() - timedelta(hours=hours)
    elif since:
        cutoff = since

    with open(eve_path) as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("event_type") != "alert":
                    continue
                if cutoff:
                    ts = datetime.fromisoformat(e["timestamp"])
                    if ts < cutoff:
                        continue
                alerts.append(e)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    return alerts


def classify_alert(alert):
    sid = alert["alert"]["signature_id"]
    sig = alert["alert"]["signature"]
    cat = alert["alert"].get("category", "Unknown")
    sev = alert["alert"]["severity"]

    if sid in KNOWN_GOOD:
        return "KNOWN_INFRA", KNOWN_GOOD[sid]

    if "SURICATA STREAM" in sig or "SURICATA Applayer" in sig or "SURICATA IPv" in sig:
        return "STREAM_NOISE", "TCP/protocol analysis artifact"

    if sev == 1:
        return "ACTION_REQUIRED", "High severity -- investigate immediately"
    if sev == 2:
        return "REVIEW", "Medium severity -- review when possible"
    if "HUNTING" in sig:
        return "HUNTING", "Threat hunting rule -- context-dependent"
    if "INFO" in sig:
        return "INFORMATIONAL", "Informational -- low priority"

    return "UNCLASSIFIED", "Needs manual classification"


def print_summary(alerts, show_all=False, top_n=15):
    if not alerts:
        print(f"{GREEN}No alerts found in the specified time window.{RESET}")
        return

    # Filter suppressed unless --all
    if not show_all:
        alerts = [a for a in alerts if a["alert"]["signature_id"] not in KNOWN_GOOD]

    total = len(alerts)
    by_class = defaultdict(list)
    for a in alerts:
        cls, reason = classify_alert(a)
        by_class[cls].append(a)

    # Header
    ts_first = alerts[0]["timestamp"] if alerts else "?"
    ts_last = alerts[-1]["timestamp"] if alerts else "?"
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  SURICATA ALERT REVIEW -- Pi2 (eth2){RESET}")
    print(f"  Window: {ts_first[:19]} to {ts_last[:19]}")
    print(f"  Total alerts: {total}")
    print(f"{BOLD}{'='*70}{RESET}")

    # Classification breakdown
    print(f"\n{BOLD}CLASSIFICATION{RESET}")
    order = ["ACTION_REQUIRED", "REVIEW", "HUNTING", "UNCLASSIFIED", "INFORMATIONAL", "STREAM_NOISE", "KNOWN_INFRA"]
    for cls in order:
        if cls in by_class:
            color = {"ACTION_REQUIRED": "\033[91m", "REVIEW": "\033[93m", "HUNTING": "\033[96m"}.get(cls, "\033[90m")
            print(f"  {color}{cls:20s}{RESET} {len(by_class[cls]):>6d}")

    # Top signatures
    print(f"\n{BOLD}TOP {top_n} SIGNATURES{RESET}")
    sigs = Counter()
    sig_meta = {}
    for a in alerts:
        sid = a["alert"]["signature_id"]
        sig = a["alert"]["signature"]
        sigs[sid] += 1
        if sid not in sig_meta:
            sig_meta[sid] = {
                "sig": sig,
                "sev": a["alert"]["severity"],
                "cat": a["alert"].get("category", "?"),
                "cls": classify_alert(a)[0],
            }

    for sid, count in sigs.most_common(top_n):
        m = sig_meta[sid]
        sev_color = SEVERITY_COLORS.get(m["sev"], "")
        cls_tag = f"[{m['cls']}]"
        print(f"  {sev_color}sev={m['sev']}{RESET} SID:{sid:<10d} {count:>6d}x  {m['sig'][:55]}")
        print(f"         {cls_tag} -- {m['cat']}")

    # Actionable alerts detail
    actionable = by_class.get("ACTION_REQUIRED", []) + by_class.get("REVIEW", []) + by_class.get("UNCLASSIFIED", [])
    if actionable:
        print(f"\n{BOLD}{'='*70}{RESET}")
        print(f"{BOLD}  ACTIONABLE ALERTS ({len(actionable)}){RESET}")
        print(f"{BOLD}{'='*70}{RESET}")
        seen = set()
        for a in actionable[-30:]:
            al = a["alert"]
            key = (al["signature_id"], a.get("src_ip"), a.get("dest_ip"))
            if key in seen:
                continue
            seen.add(key)
            sev_color = SEVERITY_COLORS.get(al["severity"], "")
            cls, reason = classify_alert(a)
            print(f"  {a['timestamp'][:19]}  {sev_color}[{SEVERITY_LABELS.get(al['severity'],'?')}]{RESET}  {a.get('src_ip','?')}:{a.get('src_port','?')} > {a.get('dest_ip','?')}:{a.get('dest_port','?')}")
            print(f"    SID:{al['signature_id']}  {al['signature']}")
            print(f"    {cls}: {reason}")
            print()
    else:
        print(f"\n{GREEN}No actionable alerts. All traffic classified as known-good or noise.{RESET}")


def export_actionable(alerts):
    actionable = []
    for a in alerts:
        if a["alert"]["signature_id"] in KNOWN_GOOD:
            continue
        cls, reason = classify_alert(a)
        if cls in ("ACTION_REQUIRED", "REVIEW", "UNCLASSIFIED", "HUNTING"):
            a["_classification"] = cls
            a["_reason"] = reason
            actionable.append(a)
    json.dump(actionable, sys.stdout, indent=2, default=str)
    print()


def show_detail(alerts):
    for a in alerts[-20:]:
        if a["alert"]["signature_id"] in KNOWN_GOOD:
            continue
        cls, reason = classify_alert(a)
        if cls in ("STREAM_NOISE",):
            continue
        al = a["alert"]
        print(f"{BOLD}--- {a['timestamp'][:19]} ---{RESET}")
        print(f"  Signature:  {al['signature']}")
        print(f"  SID:        {al['signature_id']}  Rev: {al.get('rev','?')}")
        print(f"  Severity:   {al['severity']} ({SEVERITY_LABELS.get(al['severity'],'?')})")
        print(f"  Category:   {al.get('category','?')}")
        print(f"  Source:     {a.get('src_ip','?')}:{a.get('src_port','?')}")
        print(f"  Dest:       {a.get('dest_ip','?')}:{a.get('dest_port','?')}")
        print(f"  Protocol:   {a.get('proto','?')}")
        print(f"  Class:      {cls} -- {reason}")
        if "flow" in a:
            print(f"  Flow:       pkts_toserver={a['flow'].get('pkts_toserver','?')} bytes={a['flow'].get('bytes_toserver','?')}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Suricata Alert Review & Classification")
    parser.add_argument("--all", action="store_true", help="Include suppressed/known-good alerts")
    parser.add_argument("--hours", type=float, help="Only show alerts from last N hours")
    parser.add_argument("--severity", type=int, choices=[1, 2, 3], help="Filter by severity")
    parser.add_argument("--top", type=int, default=15, help="Top N signatures to show")
    parser.add_argument("--detail", action="store_true", help="Show detailed alert info")
    parser.add_argument("--export", action="store_true", help="Export actionable alerts as JSON")
    parser.add_argument("--eve", default=EVE_LOG, help="Path to eve.json")
    args = parser.parse_args()

    alerts = load_alerts(args.eve, hours=args.hours)

    if args.severity:
        alerts = [a for a in alerts if a["alert"]["severity"] == args.severity]

    if args.export:
        export_actionable(alerts)
        return

    if args.detail:
        show_detail(alerts)
        return

    print_summary(alerts, show_all=args.all, top_n=args.top)


if __name__ == "__main__":
    main()
