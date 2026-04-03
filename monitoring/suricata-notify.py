#!/usr/bin/env python3
"""Suricata Alert Notifier -- sends actionable alerts to Telegram via Bot API.

Runs on Pi2 via cron. Reads EVE log, filters out known-good and stream noise,
deduplicates against state file, sends new actionable alerts directly to Telegram.

Usage:
    suricata-notify              # Check and notify (default: last 10 min)
    suricata-notify --minutes 30 # Custom lookback window
    suricata-notify --dry-run    # Show what would be sent without sending
    suricata-notify --test       # Send a test notification
"""

import json
import sys
import argparse
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from collections import Counter, defaultdict

EVE_LOG = "/var/log/suricata/eve.json"
STATE_FILE = "/home/rafaeljg/.suricata-notify-state.json"
LOG_FILE = "/home/rafaeljg/.suricata-notify.log"

# Telegram Bot API (Frank bot, same as OpenClaw)
BOT_TOKEN = "8497660464:AAHSBUxOvbCh-_FlNwIHL_jP1SYNbW7jLUc"
CHAT_ID = "8301256055"

# Suppressed SIDs (known infrastructure traffic)
SUPPRESS_SIDS = {
    2016149, 2016150,  # Tailscale STUN
    2033966, 2033967,  # Telegram bot
    2047122,           # Cloudflare tunnel
}

# Stream analysis SIDs (noise)
STREAM_SIDS = {
    2210020, 2210029, 2210044, 2210045, 2210063,  # STREAM analysis
    2200011, 2200022,  # IP version mismatches
    2260003,           # Applayer skip
}

SEVERITY_EMOJI = {1: "\u26a0\ufe0f", 2: "\u26a1", 3: "\u2139\ufe0f"}


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{ts} {msg}\n")
    except OSError:
        pass


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_run": None, "sent_keys": []}


def save_state(state):
    state["sent_keys"] = state["sent_keys"][-500:]
    state["last_run"] = datetime.now().isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_alerts(minutes=10):
    cutoff = datetime.now().astimezone() - timedelta(minutes=minutes)
    alerts = []
    try:
        with open(EVE_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                    if e.get("event_type") != "alert":
                        continue
                    ts = datetime.fromisoformat(e["timestamp"])
                    if ts < cutoff:
                        continue
                    sid = e["alert"]["signature_id"]
                    if sid in SUPPRESS_SIDS or sid in STREAM_SIDS:
                        continue
                    alerts.append(e)
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except FileNotFoundError:
        log("EVE log not found")
    return alerts


def classify(alert):
    sev = alert["alert"]["severity"]
    sig = alert["alert"]["signature"]
    if sev == 1:
        return "CRITICAL"
    if sev == 2:
        return "WARNING"
    if "HUNTING" in sig:
        return "HUNTING"
    return "INFO"


def make_key(alert):
    return f"{alert['alert']['signature_id']}:{alert.get('src_ip', '')}:{alert.get('dest_ip', '')}"


def build_message(alerts):
    by_class = defaultdict(list)
    for a in alerts:
        by_class[classify(a)].append(a)

    lines = []
    lines.append("\U0001f6a8 <b>IDS Alert \u2014 Pi2 (eth2)</b>")
    lines.append(f"{len(alerts)} new alert(s) detected\n")

    for cls in ["CRITICAL", "WARNING", "HUNTING", "INFO"]:
        group = by_class.get(cls, [])
        if not group:
            continue
        sigs = Counter(a["alert"]["signature"] for a in group)
        lines.append(f"<b>[{cls}]</b> ({len(group)} alerts)")
        for sig, count in sigs.most_common(5):
            sample = next(a for a in group if a["alert"]["signature"] == sig)
            src = sample.get("src_ip", "?")
            dst = sample.get("dest_ip", "?")
            sid = sample["alert"]["signature_id"]
            sev = sample["alert"]["severity"]
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"  {emoji} <code>SID:{sid}</code> sev={sev} ({count}x)")
            lines.append(f"  {sig}")
            lines.append(f"  <code>{src} \u2192 {dst}</code>")
            lines.append("")

    lines.append("<code>sudo suricata-review --hours 1</code>")
    return "\n".join(lines)


def send_telegram(message, dry_run=False):
    if dry_run:
        print(f"[DRY RUN] Would send:\n{message}")
        return True

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                log(f"Telegram sent ({len(message)} chars)")
                return True
            log(f"Telegram API error: {result}")
            return False
    except Exception as e:
        log(f"Telegram send error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Suricata Alert Notifier")
    parser.add_argument("--minutes", type=int, default=10,
                        help="Lookback window in minutes (default: 10)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be sent without sending")
    parser.add_argument("--test", action="store_true",
                        help="Send a test notification")
    args = parser.parse_args()

    if args.test:
        msg = (
            "\U0001f6a8 <b>IDS Notification Test</b>\n\n"
            "Test alert from Pi2 Suricata notifier.\n"
            f"<code>{datetime.now().isoformat()}</code>"
        )
        success = send_telegram(msg, dry_run=args.dry_run)
        sys.exit(0 if success else 1)

    state = load_state()
    sent_keys = set(state.get("sent_keys", []))

    alerts = load_alerts(minutes=args.minutes)
    if not alerts:
        log(f"No actionable alerts in last {args.minutes}m")
        save_state(state)
        return

    new_alerts = []
    new_keys = []
    for a in alerts:
        key = make_key(a)
        if key not in sent_keys:
            new_alerts.append(a)
            new_keys.append(key)

    if not new_alerts:
        log(f"All {len(alerts)} alerts already notified")
        save_state(state)
        return

    message = build_message(new_alerts)
    success = send_telegram(message, dry_run=args.dry_run)

    if success and not args.dry_run:
        state["sent_keys"] = list(sent_keys | set(new_keys))
        save_state(state)
        log(f"Notified {len(new_alerts)} new alerts ({len(new_keys)} unique keys)")
    elif args.dry_run:
        print(f"\n[DRY RUN] {len(new_alerts)} new alerts, {len(new_keys)} unique keys")


if __name__ == "__main__":
    main()
