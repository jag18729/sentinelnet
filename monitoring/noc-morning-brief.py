#!/usr/bin/env python3
"""NOC Morning Brief -- Night shift handoff to day shift.

Runs daily at 07:05 via Pi2 cron. Sends a themed shift handoff report
to Rafael's Telegram DM via Frank bot.

Usage:
    noc-morning-brief           # Run and send brief
    noc-morning-brief --dry-run # Print without sending
"""

import json
import urllib.request
import subprocess
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

BOT_TOKEN = "8497660464:AAHSBUxOvbCh-_FlNwIHL_jP1SYNbW7jLUc"
CHAT_ID = "8301256055"
EVE_LOG = "/var/log/suricata/eve.json"
NOTIFY_LOG = "/home/rafaeljg/.suricata-notify.log"
BRIEF_LOG = "/home/rafaeljg/.noc-morning-brief.log"

# SIDs to ignore in overnight alert summary
SUPPRESS_SIDS = {
    2016149, 2016150, 2033966, 2033967, 2047122,
    2210020, 2210029, 2210044, 2210045, 2210063,
    2200011, 2200022, 2260003,
}


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(BRIEF_LOG, "a") as f:
            f.write(f"{ts} {msg}\n")
    except OSError:
        pass


def send(msg, dry_run=False):
    if dry_run:
        print(msg)
        print("---")
        return True
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode()
    req = urllib.request.Request(url, data=payload,
                                headers={"Content-Type": "application/json"},
                                method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())["ok"]
    except Exception as e:
        log(f"Send failed: {e}")
        return False


def run(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else f"FAIL"
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception:
        return "ERROR"


def get_overnight_alerts():
    """Count actionable alerts from the overnight window (11pm-7am)."""
    now = datetime.now().astimezone()
    cutoff = now - timedelta(hours=8)
    total = 0
    actionable = 0
    sigs = {}
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
                    total += 1
                    sid = e["alert"]["signature_id"]
                    if sid not in SUPPRESS_SIDS:
                        actionable += 1
                        sig = e["alert"]["signature"]
                        sev = e["alert"]["severity"]
                        if sig not in sigs:
                            sigs[sig] = {"count": 0, "sev": sev, "sid": sid}
                        sigs[sig]["count"] += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    return total, actionable, sigs


def get_notify_log_overnight():
    """Check if any Telegram alerts were sent overnight."""
    sent = 0
    try:
        cutoff = datetime.now() - timedelta(hours=8)
        with open(NOTIFY_LOG) as f:
            for line in f:
                try:
                    ts_str = line[:19]
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff and "Telegram sent" in line:
                        sent += 1
                except (ValueError, IndexError):
                    continue
    except FileNotFoundError:
        pass
    return sent


def build_brief(dry_run=False):
    now = datetime.now()
    dow = now.strftime("%A")
    date_str = now.strftime("%B %d, %Y")
    time_str = now.strftime("%H:%M %Z")

    # Header
    send(f"""\u2615 <b>NOC Morning Brief</b>
<i>{dow}, {date_str}</i>

<code>Shift Handoff: Night \u2192 Day
Prepared:      {time_str}
Duty Officer:  Frank (automated)
Classification: UNCLASSIFIED</code>

Good morning. Here is your overnight status report.""", dry_run)

    import time
    time.sleep(1)

    # ---- Section 1: Infrastructure Status ----
    uptime = run("uptime -p")
    loadavg = run("cat /proc/loadavg | cut -d' ' -f1-3")
    mem_used = run("free -h | awk '/^Mem:/{print $3}'")
    mem_total = run("free -h | awk '/^Mem:/{print $2}'")
    swap = run("free -h | awk '/^Swap:/{print $3}'")
    disk_pct = run("df -h / | awk 'NR==2{print $5}'")
    disk_avail = run("df -h / | awk 'NR==2{print $4}'")
    k3s = run("sudo kubectl get nodes --no-headers 2>/dev/null | awk '{print $2}'")
    pods_run = run("sudo kubectl get pods -A --no-headers 2>/dev/null | grep -c Running")
    pods_bad = run("sudo kubectl get pods -A --no-headers 2>/dev/null | grep -cv Running")

    # Determine status icon
    load_f = float(loadavg.split()[0]) if loadavg and loadavg[0].isdigit() else 0
    infra_status = "GREEN" if load_f < 3.0 and k3s == "Ready" else "YELLOW" if k3s == "Ready" else "RED"
    infra_icon = {"GREEN": "\U0001f7e2", "YELLOW": "\U0001f7e1", "RED": "\U0001f534"}[infra_status]

    send(f"""{infra_icon} <b>INFRASTRUCTURE</b> [{infra_status}]

<code>Pi2 (primary compute):
  Uptime:  {uptime}
  Load:    {loadavg}
  Memory:  {mem_used}/{mem_total} (swap: {swap})
  Disk:    {disk_pct} used ({disk_avail} free)
  K3s:     {k3s} ({pods_run} pods, {pods_bad} errored)</code>""", dry_run)

    time.sleep(1)

    # ---- Section 2: Fleet Reachability ----
    checks = {
        "Pi1 Prometheus": run("curl -sf --max-time 8 http://100.77.26.41:9090/-/healthy >/dev/null && echo UP || echo DOWN"),
        "Pi1 Grafana": run("curl -sf --max-time 8 http://100.77.26.41:3000/api/health >/dev/null && echo UP || echo DOWN"),
        "Pi1 Loki": run("curl -sf --max-time 8 http://100.77.26.41:3100/ready >/dev/null && echo UP || echo DOWN"),
        "Pi0 SSH": run("ssh -o ConnectTimeout=5 -o BatchMode=yes pi0 echo UP 2>/dev/null || echo DOWN"),
        "RV2 SSH": run("ssh -o ConnectTimeout=5 -o BatchMode=yes rafaeljg@100.118.229.114 echo UP 2>/dev/null || echo DOWN"),
    }
    up_count = sum(1 for v in checks.values() if v == "UP")
    total_count = len(checks)
    fleet_status = "GREEN" if up_count == total_count else "YELLOW" if up_count >= 3 else "RED"
    fleet_icon = {"GREEN": "\U0001f7e2", "YELLOW": "\U0001f7e1", "RED": "\U0001f534"}[fleet_status]

    check_lines = []
    for name, status in checks.items():
        icon = "\u2705" if status == "UP" else "\u274c"
        check_lines.append(f"  {icon} {name}")

    send(f"""{fleet_icon} <b>FLEET STATUS</b> [{fleet_status}] ({up_count}/{total_count})

<code>{"chr(10)".join(check_lines)}</code>""", dry_run)

    time.sleep(1)

    # ---- Section 3: Security / IDS ----
    suri_pi2 = run("systemctl is-active suricata")
    suri_rv2 = run("ssh -o ConnectTimeout=5 rafaeljg@100.118.229.114 systemctl is-active suricata 2>/dev/null || echo DOWN")
    feeder = run("ssh -o ConnectTimeout=5 rafaeljg@100.118.229.114 systemctl is-active sentinelnet-feeder 2>/dev/null || echo DOWN")
    eve_loki = run("ssh -o ConnectTimeout=5 rafaeljg@100.118.229.114 systemctl is-active eve-to-loki 2>/dev/null || echo DOWN")
    wazuh = run("sudo docker ps --filter name=wazuh --format '{{.Status}}' 2>/dev/null | head -1")
    f2b = run("systemctl is-active fail2ban")

    total_alerts, actionable, top_sigs = get_overnight_alerts()
    notifs_sent = get_notify_log_overnight()

    sec_status = "GREEN" if actionable == 0 else "YELLOW" if actionable < 10 else "RED"
    sec_icon = {"GREEN": "\U0001f7e2", "YELLOW": "\U0001f7e1", "RED": "\U0001f534"}[sec_status]

    sig_lines = ""
    if top_sigs:
        sorted_sigs = sorted(top_sigs.items(), key=lambda x: x[1]["count"], reverse=True)[:5]
        for sig, info in sorted_sigs:
            sig_lines += f"\n    sev={info['sev']} SID:{info['sid']} ({info['count']}x) {sig[:45]}"

    overnight_block = f"""Overnight IDS (last 8h):
  Total events:  {total_alerts:,}
  Actionable:    {actionable}
  Notifs sent:   {notifs_sent}"""

    if sig_lines:
        overnight_block += f"\n  Top signatures:{sig_lines}"

    send(f"""{sec_icon} <b>SECURITY</b> [{sec_status}]

<code>IDS Sensors:
  Pi2 Suricata:  {suri_pi2} (eth2, 91K rules)
  RV2 Suricata:  {suri_rv2} (end0, 75K rules)
  RV2 Feeder:    {feeder} (SPAN mirror)
  EVE-to-Loki:   {eve_loki}

HIDS:
  Wazuh:         {wazuh}
  fail2ban:      {f2b}

{overnight_block}</code>""", dry_run)

    time.sleep(1)

    # ---- Section 4: Services + Crons ----
    sentinel = run("curl -sf --max-time 5 http://localhost:30800/metrics >/dev/null && echo UP || echo DOWN")
    cloudflared = run("systemctl is-active cloudflared")
    openclaw = run("systemctl --user is-active openclaw-gateway")
    vector = run("systemctl is-active vector")
    runners = run("systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -c actions.runner")

    try:
        cron_raw = run("openclaw cron list --json 2>/dev/null", timeout=15)
        crons = json.loads(cron_raw)
        cron_ok = sum(1 for j in crons.get("jobs", [])
                      if j.get("state", {}).get("lastStatus") == "ok")
        cron_total = len(crons.get("jobs", []))
        cron_fail = cron_total - cron_ok
    except Exception:
        cron_ok = cron_total = cron_fail = "?"

    svc_status = "GREEN" if sentinel == "UP" and openclaw == "active" else "YELLOW"
    svc_icon = {"GREEN": "\U0001f7e2", "YELLOW": "\U0001f7e1", "RED": "\U0001f534"}[svc_status]

    send(f"""{svc_icon} <b>SERVICES</b> [{svc_status}]

<code>SentinelNet API: {sentinel} (:30800)
Cloudflared:     {cloudflared}
OpenClaw GW:     {openclaw}
Vector:          {vector}
GH Runners:      {runners} active
Frank Crons:     {cron_ok}/{cron_total} healthy</code>""", dry_run)

    time.sleep(1)

    # ---- Section 5: Handoff Notes ----
    issues = []
    if k3s != "Ready":
        issues.append("K3s node not Ready")
    if int(pods_bad) > 3 if pods_bad.isdigit() else False:
        issues.append(f"{pods_bad} pods in error state")
    for name, status in checks.items():
        if status != "UP":
            issues.append(f"{name} unreachable")
    if suri_pi2 != "active":
        issues.append("Pi2 Suricata down")
    if suri_rv2 != "active":
        issues.append("RV2 Suricata down")
    if actionable > 0:
        issues.append(f"{actionable} actionable IDS alerts overnight")
    if str(cron_fail).isdigit() and int(str(cron_fail)) > 0:
        issues.append(f"{cron_fail} Frank cron(s) failing")

    if issues:
        issue_lines = "\n".join(f"  \u26a0\ufe0f {i}" for i in issues)
        handoff = f"<b>Action items:</b>\n{issue_lines}"
    else:
        handoff = "No issues. All systems nominal overnight."

    send(f"""\U0001f4cb <b>SHIFT HANDOFF NOTES</b>

{handoff}

<i>End of brief. Have a good shift.</i>
<code>-- Frank, Night Duty Officer</code>""", dry_run)


def main():
    parser = argparse.ArgumentParser(description="NOC Morning Brief")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    log("Starting morning brief")
    build_brief(dry_run=args.dry_run)
    log("Morning brief complete")


if __name__ == "__main__":
    main()
