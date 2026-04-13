#!/usr/bin/env python3
"""Check for new escalation-level alerts in the fleet triage queue.
Prints formatted alerts to stdout for OpenClaw/Telegram delivery.
Prints nothing if no new escalations (agent interprets as HEARTBEAT_OK).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, "/usr/local/lib")
import fleet_triage_common as ftc

ESCALATION_STATE = ftc.STATE_DIR / "escalation-state.json"


def load_escalation_state():
    try:
        return json.loads(ESCALATION_STATE.read_text())
    except Exception:
        return {"last_checked_at": None}


def save_escalation_state(state):
    tmp = ESCALATION_STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(ESCALATION_STATE)


def main():
    state = load_escalation_state()
    last_checked = state.get("last_checked_at")

    entries = ftc.read_queue_entries()
    escalations = []
    for e in entries:
        if last_checked and e.get("queued_at", "") <= last_checked:
            continue
        triage = e.get("triage", {})
        if triage.get("action") == "escalate" or triage.get("severity") == "critical":
            escalations.append(e)

    if not escalations:
        state["last_checked_at"] = ftc.utcnow_iso()
        save_escalation_state(state)
        return 0

    lines = ["FLEET TRIAGE ESCALATION", ""]
    for e in escalations:
        a = e.get("alert", {})
        t = e.get("triage", {})
        lines.append(
            f"[{t.get('severity', '?').upper()}] {a.get('agent', '?')} "
            f"rule {a.get('rule_id', '?')}: {a.get('description', '?')}"
        )
        log_preview = (a.get("full_log") or "")[:120]
        if log_preview:
            lines.append(f"  log: {log_preview}")
        lines.append(f"  via: {t.get('classifier', '?')} at {e.get('queued_at', '?')}")
        lines.append("")

    lines.append(f"{len(escalations)} alert(s) require attention.")
    lines.append("Run: fleet-triage-lessons list | ssh pi2 'cat /var/lib/fleet-triage/summaries/$(ls -t /var/lib/fleet-triage/summaries/ | head -1)'")

    print("\n".join(lines))

    state["last_checked_at"] = ftc.utcnow_iso()
    save_escalation_state(state)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"escalation check error: {e}", file=sys.stderr)
        sys.exit(1)
