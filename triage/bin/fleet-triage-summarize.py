#!/usr/bin/env python3
"""Fleet triage summarizer: reads classified queue, calls XPS Ollama for
narrative summary, then runs a self-supervised teacher pass that asks Gemma 4
to verify each alert's classification and writes disagreements as pending
lessons.

Runs on Pi2 as a systemd timer. The narrative phase advances state.last_summary_ts
on success. The teacher phase is best-effort and never blocks the narrative.
"""
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, "/usr/local/lib")
import fleet_triage_common as ftc

XPS_URL = "http://100.73.127.58:11434"
XPS_TIMEOUT = 300
MODEL = "gemma4:e4b"
MIN_ENTRIES_FOR_SUMMARY = 1


def log(msg):
    print(f"[summarize] {msg}", file=sys.stderr, flush=True)


def filter_relevant(entries, since_ts):
    relevant = []
    for e in entries:
        if since_ts and e.get("queued_at", "") <= since_ts:
            continue
        triage = e.get("triage", {})
        sev = (triage.get("severity") or "").lower()
        act = (triage.get("action") or "").lower()
        if sev in {"critical", "high", "medium"} or act in {"escalate", "investigate"}:
            relevant.append(e)
    return relevant


def xps_health():
    try:
        with urllib.request.urlopen(f"{XPS_URL}/api/version", timeout=5) as r:
            return bool(json.loads(r.read()).get("version"))
    except Exception:
        return False


def build_prompt(entries):
    lines = []
    for e in entries:
        a = e.get("alert", {})
        t = e.get("triage", {})
        lines.append(json.dumps({
            "ts": a.get("ts"),
            "agent": a.get("agent"),
            "level": a.get("level"),
            "desc": a.get("description"),
            "severity": t.get("severity"),
            "action": t.get("action"),
            "log": a.get("full_log"),
        }, separators=(",", ":")))
    alert_block = "\n".join(lines)

    return f"""You are a security analyst producing an operational triage digest for a home lab fleet (raspberry pis, a workstation, a RISC-V board, a firewall). The alerts below have already been pre-classified by a smaller model; your job is to produce a human-readable operator report.

Alerts (JSON per line, already filtered to actionable severity):

{alert_block}

Produce a markdown report with these sections:

## Overview
One paragraph. What happened, on which hosts, in what timeframe.

## Key Patterns
Bullet list of notable clusters, repeated source IPs, suspicious sequences.

## Priorities for Operator
Numbered list of the top 3 things to actually look at. Be specific about host and action.

## False Positive Risk
One sentence per alert type that could plausibly be a false positive, with why.

Keep the whole report under 400 words. Do not repeat raw alert data verbatim."""


def call_xps(prompt, format_json=False):
    options = {"num_ctx": 8192, "temperature": 0.2}
    body_obj = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": options,
    }
    if format_json:
        body_obj["format"] = "json"
    body = json.dumps(body_obj).encode()
    req = urllib.request.Request(
        f"{XPS_URL}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=XPS_TIMEOUT) as r:
        return json.loads(r.read())


def write_summary(entries, response, elapsed):
    now = datetime.now(timezone.utc)
    fname = now.strftime("%Y-%m-%d-%H-%M.md")
    path = ftc.SUMMARY_DIR / fname
    sev_counts = {}
    for e in entries:
        sev = e.get("triage", {}).get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    header = [
        f"# Fleet triage summary - {now.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"- Alerts analyzed: **{len(entries)}**",
        f"- Severity breakdown: {', '.join(f'{k}={v}' for k, v in sorted(sev_counts.items()))}",
        f"- Model: `{MODEL}` on XPS (100.73.127.58)",
        f"- Generation time: {elapsed:.1f}s ({response.get('eval_count', 0)} output tokens)",
        "",
        "---",
        "",
    ]
    body = response.get("response", "").strip()

    audit = ["", "---", "", "## Raw alert index (for audit)", ""]
    for e in entries:
        a = e.get("alert", {})
        t = e.get("triage", {})
        audit.append(
            f"- `{e.get('alert_id')}` [{t.get('severity')}/{t.get('action')}] "
            f"{a.get('agent')} lvl{a.get('level')}: {a.get('description')}"
        )

    path.write_text("\n".join(header) + body + "\n" + "\n".join(audit) + "\n")
    return path


def build_teacher_prompt(entries):
    """Ask Gemma 4 to independently classify each alert and extract keywords."""
    items = []
    for e in entries:
        a = e.get("alert", {})
        t = e.get("triage", {})
        items.append({
            "alert_id": e.get("alert_id"),
            "rule_id": a.get("rule_id"),
            "agent": a.get("agent"),
            "level": a.get("level"),
            "description": a.get("description"),
            "full_log": a.get("full_log"),
            "rv2_severity": t.get("severity"),
            "rv2_action": t.get("action"),
        })
    block = json.dumps(items, separators=(",", ":"))

    return f"""You are reviewing a small model's classifications of security alerts to produce training examples for a feedback loop.

For each alert, return one JSON object with these exact fields:
- alert_id: copy from input
- correct_severity: one of "critical", "high", "medium", "low", "noise"
- correct_action: one of "escalate", "investigate", "log", "ignore"
- log_keywords: array of 2 to 3 short lowercase phrases drawn from the alert's full_log that uniquely identify this kind of alert
- reason: one short sentence

Severity definitions:
- critical: confirmed compromise or active exploit
- high: strong indicator requiring human investigation
- medium: anomaly worth a look during business hours
- low: routine event, log only
- noise: false positive, no action

Action definitions:
- escalate: page someone now
- investigate: review during business hours
- log: keep for trend analysis
- ignore: suppress

Return ONLY a JSON object with key "verifications" whose value is the array. No prose. No markdown.

Alerts:
{block}"""


def parse_teacher_response(response_text):
    """Parse Gemma's JSON-mode response. Returns a list of verification dicts
    or None on failure."""
    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        for key in ("verifications", "results", "items", "alerts"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return None
    if isinstance(data, list):
        return data
    return None


def run_teacher_pass(entries):
    """Best-effort: ask Gemma to verify RV2's classifications, ingest
    disagreements as pending lessons, promote any that hit threshold."""
    if not entries:
        log("teacher: no entries to review")
        return

    prompt = build_teacher_prompt(entries)
    log(f"teacher: prompt size {len(prompt)} chars, {len(entries)} alerts")

    try:
        t0 = time.time()
        resp = call_xps(prompt, format_json=True)
        teacher_elapsed = time.time() - t0
    except Exception as e:
        log(f"teacher: XPS call failed: {e}; skipping teacher pass")
        return

    raw_text = resp.get("response", "")
    verifications = parse_teacher_response(raw_text)
    if verifications is None:
        log(f"teacher: could not parse JSON response (head: {raw_text[:120]!r}); skipping")
        return

    log(f"teacher: parsed {len(verifications)} verifications in {teacher_elapsed:.1f}s")

    # Index entries by alert_id for lookup
    by_id = {e.get("alert_id"): e for e in entries}

    lessons = ftc.load_lessons()
    disagreements = 0
    for v in verifications:
        aid = v.get("alert_id")
        entry = by_id.get(aid)
        if entry is None:
            continue
        rv2_sev = (entry.get("triage", {}).get("severity") or "").lower()
        rv2_act = (entry.get("triage", {}).get("action") or "").lower()

        gemma_sev = ftc.normalize_severity(v.get("correct_severity"))
        gemma_act = ftc.normalize_action(v.get("correct_action"))
        if not gemma_sev or not gemma_act:
            continue

        if gemma_sev == rv2_sev and gemma_act == rv2_act:
            continue  # agreement, nothing to learn

        # Build the lesson pattern from the entry's compact alert
        alert = entry.get("alert", {})
        keywords = v.get("log_keywords") or []
        if not isinstance(keywords, list):
            keywords = []
        keywords = [str(k).lower().strip() for k in keywords if k]
        if not keywords:
            continue  # need keywords to match later

        pattern = {
            "rule_id": alert.get("rule_id"),
            "agent": alert.get("agent"),
            "log_keywords": keywords[:3],
        }
        classification = {
            "severity": gemma_sev,
            "action": gemma_act,
        }
        ftc.ingest_lesson(
            lessons,
            pattern,
            classification,
            source="gemma-teacher",
            reason=v.get("reason") or "",
        )
        disagreements += 1

    promoted = ftc.promote_eligible(lessons)
    try:
        ftc.save_lessons(lessons)
    except Exception as e:
        log(f"teacher: failed to save lessons: {e}")
        return

    log(f"teacher: {len(verifications)} reviewed, {disagreements} disagreements, {promoted} promoted")


def main():
    state = ftc.load_state()
    last_summary_ts = state.get("last_summary_ts")
    log(f"starting, last_summary_ts={last_summary_ts}")

    entries = ftc.read_queue_entries()
    relevant = filter_relevant(entries, last_summary_ts)
    log(f"queue={len(entries)} relevant={len(relevant)}")

    if len(relevant) < MIN_ENTRIES_FOR_SUMMARY:
        log("nothing to summarize")
        return 0

    if not xps_health():
        log("XPS health check failed; skipping this run (state not advanced)")
        return 0

    prompt = build_prompt(relevant)
    log(f"narrative prompt size: {len(prompt)} chars")

    try:
        t0 = time.time()
        response = call_xps(prompt)
        elapsed = time.time() - t0
    except Exception as e:
        log(f"XPS call failed: {e}; state not advanced")
        return 0

    path = write_summary(relevant, response, elapsed)
    log(f"wrote {path} ({elapsed:.1f}s)")

    new_ts = max((e.get("queued_at", "") for e in relevant), default=last_summary_ts)
    state["last_summary_ts"] = new_ts
    ftc.save_state(state)
    log(f"narrative done, last_summary_ts={new_ts}")

    # Best-effort teacher pass
    try:
        run_teacher_pass(relevant)
    except Exception as e:
        log(f"teacher: unexpected error (non-fatal): {e}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"fatal: {e}")
        sys.exit(1)
