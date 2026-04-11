#!/usr/bin/env python3
"""Fleet triage filter: pulls new Wazuh alerts, classifies via lesson cache
or RV2, and queues them.

Runs on Pi2 as a systemd timer. Reads alerts from the wazuh-manager Docker
container, tracks progress in /var/lib/fleet-triage/state.json, appends
classified entries to /var/lib/fleet-triage/queue.jsonl. Lesson cache hits
return in milliseconds; cache misses fall through to RV2 (~50s/alert).

Shared state and lesson logic live in fleet_triage_common.
"""
import json
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, "/usr/local/lib")
import fleet_triage_common as ftc

WAZUH_CONTAINER = "wazuh-manager"
WAZUH_ALERT_PATH = "/var/ossec/logs/alerts/alerts.json"
RV2_URL = "http://100.118.229.114:8090"
RV2_TIMEOUT = 90
MAX_ALERTS_PER_RUN = 10
TAIL_WINDOW = 500

SEV_RE = re.compile(r"(?im)^\s*SEVERITY\s*:\s*(.+?)(?:\n|$|\|)")
ACT_RE = re.compile(r"(?im)^\s*ACTION\s*:\s*(.+?)(?:\n|$|\|)")


def log(msg):
    print(f"[filter] {msg}", file=sys.stderr, flush=True)


def pull_recent_alerts():
    try:
        out = subprocess.check_output(
            ["docker", "exec", WAZUH_CONTAINER, "tail", f"-{TAIL_WINDOW}", WAZUH_ALERT_PATH],
            text=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as e:
        log(f"wazuh tail failed: {e}")
        return []
    except subprocess.TimeoutExpired:
        log("wazuh tail timed out")
        return []
    alerts = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts


def rv2_health():
    try:
        with urllib.request.urlopen(f"{RV2_URL}/health", timeout=5) as r:
            return json.loads(r.read()).get("status") == "ok"
    except Exception:
        return False


def rv2_triage_raw(compact):
    body = json.dumps({"alert_json": json.dumps(compact)}).encode()
    req = urllib.request.Request(
        f"{RV2_URL}/triage_alert",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=RV2_TIMEOUT) as r:
        return json.loads(r.read())


def parse_rv2_raw(raw):
    sev_token = None
    act_token = None
    if raw:
        sev_m = SEV_RE.search(raw)
        if sev_m:
            sev_token = ftc.normalize_severity(sev_m.group(1))
        act_m = ACT_RE.search(raw)
        if act_m:
            act_token = ftc.normalize_action(act_m.group(1))
    return sev_token, act_token


def level_fallback(compact, reason_suffix=""):
    lvl = compact.get("level") or 0
    severity = ftc.LEVEL_TO_SEVERITY.get(lvl, "low")
    if lvl >= 9:
        action = "escalate"
    elif lvl >= 7:
        action = "investigate"
    elif lvl >= 4:
        action = "log"
    else:
        action = "ignore"
    return {
        "severity": severity,
        "action": action,
        "reason": f"Classified from rule.level={lvl}{reason_suffix}.",
        "fallback": True,
    }


def classify(compact, lessons, rv2_up):
    """Returns (triage_dict, lesson_hit_or_none)."""
    # 1. lesson cache (only authoritative entries)
    match = ftc.match_lesson(compact, lessons)
    if match:
        return (
            {
                "severity": match["classification"]["severity"],
                "action": match["classification"]["action"],
                "reason": f"lesson cache hit ({match['lesson_id'][:8]})",
                "classifier": "lesson-cache",
                "lesson_id": match["lesson_id"],
            },
            match,
        )

    # 2. RV2 health gate
    if not rv2_up:
        result = level_fallback(compact, " (RV2 unhealthy)")
        result["classifier"] = "fallback-health"
        return (result, None)

    # 3. RV2 inference
    try:
        t0 = time.time()
        resp = rv2_triage_raw(compact)
        classify_ms = int((time.time() - t0) * 1000)
    except Exception as e:
        result = level_fallback(compact, f" (RV2 error: {e})")
        result["classifier"] = "fallback-error"
        return (result, None)

    raw = resp.get("raw") or ""
    sev, act = parse_rv2_raw(raw)

    if sev and act:
        return (
            {
                "severity": sev,
                "action": act,
                "reason": f"rv2 classification (inference {resp.get('inference_ms')}ms)",
                "raw": raw[:200],
                "classify_ms": classify_ms,
                "classifier": "rv2",
            },
            None,
        )

    result = level_fallback(compact, f" (RV2 output unparseable: {raw[:80]!r})")
    result["classify_ms"] = classify_ms
    result["classifier"] = "fallback-parse"
    return (result, None)


def main():
    state = ftc.load_state()
    last_id = state.get("last_alert_id")
    log(f"starting, last_alert_id={last_id}")

    lessons = ftc.load_lessons()
    auth_count = sum(1 for l in lessons if l.get("status") == "authoritative")
    log(f"loaded {len(lessons)} lessons ({auth_count} authoritative)")

    alerts = pull_recent_alerts()
    if not alerts:
        log("no alerts read from wazuh")
        return 0

    if last_id is None:
        new = alerts[-MAX_ALERTS_PER_RUN:]
        log(f"first run: taking last {len(new)} alerts as baseline")
    else:
        new = [a for a in alerts if a.get("id", "") > last_id]
        log(f"found {len(new)} new alerts since {last_id}")
        if len(new) > MAX_ALERTS_PER_RUN:
            log(f"capping to {MAX_ALERTS_PER_RUN}/run, {len(new) - MAX_ALERTS_PER_RUN} carry over")
            new = new[:MAX_ALERTS_PER_RUN]

    if not new:
        return 0

    rv2_up = rv2_health()
    if not rv2_up:
        log("RV2 health check failed, will use level-based fallback for cache misses")

    lessons_dirty = False
    cache_hits = 0
    with open(ftc.QUEUE_FILE, "a") as qf:
        for a in new:
            compact = ftc.extract_compact_alert(a)
            alert_id = a.get("id")
            result, hit_lesson = classify(compact, lessons, rv2_up)
            if hit_lesson is not None:
                hit_lesson["hits"] = hit_lesson.get("hits", 0) + 1
                hit_lesson["last_seen_at"] = ftc.utcnow_iso()
                lessons_dirty = True
                cache_hits += 1
            entry = {
                "alert_id": alert_id,
                "alert": compact,
                "triage": result,
                "queued_at": ftc.utcnow_iso(),
            }
            qf.write(json.dumps(entry) + "\n")
            qf.flush()
            log(f"queued {alert_id} sev={result.get('severity')} act={result.get('action')} via={result.get('classifier')}")

    if lessons_dirty:
        try:
            ftc.save_lessons(lessons)
        except Exception as e:
            log(f"WARNING: failed to persist lesson hits: {e}")

    new_last = max((a.get("id", "") for a in new), default=last_id)
    state["last_alert_id"] = new_last
    ftc.save_state(state)
    log(f"done, last_alert_id={new_last}, queued {len(new)} alerts ({cache_hits} cache hits)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"fatal: {e}")
        sys.exit(1)
