"""Shared module for the fleet triage pipeline.

Holds state file helpers, queue parsing, alert compaction, severity/action
normalization, and the lesson store (load/save/match/ingest/promote).

Imported by both /usr/local/bin/fleet-triage-filter.py and
/usr/local/bin/fleet-triage-summarize.py via:

    import sys
    sys.path.insert(0, "/usr/local/lib")
    import fleet_triage_common as ftc
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# Paths
STATE_DIR = Path("/var/lib/fleet-triage")
STATE_FILE = STATE_DIR / "state.json"
QUEUE_FILE = STATE_DIR / "queue.jsonl"
LESSONS_FILE = STATE_DIR / "lessons.jsonl"
SUMMARY_DIR = STATE_DIR / "summaries"

# Vocabulary
VALID_SEVERITIES = ("critical", "high", "medium", "low", "noise")
VALID_ACTIONS = ("escalate", "investigate", "log", "ignore")

LEVEL_TO_SEVERITY = {
    0: "noise", 1: "noise", 2: "noise", 3: "low", 4: "low",
    5: "low", 6: "medium", 7: "medium", 8: "medium",
    9: "high", 10: "high", 11: "high",
    12: "critical", 13: "critical", 14: "critical", 15: "critical",
}

DEFAULT_PROMOTION_THRESHOLD = 3

_WS_RE = re.compile(r"\s+")


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_whitespace(s):
    """Collapse runs of whitespace to single spaces and strip ends.
    Used by the lesson matcher so keyword substring lookups are robust to
    Wazuh's tabs, multi-space alignment, and embedded newlines."""
    if not s:
        return ""
    return _WS_RE.sub(" ", s).strip()


# State file

def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"last_alert_id": None, "last_summary_ts": None}


def save_state(state):
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_FILE)


# Queue

def read_queue_entries():
    if not QUEUE_FILE.exists():
        return []
    entries = []
    with open(QUEUE_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


# Alert compaction (filter writes these into queue.jsonl entries)

def extract_compact_alert(raw_alert):
    compact = {
        "ts": raw_alert.get("timestamp", "")[:19],
        "level": raw_alert.get("rule", {}).get("level"),
        "rule_id": raw_alert.get("rule", {}).get("id"),
        "description": raw_alert.get("rule", {}).get("description"),
        "groups": raw_alert.get("rule", {}).get("groups", []),
        "agent": raw_alert.get("agent", {}).get("name"),
        "full_log": (raw_alert.get("full_log") or "")[:300],
    }
    data = raw_alert.get("data", {})
    if isinstance(data, dict):
        for k in ("srcip", "dstip", "srcport", "dstport", "title", "file", "command", "uid", "user"):
            if k in data:
                compact[k] = data[k]
    return compact


# Normalization

def normalize_severity(token):
    if not token:
        return None
    s = str(token).lower().strip()
    for v in VALID_SEVERITIES:
        if v in s:
            return v
    return None


def normalize_action(token):
    if not token:
        return None
    s = str(token).lower().strip()
    for v in VALID_ACTIONS:
        if v in s:
            return v
    return None



def enforce_coherence(severity, action):
    """Force severity/action pairs to be logically consistent.
    Returns (severity, action, corrected:bool)."""
    if severity == "noise" and action != "ignore":
        return severity, "ignore", True
    if severity == "critical" and action not in ("escalate",):
        return severity, "escalate", True
    if severity == "low" and action not in ("log", "ignore"):
        return severity, "log", True
    if severity == "high" and action == "ignore":
        return severity, "investigate", True
    return severity, action, False


# Lesson store

def lesson_id_for(pattern, classification):
    """Deterministic SHA1-derived lesson ID. Same pattern + same verdict
    yields the same ID. Different verdicts for the same pattern compete as
    separate lessons rather than overwriting each other."""
    parts = [
        str(pattern.get("rule_id") or ""),
        str(pattern.get("agent") or ""),
        ",".join(sorted(_normalize_whitespace(k).lower() for k in (pattern.get("log_keywords") or []))),
        str(classification.get("severity") or ""),
        str(classification.get("action") or ""),
    ]
    payload = "|".join(parts)
    return hashlib.sha1(payload.encode()).hexdigest()[:16]


def load_lessons():
    if not LESSONS_FILE.exists():
        return []
    lessons = []
    try:
        with open(LESSONS_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    lessons.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return lessons


def save_lessons(lessons):
    tmp = LESSONS_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        for lesson in lessons:
            f.write(json.dumps(lesson, separators=(",", ":")) + "\n")
    tmp.replace(LESSONS_FILE)


def match_lesson(alert, lessons, status="authoritative"):
    """Return the first lesson whose pattern matches the alert. Pass
    status=None to match any status (used by ingest dedup, not the filter
    cache lookup which only wants authoritative entries).

    Whitespace is collapsed on both sides before substring comparison so
    Wazuh logs with tab alignment match Gemma's space-normalized keywords."""
    rule_id = alert.get("rule_id")
    agent = alert.get("agent")
    log = _normalize_whitespace(alert.get("full_log") or "").lower()
    for lesson in lessons:
        if status and lesson.get("status") != status:
            continue
        p = lesson.get("pattern", {})
        if p.get("rule_id") != rule_id:
            continue
        if p.get("agent") != agent:
            continue
        keywords = [_normalize_whitespace(k).lower() for k in (p.get("log_keywords") or [])]
        if keywords and not all(kw in log for kw in keywords):
            continue
        return lesson
    return None


def ingest_lesson(lessons, pattern, classification, source="gemma-teacher", reason=None,
                  promotion_threshold=DEFAULT_PROMOTION_THRESHOLD):
    """Upsert a lesson keyed by its deterministic lesson_id. If a matching
    lesson already exists, increment its promotion_count and update
    last_seen_at. Otherwise append a new pending entry. Returns the lesson."""
    lid = lesson_id_for(pattern, classification)
    now = utcnow_iso()
    for lesson in lessons:
        if lesson.get("lesson_id") == lid:
            lesson["promotion_count"] = lesson.get("promotion_count", 0) + 1
            lesson["last_seen_at"] = now
            return lesson
    new_lesson = {
        "lesson_id": lid,
        "status": "pending",
        "source": source,
        "promotion_count": 1,
        "promotion_threshold": promotion_threshold,
        "pattern": {
            "rule_id": pattern.get("rule_id"),
            "agent": pattern.get("agent"),
            "log_keywords": [_normalize_whitespace(k) for k in (pattern.get("log_keywords") or [])],
        },
        "classification": {
            "severity": classification.get("severity"),
            "action": classification.get("action"),
            "reason": reason or classification.get("reason") or "",
        },
        "created_at": now,
        "last_seen_at": now,
        "last_promoted_at": None,
        "hits": 0,
    }
    lessons.append(new_lesson)
    return new_lesson


def promote_eligible(lessons):
    """Flip any pending lesson whose promotion_count has reached its
    threshold to authoritative. Returns the count promoted."""
    promoted = 0
    now = utcnow_iso()
    for lesson in lessons:
        if lesson.get("status") != "pending":
            continue
        if lesson.get("promotion_count", 0) >= lesson.get("promotion_threshold", DEFAULT_PROMOTION_THRESHOLD):
            lesson["status"] = "authoritative"
            lesson["last_promoted_at"] = now
            promoted += 1
    return promoted

def prune_stale_lessons(lessons, max_age_days=90):
    """Remove lessons that have not been seen in max_age_days.
    Pending lessons are pruned unconditionally after the age limit.
    Authoritative lessons are only pruned if they have zero hits
    (lessons with hits > 0 have proven their value and are kept).
    Returns (pruned_list, removed_count)."""
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    kept = []
    removed = 0
    for lesson in lessons:
        last_seen = lesson.get("last_seen_at") or lesson.get("created_at") or ""
        if last_seen < cutoff:
            if lesson.get("status") == "pending":
                removed += 1
                continue
            if lesson.get("status") == "authoritative" and lesson.get("hits", 0) == 0:
                removed += 1
                continue
        kept.append(lesson)
    return kept, removed

