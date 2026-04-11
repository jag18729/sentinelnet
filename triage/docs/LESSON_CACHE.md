# Lesson Cache and Self-Supervised Learning

The lesson cache is the part of Fleet Triage that gets smarter over time. This document covers how it works, what the schema looks like, how operators interact with it, and the design choices behind each piece.

## What problem it solves

Fleet Triage's Tier 1 classifier (Qwen2 1.5B int4 on RV2) takes about 50 seconds per alert. The home lab generates the same kinds of Wazuh alerts over and over: rootcheck false positives on Pi0, netstat listing reports, systemd service exits, the same handful of patterns for weeks at a time. Classifying each instance from scratch is the wrong shape.

The lesson cache stores classification verdicts keyed by an alert pattern. When a new alert matches a stored pattern, the classifier returns the cached verdict in milliseconds and skips the model call entirely. The cache populates itself from a self-supervised teacher pass: every 30 minutes, the larger XPS Gemma 4 model reviews what RV2 classified, and disagreements become pending lessons. Once a pending lesson reinforces three times, it flips to authoritative and starts serving cache hits.

The result is a classifier that gets faster and more accurate without any human intervention or model fine-tuning.

## Where it lives

| Component | Path | Purpose |
|---|---|---|
| Lesson store | `/var/lib/fleet-triage/lessons.jsonl` | JSONL file, one lesson per line |
| Shared module | `/usr/local/lib/fleet_triage_common.py` | load, save, match, ingest, promote |
| Filter integration | `/usr/local/bin/fleet-triage-filter.py` | calls match_lesson before RV2 |
| Teacher integration | `/usr/local/bin/fleet-triage-summarize.py` | calls ingest_lesson on disagreements |
| Operator CLI | `/usr/local/bin/fleet-triage-lessons.py` | list, show, promote, reject, add, stats |
| Unit tests | `/usr/local/lib/test_fleet_triage_common.py` | 26 tests covering matcher, ingest, promotion, atomicity |

## Lesson schema

```json
{
  "lesson_id": "acdd57b2e30778c0",
  "status": "authoritative",
  "source": "gemma-teacher",
  "promotion_count": 2,
  "promotion_threshold": 3,
  "pattern": {
    "rule_id": "533",
    "agent": "pi0",
    "log_keywords": [
      "netstat listening ports",
      "tcp6 0 0 :::2049",
      "udp6 0 0 :::50839"
    ]
  },
  "classification": {
    "severity": "low",
    "action": "log",
    "reason": "Listing of listening ports is a routine event and should only be logged for trend analysis."
  },
  "created_at": "2026-04-11T17:30:36Z",
  "last_seen_at": "2026-04-11T17:36:40Z",
  "last_promoted_at": "2026-04-11T17:31:47Z",
  "hits": 2
}
```

### Field reference

| Field | Type | Purpose |
|---|---|---|
| `lesson_id` | string (16 hex chars) | Deterministic SHA1 of the pattern and classification. Same pattern with the same verdict yields the same ID. Different verdicts compete as separate lessons. |
| `status` | `"pending"` or `"authoritative"` | Pending lessons are not consulted by the filter. Only authoritative lessons serve cache hits. |
| `source` | `"gemma-teacher"` or `"operator"` | Where this lesson came from. Operator-added lessons are authoritative immediately. |
| `promotion_count` | int | Number of times this exact lesson_id has been re-ingested. Gets incremented on each duplicate ingest. |
| `promotion_threshold` | int (default 3) | Required count to flip pending to authoritative. Per-lesson so high-impact verdicts can be set higher. |
| `pattern.rule_id` | string | Wazuh rule ID this lesson applies to |
| `pattern.agent` | string | Wazuh agent name this lesson applies to |
| `pattern.log_keywords` | list of strings | All must appear in the alert's `full_log` (relaxed match). Whitespace is normalized to single spaces on both sides before comparison. |
| `classification.severity` | one of `critical, high, medium, low, noise` | The cached verdict |
| `classification.action` | one of `escalate, investigate, log, ignore` | The cached action recommendation |
| `classification.reason` | string | Free text. Shown by `lessons show` and `lessons stats`. Not used by the matcher. |
| `created_at` | ISO 8601 UTC | When the first ingest of this lesson_id happened |
| `last_seen_at` | ISO 8601 UTC | When the most recent ingest or cache hit happened |
| `last_promoted_at` | ISO 8601 UTC or null | When the lesson last flipped pending to authoritative |
| `hits` | int | Number of times the filter has cache-hit on this lesson |

## The matcher

The matcher in `fleet_triage_common.match_lesson()` runs once per alert in the filter, before any RV2 call. It walks the lesson list (default filter: `status="authoritative"`) and returns the first lesson whose pattern matches the alert.

### Match rules

1. **Exact match on `rule_id`.** No fuzzy matching, no rule range. The Wazuh rule ID is the strongest signal a lesson can use.
2. **Exact match on `agent`.** Same reason. A lesson learned about Pi0's rootcheck does not apply to Pi2's rootcheck because the two hosts have different baselines.
3. **All keywords must appear in the `full_log`.** Substring lookup, case-insensitive, after whitespace normalization. The "all keywords must appear" semantics is the relaxed-AND match the user picked during the design phase. It is permissive enough to catch variants of the same pattern (different file paths, different timestamps) but tight enough to avoid catching unrelated alerts that happen to share a rule_id.

### Whitespace normalization

This matters in production. Wazuh emits logs with tab alignment and multi-space columns:

```
tcp6       0      0 :::2049                 :::*                    LISTEN
```

Gemma 4 extracts keywords as natural-prose phrases:

```
"tcp6 0 0 :::2049"
```

A literal substring match against these two never succeeds. The matcher collapses runs of whitespace to single spaces on both sides before comparison:

```python
_WS_RE = re.compile(r"\s+")
def _normalize_whitespace(s):
    return _WS_RE.sub(" ", s or "").strip()
```

This is applied to the alert's `full_log` once at the top of `match_lesson` and to each keyword when it is read. The same normalization is applied at lesson ingest time so the stored keywords are already canonical.

The whitespace fix is locked in by two regression tests in `test_fleet_triage_common.py`:

- `test_matches_alert_with_tab_alignment`
- `test_keyword_with_internal_whitespace_normalizes`

### What does not match

| Reason | Example |
|---|---|
| Different rule | Lesson rule_id `510`, alert rule_id `533` |
| Different agent | Lesson agent `pi0`, alert agent `pi1` |
| Missing one keyword | Lesson keywords `["A", "B"]`, log contains only `A` |
| Empty keyword list | Matches everything for that rule_id+agent. This is intentional, used when a whole rule is fully cacheable regardless of log content. Operators can edit a lesson to clear its keyword list via the CLI's `add` command. |
| Lesson is `pending` | Pending lessons are not consulted by the default `match_lesson` call. They become eligible only after promotion. |

## Ingestion (the teacher pass)

Every summarizer run, after the narrative phase succeeds, the teacher pass runs:

1. Build a structured prompt that includes RV2's classification for each relevant alert
2. POST to XPS Ollama with `format: "json"`, asking Gemma 4 to independently classify each alert and extract 2-3 lowercase log keywords
3. Parse the JSON response (Ollama JSON-mode guarantees well-formed JSON)
4. For each alert where Gemma's verdict differs from RV2's, call `ingest_lesson()`

### `ingest_lesson()` semantics

```python
def ingest_lesson(lessons, pattern, classification, source, reason):
    lid = lesson_id_for(pattern, classification)
    for lesson in lessons:
        if lesson["lesson_id"] == lid:
            lesson["promotion_count"] += 1
            lesson["last_seen_at"] = utcnow()
            return lesson
    # otherwise: append a new pending lesson with promotion_count=1
```

The lesson_id is deterministic on `(rule_id, agent, sorted_keywords, severity, action)`. This means:

- Same pattern + same verdict from Gemma twice -> increments promotion_count to 2
- Same pattern + different verdict -> creates a new competing lesson, both pending
- Different pattern -> creates a new lesson

After all ingests, `promote_eligible()` walks the list and flips any pending lesson whose `promotion_count >= promotion_threshold` to `authoritative`. The default threshold is 3, configurable per-lesson.

### Conservative promotion in action

During the bring-up validation, Gemma 4 reviewed 27 alerts in a single teacher pass. Among them were several Wazuh rootcheck rule-510 alerts on Pi0. Gemma emitted four conflicting verdicts for the same rule_id+agent pattern across those alerts:

| Verdict | Keywords | Times seen |
|---|---|---|
| `noise/ignore` | `trojaned version of file`, `signa` | 1 |
| `noise/ignore` | `trojaned version of file`, `file` | 1 |
| `medium/investigate` | `trojaned version of file`, `file` | 1 |
| `high/investigate` | `trojaned version of file`, `file` | 1 |

None of these reaches `promotion_count = 3` because none of them are reinforced by a second consistent verdict. All four sit in the pending pool indefinitely until either Gemma starts agreeing with itself or the operator promotes one manually.

This is the protection the threshold provides. Without it, the first verdict to land would have poisoned the cache. With it, the cache stays uncontaminated until there is real evidence of agreement.

The same teacher pass produced the lesson `acdd57b2` for rule 533 (netstat listening ports) on Pi0 with two consistent reinforcements in a single batch. That one made it to `promotion_count = 2`, one short of the threshold. A manual promote via the CLI took it the rest of the way and unlocked end-to-end cache hits on subsequent filter runs.

## Operator CLI

`fleet-triage-lessons` is the operator interface. argparse-based, no external dependencies, lives at `/usr/local/bin/fleet-triage-lessons.py`.

### `list`

```bash
fleet-triage-lessons list             # all lessons
fleet-triage-lessons list --pending   # only pending
fleet-triage-lessons list --auth      # only authoritative
```

Output is a fixed-width table with id (16 hex chars), status, promotion fraction, hits, source, and a one-line pattern summary. Suitable for piping to `grep`, `sort`, or `wc -l`.

### `show <id_prefix>`

```bash
fleet-triage-lessons show acdd57b2
```

Prints the full lesson as pretty JSON. Lesson IDs accept short prefixes (4+ chars). If the prefix is ambiguous, the CLI lists the matching IDs and exits with status 1.

### `promote <id_prefix>`

```bash
fleet-triage-lessons promote acdd57b2
```

Manually flips a pending lesson to authoritative without waiting for the threshold. Use this when you know a Gemma verdict is correct and want to bypass the conservative promotion gate. Idempotent: re-running on an already-authoritative lesson is a no-op with a warning.

### `reject <id_prefix>`

```bash
fleet-triage-lessons reject d21a352b
```

Deletes a lesson permanently. Use this when Gemma got it wrong and you do not want the lesson to compete with the correct verdict. The deletion is rebroadcast to disk via atomic save.

### `add`

```bash
fleet-triage-lessons add
```

Interactive prompt that walks the operator through creating an authoritative lesson by hand. Used when you already know a pattern that the teacher has not discovered yet, or when you want to seed the cache before the first teacher pass. Operator-added lessons skip the pending state and become authoritative immediately, with `source: "operator"`.

### `stats`

```bash
fleet-triage-lessons stats
```

Output:

```
Total lessons: 8
  by status:    {'pending': 7, 'authoritative': 1}
  by source:    {'gemma-teacher': 8}
  total hits:   2 (authoritative only: 2)

Top 5 by hit count:
  acdd57b2e307 hits=2 pi0/r533 -> low/log
```

Shows aggregate counts, hit totals, and the top 5 most-hit lessons. Use this as the dashboard. If `total hits` is climbing, the cache is doing its job.

## Operator workflow

Day to day, the cache should require zero operator interaction. The teacher pass populates pending lessons, repetition promotes them, and cache hits accumulate.

The cases where an operator should engage:

### A lesson is wrong

Read the latest summary, notice an alert is being misclassified, find the relevant lesson:

```bash
fleet-triage-lessons list --auth | grep r510
fleet-triage-lessons show <id_prefix>
fleet-triage-lessons reject <id_prefix>
```

Then either let the teacher rediscover the right verdict naturally, or seed it with `add`.

### A lesson is missing

A pattern that should obviously be cached is not being cached. Check pending lessons first:

```bash
fleet-triage-lessons list --pending | grep r510
```

If it is sitting at promotion_count 1 or 2, you can either wait for natural reinforcement or promote it manually if you trust the verdict. If it is missing entirely, the teacher has not seen this pattern enough times. You can seed it with `add`.

### Cache is stale

A lesson was correct when it was promoted but the underlying pattern changed (different software version, different alert format). The hit count keeps climbing but the verdicts are now wrong. Reject the stale lesson and let the teacher rediscover.

### Dashboarding

```bash
fleet-triage-lessons stats
ls /var/lib/fleet-triage/summaries/ | tail -5
journalctl -u fleet-triage-filter.service --since "1 hour ago" | grep cache
```

Three commands give a complete operational picture: lesson health, recent reports, recent cache activity.

## Failure modes

| Failure | Behavior |
|---|---|
| `lessons.jsonl` corrupt | `load_lessons()` skips corrupt lines and returns the rest. Filter runs against zero or partial lesson set, falls through to RV2. |
| `lessons.jsonl` missing | `load_lessons()` returns `[]`. Same as the corrupt case from the filter's perspective. |
| Teacher returns invalid JSON | `parse_teacher_response()` returns None. Teacher phase logs and exits cleanly. Lessons not modified. |
| Teacher returns empty array | Zero disagreements ingested. promote_eligible runs anyway and promotes anything that was already at threshold from a previous run. |
| Save fails mid-write | Atomic temp-and-rename pattern means the original file is untouched. Operator sees a logged error in journalctl. |
| Two filter runs overlap | Should not happen because systemd `OnUnitInactiveSec` waits for completion before scheduling, but if it did, both would `load_lessons()`, classify, and `save_lessons()`. The save is atomic so the second one wins. Hit counters from the first run are lost. Acceptable for an edge case. |

## What this is not

The lesson cache is not a replacement for fine-tuning. It is a per-pattern lookup table that bypasses model inference. The lessons are not gradient updates, the cache is not a feature store, and the teacher pass is not a training loop.

It is not a substitute for human review of high-severity alerts. Lessons let the system get faster on patterns that have already been classified. They do not cause the system to forward escalations directly to a human. That layer (Frank/Telegram) lives in a separate codebase.

It is not a substitute for Wazuh tuning. If a Wazuh rule is producing 100% false positives, the right fix is to disable or adjust the rule in Wazuh, not to teach the lesson cache to mark it as `noise`. The cache exists for cases where the rule is correct most of the time but the small model is wasting cycles re-classifying the same patterns.
