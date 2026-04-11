# Fleet Triage Architecture

> *The cheapest classification is the one you do not have to do twice. The cheapest model is the one that did not need to run. The cheapest operator is the one who reads two paragraphs instead of two thousand alerts.*

## Overview

Fleet Triage is a three-layer pipeline for processing Wazuh HIDS alerts in a small home lab. Each layer has one job. Each layer can fail independently without taking the others down.

The design constraints that drove this shape:

1. **The small model is slow.** Qwen2 1.5B int4 on a Ky X1 RISC-V SoC, served through onnxruntime-genai, takes about 50 seconds per alert. That is unacceptable for the alert volume Wazuh generates during a rootcheck scan.
2. **The large model is unavailable.** XPS lives in a WSL2 instance on a Windows desktop. Power events, reboots, and the user signing out can take it offline for hours. Anything that depends on it must degrade gracefully when it is gone.
3. **The cloud model costs money.** Frank, the operator-facing OpenClaw agent, runs on Gemini 2.5 Flash. Every API call has a marginal cost and a marginal latency. Reserving it for human-initiated queries keeps spend predictable.
4. **The home lab generates the same alerts over and over.** Wazuh rootcheck on Pi0 fires hundreds of times per week with effectively identical content. Classifying it from scratch every time is theatre.

The architecture solves all four constraints with a tiered classifier and a lesson cache that bypasses the slow model on repeat patterns.

## Tier breakdown

### Tier 1: Filter (Pi2)

```
+----------------------------+
| /usr/local/bin/             |
|   fleet-triage-filter.py    |
|                             |
| systemd timer:              |
|   every 5 min after         |
|   previous completion       |
|                             |
| max 10 alerts per run       |
+--------------+-------------+
               |
   for each new alert:
               |
               v
+----------------------------+
| 1. Lesson cache lookup      |
|    match by:                |
|      rule_id                |
|      agent                  |
|      log_keywords (AND)     |
|    status: authoritative    |
|                             |
|    HIT: return immediately  |
|         increment hits      |
|         (~10 ms)            |
+--------------+-------------+
               |  miss
               v
+----------------------------+
| 2. RV2 health check         |
|    GET /health on           |
|    100.118.229.114:8090     |
+--------------+-------------+
               |  ok
               v
+----------------------------+
| 3. RV2 inference            |
|    POST /triage_alert       |
|    Qwen2 1.5B int4          |
|    parse raw response       |
|    normalize severity+act   |
|    (~42-50 s)               |
+--------------+-------------+
               |
               v
+----------------------------+
| 4. Append to queue.jsonl    |
|    update state.json        |
+----------------------------+
```

The filter is intentionally simple. It does not summarize, does not retry, does not page anyone. Its job is to get a verdict for every new alert and put it in the queue.

Three reasons it does not panic on failure:

1. **RV2 timeouts** (`rv2_health()` returns False) make the filter fall back to a deterministic rule-level mapping (level 0-2: noise, 3-5: low, 6-8: medium, 9-11: high, 12-15: critical) with classifier tag `fallback-health`. Output quality drops, but the queue keeps moving.
2. **RV2 returns garbage** (the raw response cannot be parsed by the strict regex extractor for SEVERITY and ACTION line-starts) triggers `fallback-parse`. We saw this consistently with Qwen 1.5B during bring-up: it would return chat template tokens, multiple ACTION lines, or numeric prefixes like `[critical]0`. The parser is intentionally strict so we know when to fall back rather than ingesting noise.
3. **Lesson file corrupt** (load_lessons returns empty on JSONDecodeError per line) means the cache is bypassed entirely and every alert goes through RV2 or fallback. The pipeline degrades, it does not crash.

### Tier 2: Summarizer (Pi2)

```
+----------------------------+
| /usr/local/bin/             |
|   fleet-triage-summarize.py |
|                             |
| systemd timer:              |
|   every 30 min after        |
|   previous completion       |
+--------------+-------------+
               |
               v
+----------------------------+
| 1. Read queue.jsonl         |
|    Filter to entries:       |
|      queued_at > last_      |
|        summary_ts           |
|      severity in {critical, |
|        high, medium} OR     |
|      action in {escalate,   |
|        investigate}         |
+--------------+-------------+
               |
               v
+----------------------------+
| 2. XPS health check         |
|    GET /api/version on      |
|    100.73.127.58:11434      |
|                             |
|    Fail: log, return.       |
|    State NOT advanced.      |
|    Same entries retried     |
|    on next firing.          |
+--------------+-------------+
               |  ok
               v
+----------------------------+
| 3. Narrative phase          |
|    POST /api/generate       |
|    model gemma4:e4b         |
|    num_ctx 8192, temp 0.2   |
|    Build markdown report    |
|    Write summaries/*.md     |
|    Advance state            |
|    (~50 s warm)             |
+--------------+-------------+
               |
               v
+----------------------------+
| 4. Teacher phase            |
|    POST /api/generate       |
|    format=json              |
|    Independent verification |
|    of each relevant entry   |
|    by Gemma 4               |
|                             |
|    For each disagreement    |
|    with RV2's verdict:      |
|      build pattern from     |
|      alert + Gemma keywords |
|      ingest_lesson()        |
|                             |
|    promote_eligible()       |
|    save_lessons()           |
|    (~5 s per alert)         |
+----------------------------+
```

The narrative and teacher phases use the same Ollama daemon and the same model, but they exist in different failure domains by design.

The narrative phase advances state on success. If it fails, the summarizer exits without touching state, so the same entries get retried next firing. This is a hard rule. Operators rely on the markdown reports being a continuous record.

The teacher phase is best-effort. It runs after a successful narrative write, and any failure in the teacher pass (network error, JSON parse failure, save error, even an unexpected exception) is logged and swallowed. The narrative report is already on disk. Learning will catch up next time the timer fires.

This split matters because the teacher pass is the riskier of the two. It uses Ollama's `format: "json"` parameter, which forces the model to return well-formed JSON, but the parser still has to handle:

1. Empty arrays (zero disagreements, common when Gemma agrees with RV2)
2. Missing fields (Gemma occasionally drops keywords)
3. Invalid severities or actions (Gemma occasionally invents new categories)
4. Wrong alert_id references (Gemma occasionally hallucinates IDs)

Each of these is handled defensively. None of them should ever cause the narrative report to be re-generated or the state to roll back.

### Tier 3: Cloud backstop (Pi2 + cloud)

This tier is operator-driven, not timer-driven. Frank (the OpenClaw `main` agent on Pi2) reads `/var/lib/fleet-triage/summaries/` and `queue.jsonl` on demand, and uses Gemini 2.5 Flash to answer operator questions about the fleet's recent alert state. Telegram delivery via the existing `@frank_is_a_real_bot` integration.

This tier is not yet wired. The rest of the pipeline produces the artifacts Frank will read. The integration belongs in the OpenClaw workspace, not in this repo.

## Failure mode matrix

| RV2 (filter) | XPS (summarizer narrative) | XPS (summarizer teacher) | Pi2 (host) | Pipeline behavior |
|---|---|---|---|---|
| Up | Up | Up | Up | Full pipeline. Filter classifies in 50 ms (cache hit) or 50 s (RV2 miss). Summarizer produces markdown every 30 min and grows the lesson cache. |
| Up | Up | Down | Up | Filter and summarizer narrative work. Teacher pass logs and exits. Lesson cache stops growing but existing lessons keep serving cache hits. |
| Up | Down | Down | Up | Filter still works (RV2 + cache). Summarizer skips this run, retries next firing. Backlog accumulates in queue.jsonl until XPS returns. |
| Down | Up | Up | Up | Filter falls back to rule-level classification with `classifier=fallback-health`. Summarizer still produces narratives but quality of triage labels is reduced. Teacher pass still ingests lessons but fewer disagreements because both sides are weaker signals. |
| Down | Down | Down | Up | Filter falls back to rule-level. Summarizer skips. Operator reads queue.jsonl directly or asks Frank. Pipeline is degraded but not broken. |
| Up/Down | Up/Down | Up/Down | Down | Pipeline is down. This is the acceptable single point of failure because Pi2 is the most reliable host in the fleet (always-on, ARM, on a UPS) and the alert source (Wazuh) lives there too. |

The deliberate design property: there is no scenario where a single host failure causes data loss or corrupted state. The state file (`state.json`) is updated atomically via temp-file-and-rename. The queue is append-only. The lesson file is rewritten atomically. Restarting any component from the last known good state is safe.

## Performance characteristics

Measured on the 2026-04-11 bring-up. Steady-state numbers will vary with model warm-up state and concurrent load.

### Filter

| Path | Time | Cache hit | Notes |
|---|---|---|---|
| Lesson cache hit | < 10 ms | yes | substring lookup against authoritative lessons in memory |
| RV2 inference | 42-50 s | no | Qwen2 1.5B int4 forward pass on Ky X1 |
| RV2 fallback (rule level) | < 5 ms | no | only when RV2 health check fails |
| RV2 parse failure | 42-50 s | no | RV2 ran but output was unparseable, falls through to rule level |

For the home lab's actual alert mix (heavy on rootcheck repeats), the cache hit rate climbs over the first day or two and the average per-alert cost drops by an order of magnitude.

### Summarizer

| Phase | Time | Notes |
|---|---|---|
| Health check (XPS up) | < 100 ms | local Tailscale latency |
| Health check (XPS down) | 5 s | timeout |
| Narrative, warm model | ~50 s | 27 alerts, 8.8KB prompt, 933 output tokens |
| Narrative, cold model | +17 s | first request after Gemma 4 e4b unloads from VRAM |
| Teacher phase, 27 alerts | ~142 s | 5 s per alert with structured JSON output |
| Lesson save | < 10 ms | atomic temp-and-rename |

The 30-minute timer cadence is generous. Even pathological runs (50+ alerts after a long XPS outage) finish in under 5 minutes total.

## Design rationale

### Why two tiers, not one

A single tier on the small model is too slow under burst load. A single tier on the large model means every alert goes through XPS, and XPS is the unreliable host. The two-tier split lets the slow-but-always-on tier handle the hot path and the fast-but-unreliable tier handle the analytical work.

### Why the lesson cache is rule_id + agent + keyword AND, not embeddings

Embeddings would generalize better. They would also require a third model (an embedding model), a vector store, and a similarity threshold to tune. For a home lab fleet that generates the same handful of patterns over and over, exact-pattern lookup with a small relaxed keyword check is dramatically simpler and produces near-100% recall on the patterns it knows about. The miss rate against new patterns is fine because misses just fall through to the existing classifier chain.

### Why conservative promotion (threshold 3)

Gemma 4 is wrong sometimes. During the bring-up validation we observed Gemma 4 emit four conflicting verdicts for the same `rule 510 / pi0 / trojaned version of file` pattern across a single 27-alert batch: two `noise/ignore`, one `high/investigate`, one `medium/investigate`. None of those reaches threshold 3 individually, so none of them get promoted. The cache stays uncontaminated until Gemma settles on one consistent answer.

If we used a threshold of 1 (promote-on-first-disagreement), the first verdict to land would have poisoned the cache and all subsequent rule-510 alerts would have been classified incorrectly. The threshold is the safety margin against teacher inconsistency.

### Why deterministic lesson IDs that include the verdict

A lesson ID that hashes only the pattern would let conflicting verdicts overwrite each other in the cache. Including the classification in the hash means competing verdicts produce competing lessons that race to threshold independently. The first to reach 3 wins. The others sit pending forever or get rejected via the operator CLI.

This is the same reason the lesson schema separates `pattern` and `classification` as distinct sub-objects: they have independent lifecycles.

### Why whitespace normalization on both sides of the matcher

Wazuh emits logs with tab and multi-space alignment (netstat output, ps tables, etc.). Gemma 4 extracts keywords with single spaces because that is how it normally writes prose. The first matcher we shipped did literal substring lookup and never matched anything in production. The fix is to collapse runs of whitespace to single spaces on both keyword and log sides before comparison. Two regression tests in `tests/test_fleet_triage_common.py` lock this in.

### Why the teacher pass uses Ollama's `format: "json"` mode

The first parser we built used regex to extract `SEVERITY:` and `ACTION:` line-starts from natural-language model output. This worked for Gemma 4 about 60% of the time and produced silent garbage the rest of the time. Switching to Ollama's JSON-mode (which forces well-formed JSON output by sampling against the JSON grammar) eliminated the parse failures entirely. The teacher prompt asks for a specific schema and the parser walks the resulting structure with normal `json.loads()`.

### Why the narrative phase advances state and the teacher phase does not

State (`last_summary_ts`) tracks how far through the queue the operator-facing reports have caught up. If the narrative phase succeeds but the teacher phase fails, we still want the markdown report to be considered final, not regenerated next firing. The teacher pass is auxiliary learning, not the primary product.

If both phases shared state, a flaky teacher pass would force the operator to read the same alerts in two different summary files. By separating them, the worst case is a brief gap in the lesson cache growth, which the next firing recovers automatically.
