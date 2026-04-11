# Fleet Triage

**Two-tier LLM pipeline for Wazuh alert triage with self-supervised learning**

A small-model classifier on RISC-V edge hardware filters Wazuh alerts in real time. A larger model on GPU produces operator-facing summaries on a 30-minute cadence and acts as a teacher: when it disagrees with the small model, the disagreement becomes a lesson. Lessons accumulate in a local cache, and once a pattern reinforces three times, the cache short-circuits the slow per-alert classifier entirely.

The system gets faster and more accurate over time without any human intervention or model fine-tuning.

## Architecture

```
Wazuh alerts.json (Pi2, inside wazuh-manager container)
        |
        v
+-------------------------------------------+
| Tier 1: Filter (Pi2)                      |
|   1. Lesson cache lookup (rule_id+agent   |
|      +keywords). Hit returns in ms.       |
|   2. Cache miss: RV2 /triage_alert (~50s) |
|   3. RV2 down: rule.level fallback        |
|                                           |
|   Cadence: every 5 minutes                |
|   Cap:     10 alerts per run              |
+-------------------------------------------+
        |
        v   queue.jsonl
        |
+-------------------------------------------+
| Tier 2: Summarizer (Pi2)                  |
|   1. Narrative phase: XPS Gemma 4 reads   |
|      the queue, writes a markdown report  |
|   2. Teacher phase: same Gemma 4 grades   |
|      RV2's classifications, ingests       |
|      disagreements as pending lessons     |
|   3. Promote: lessons hitting threshold 3 |
|      flip to authoritative                |
|                                           |
|   Cadence: every 30 minutes               |
+-------------------------------------------+
        |
        v   summaries/YYYY-MM-DD-HH-MM.md
        |
+-------------------------------------------+
| Tier 3: Cloud backstop (operator-driven)  |
|   Frank (OpenClaw + Gemini 2.5 Flash)     |
|   reads queue and summaries on demand.    |
|   Engaged when operator asks, not on a    |
|   timer. Telegram delivery.               |
+-------------------------------------------+
```

## Why this shape

The home lab generates the same kinds of Wazuh alerts over and over. Wazuh rootcheck on Pi0, netstat output on Pi0, systemd service exits on Pi2. A naive design would burn 50 seconds of RISC-V inference per alert, every time, forever.

Instead, the small model (Qwen2 1.5B int4 on a Ky X1 RISC-V SoC, accessed via onnxruntime-genai) handles the long tail of one-off alerts. The larger model (Gemma 4 e4b on an RTX 4060 Ti) reviews the small model's decisions in batches, catches consistent mistakes, and writes lessons that bypass the small model entirely on future hits.

The result: a self-improving classifier with three properties that matter operationally.

1. **Latency improves with time.** Repeat patterns drop from ~50 seconds to ~10 milliseconds once their lesson is promoted. The home lab's most common alert (rootcheck false positives) is also the most cacheable.
2. **No model retraining required.** Lessons live in a flat JSONL file, not in model weights. Adding, editing, or removing them is a JSON edit. No fine-tuning pipeline, no ONNX export, no risk of catastrophic forgetting.
3. **Failure isolation per tier.** Each tier can fail without taking the others down. RV2 offline degrades to rule-level classification. XPS offline pauses learning but the filter keeps running. Both offline still produces queued, level-classified entries that Frank can read on demand.

## File layout

```
triage/
|- README.md              this file
|- lib/
|  '- fleet_triage_common.py     shared module: state, queue, lesson store
|- bin/
|  |- fleet-triage-filter.py     timer-driven, classifies new alerts
|  |- fleet-triage-summarize.py  timer-driven, narrative + teacher pass
|  '- fleet-triage-lessons.py    operator CLI
|- systemd/
|  |- fleet-triage-filter.service
|  |- fleet-triage-filter.timer
|  |- fleet-triage-summarize.service
|  '- fleet-triage-summarize.timer
|- tests/
|  '- test_fleet_triage_common.py    26 unit tests for the shared module
'- docs/
   |- ARCHITECTURE.md     deeper architecture, failure modes, performance
   |- LESSON_CACHE.md     learning loop, schema, CLI reference
   '- DEPLOYMENT.md       step-by-step install
```

State files live on the deployment host at `/var/lib/fleet-triage/`:

| Path | Purpose |
|---|---|
| `state.json` | Last processed alert ID and last summary timestamp |
| `queue.jsonl` | Classified alerts, one JSON object per line |
| `lessons.jsonl` | Lesson cache, one JSON object per line |
| `summaries/YYYY-MM-DD-HH-MM.md` | Operator-facing markdown reports |

## Quick start

See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) for the full install procedure. The short version, on Pi2:

```bash
# Install code
sudo install -m 644 lib/fleet_triage_common.py        /usr/local/lib/
sudo install -m 644 tests/test_fleet_triage_common.py /usr/local/lib/
sudo install -m 755 bin/fleet-triage-filter.py        /usr/local/bin/
sudo install -m 755 bin/fleet-triage-summarize.py     /usr/local/bin/
sudo install -m 755 bin/fleet-triage-lessons.py       /usr/local/bin/

# Install systemd units
sudo install -m 644 systemd/fleet-triage-*.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload

# Set up state directory
sudo mkdir -p /var/lib/fleet-triage/summaries
sudo chown -R rafaeljg:rafaeljg /var/lib/fleet-triage
echo '{"last_alert_id": null, "last_summary_ts": null}' | sudo tee /var/lib/fleet-triage/state.json
sudo touch /var/lib/fleet-triage/queue.jsonl /var/lib/fleet-triage/lessons.jsonl

# Verify
cd /usr/local/lib && python3 -m unittest test_fleet_triage_common -v

# Enable timers
sudo systemctl enable --now fleet-triage-filter.timer fleet-triage-summarize.timer
systemctl list-timers fleet-triage-*
```

## Operational commands

```bash
# Status
systemctl status fleet-triage-filter.service fleet-triage-summarize.service
systemctl list-timers fleet-triage-*

# Logs
journalctl -u fleet-triage-filter.service -f
journalctl -u fleet-triage-summarize.service -f

# Manual run (does not affect timer schedule)
sudo systemctl start fleet-triage-filter.service
sudo systemctl start fleet-triage-summarize.service

# Lesson cache management
fleet-triage-lessons stats
fleet-triage-lessons list --pending
fleet-triage-lessons list --auth
fleet-triage-lessons show <id_prefix>
fleet-triage-lessons promote <id_prefix>
fleet-triage-lessons reject <id_prefix>
fleet-triage-lessons add                  # interactive

# Read latest summary
ls -t /var/lib/fleet-triage/summaries/ | head -1 | xargs -I{} cat /var/lib/fleet-triage/summaries/{}
```

## Hardware

| Node | Role | Specs |
|---|---|---|
| Pi2 | Pipeline host, Wazuh manager, systemd timers | Pi 5, 16GB ARM Cortex-A76 |
| RV2 (Orange Pi) | Tier 1 small-model inference | Ky(R) X1 RISC-V, 8c, 7.7GB, onnxruntime-genai |
| XPS | Tier 2 GPU inference | i7-11700, RTX 4060 Ti 8GB, Ollama in WSL2 |

Tailscale carries all inter-host traffic. The PA-220 firewall blocks direct cross-zone access between Pi2 and RV2/XPS, so Tailscale IPs are the canonical addresses.

## Status

- [x] Filter and summarizer scripts deployed on Pi2 systemd timers
- [x] Shared module with 26 unit tests covering matcher, ingest, promotion, atomicity
- [x] Lesson cache live, end-to-end cache hit verified, CLI shipped
- [x] Gemma 4 teacher pass producing pending lessons automatically
- [x] Failure modes validated: corrupt lessons.jsonl, XPS unreachable
- [ ] Lesson coherence check (severity=noise should imply action=ignore)
- [ ] Frank/Telegram integration so escalations surface without polling
- [ ] WSL auto-boot hardening on XPS so reboots do not drop the GPU tier
- [ ] Lesson rotation/pruning for very long-running deployments

## Performance

Numbers from the 2026-04-11 bring-up on this hardware:

| Operation | Time | Notes |
|---|---|---|
| Filter, RV2 cache miss | 42-50s per alert | Qwen2 1.5B int4 inference time |
| Filter, lesson cache hit | <10 ms per alert | substring matching against authoritative lessons |
| Summarizer, narrative phase | ~50s | Gemma 4 e4b warm, 27 alerts, 8.8KB prompt |
| Summarizer, teacher phase | ~5s per alert | structured JSON output via Ollama format=json |
| End to end (50 alerts, mostly cache miss) | ~7-8 minutes filter + ~3 minutes summarizer | bounded by per-run cap of 10 alerts |

## Further reading

- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md): tier breakdown, failure modes, design rationale
- [docs/LESSON_CACHE.md](./docs/LESSON_CACHE.md): learning loop internals, schema, CLI reference, operator workflow
- [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md): full install and verification procedure
- [../README.md](../README.md): SentinelNet repo overview
