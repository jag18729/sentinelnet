# Journal: 2026-04-10 to 2026-04-12 -- Fleet Triage Pipeline, Start to Finish

## The Short Version

Built a two-tier LLM pipeline that triages Wazuh alerts using a small RISC-V model for per-alert classification and a GPU model for batch summarization and self-supervised teaching. The system gets faster over time without retraining. Shipped with 38 unit tests, Telegram escalation delivery, and full documentation.

Three days of work. Seven things went wrong that I didn't expect. All of them taught me something.

## What Got Built

SentinelNet was already classifying live network flows (1M+ predictions via the scapy feeder on RV2). But Wazuh HIDS alerts were piling up unprocessed. Rootcheck scans on Pi0 fire hundreds of alerts per week. Nobody was reading them.

The triage pipeline is three tiers:
- **Tier 1 (RV2):** Qwen2 1.5B int4 on the Ky X1 RISC-V SoC via onnxruntime-genai. Per-alert severity classification. Originally ~50 seconds per alert, now ~13 seconds after prompt tightening.
- **Tier 2 (XPS):** Gemma 4 e4b (8B params) on an RTX 4060 Ti via Ollama in WSL2. Batch narrative summaries every 30 minutes, plus a teacher pass that grades RV2's work and writes disagreements as "lessons".
- **Tier 3 (cloud):** Frank via Gemini 2.5 Flash, on demand. Reads the summaries and queue when the operator asks.

The lesson cache is the interesting part. When Gemma disagrees with RV2 on the same pattern three times consistently, that disagreement becomes an authoritative lesson. The filter checks the cache before calling RV2. Cache hits return in milliseconds. The system literally gets faster the longer it runs.

As of this writing: 41 lessons ingested (39 pending, 2 authoritative), 10 cache hits on the promoted netstat lesson, 15 summary reports generated, 139 alerts classified.

## Lesson 1: Verify Before Declaring Infeasible

I confidently told the user that running an LLM on RISC-V hardware was impractical because llama.cpp doesn't have good RISC-V support. Then the user said "I think I have one running on RV2." I checked. There was a fully functional Qwen2 1.5B service that had been running since March 9 with a purpose-built `/triage_alert` endpoint.

The stack was onnxruntime-genai on a Ky X1 with hardware acceleration. Nothing to do with llama.cpp. My mental model of "RISC-V inference = llama.cpp = impractical" was a category error. The hardware had its own inference path and the user had already wired it up.

**Takeaway:** When someone says "I think X is running," SSH in and check before saying it can't work.

## Lesson 2: Know Where Your Tailscale Daemon Lives

The XPS machine runs WSL2 on Windows. I assumed Tailscale was installed on the Windows side (like most WSL setups where Tailscale is a Windows service and WSL inherits the network). Wrong. Tailscale was running inside WSL2 as a Linux daemon. The `100.73.127.58` IP belongs to the WSL2 VM, not the Windows host.

This inverted the entire integration plan. A Windows-side Ollama daemon would NOT be reachable from Pi2 via that Tailscale IP without either a second Tailscale node on Windows or a netsh portproxy bridge (both fragile). The correct architecture is WSL-side Ollama in the same network namespace as the Tailscale daemon. Zero NAT, zero forwarding.

I had already written a pros/cons analysis recommending Windows-side Ollama. Had to retract it once I found the Tailscale daemon was in WSL. The recommendation flipped 180 degrees based on one `which tailscale` command.

**Takeaway:** Check which network namespace your services live in before designing the routing.

## Lesson 3: Whitespace Is Never "Just Whitespace"

The lesson cache matcher does substring lookup: check if all stored keywords appear in the alert's `full_log`. Simple. Shipped it. Tested it against a promoted lesson. Zero matches.

The problem: Wazuh emits logs with tab and multi-space alignment (`tcp6       0      0 :::2049`). Gemma extracts keywords with single spaces (`tcp6 0 0 :::2049`). A literal substring match between these two never succeeds.

The fix was six lines: collapse runs of whitespace to single spaces on both sides before comparison. Added two regression tests to lock it in. Without this fix, the entire lesson cache would have silently never matched anything in production. I would have shipped a feature that looked correct in unit tests (which used clean strings) but failed on every real alert.

**Takeaway:** If your matcher works on synthetic test data but not on real data, check whitespace, encoding, and newlines first.

## Lesson 4: Conservative Promotion Saved the Cache

The teacher pass asks Gemma 4 to independently classify each alert and compares with RV2's verdict. Disagreements become pending lessons. Pending lessons need 3 reinforcements to become authoritative.

In the first teacher batch (27 alerts), Gemma emitted four conflicting verdicts for the same rootcheck pattern on Pi0:
- `noise/ignore` (twice)
- `high/investigate` (once)
- `medium/investigate` (once)

None of these reached the threshold of 3. None got promoted. The cache stayed clean.

If I had used threshold-1 (promote on first disagreement), whichever verdict landed first would have poisoned the cache for every future rootcheck alert. The conservative threshold is not just a "nice to have." It is the difference between a self-improving system and a self-corrupting one.

**Takeaway:** When using a larger model to teach a smaller one, the teacher is wrong often enough to matter. Gate the feedback loop.

## Lesson 5: max_length Doesn't Mean What You Think

RV2's `/triage_alert` endpoint called the inference function with `max_length=128`. I changed it to 16 to speed things up. Latency didn't change. The alerts still took 50 seconds.

The bug was in the `infer()` function: `actual_max = max(req.max_length, len(input_tokens) + 64)`. That `+ 64` meant the model always generated at least 64 tokens past the prompt regardless of `max_length`. My 16 was being silently overridden.

Fixed the formula to `actual_max = len(input_tokens) + req.max_length` so `max_length` controls NEW tokens only. Then set it to 6 (we only need one word). Per-alert latency dropped from ~50 seconds to ~13 seconds. A 75% reduction from a one-line fix that had nothing to do with the model, the prompt, or the hardware.

**Takeaway:** When a parameter doesn't do what you expect, read the function that consumes it. The abstraction is leaking.

## Lesson 6: .gitignore Is a Silent Killer

Committed the entire `triage/` directory. Pushed it. CI was happy. Nobody noticed that `triage/lib/fleet_triage_common.py` (the shared module that both scripts import) was missing from the repo.

Root cause: the top-level `.gitignore` had `lib/` as a pattern (standard Python packaging ignore). It matched `triage/lib/` as well, silently excluding it from `git add`, `git status`, and every other git operation. The file existed on disk but was invisible to version control.

Found it during the hardening session when `git diff` showed no changes to the module even though I knew I had added new functions. Added `!triage/lib/` exception to `.gitignore`.

**Takeaway:** After `git add` of a new directory, run `git status` and count the files. If any are missing, check `.gitignore` with `git check-ignore -v <path>`.

## Lesson 7: WSL Auto-Boot Comes Full Circle

The very first journal entry (2026-02-12) documents losing a training run because WSL rebooted overnight. That was the XPS machine. Two months later, the same WSL instability created a different problem: if XPS reboots and nobody logs in, WSL doesn't start, Tailscale doesn't start, and the entire GPU tier drops off the fleet.

The fix is a Windows Task Scheduler entry that runs `wsl.exe -d Ubuntu -u root -- /bin/true` at system startup, before any user login. Systemd inside WSL brings up tailscaled and ollama. Now XPS survives reboots.

The irony: the training run loss in February was caused by WSL stopping unexpectedly. The triage pipeline problem in April was caused by WSL not starting at all. Same machine, opposite failure modes, both rooted in the fact that WSL2 lifecycle is tied to Windows user sessions by default.

**Takeaway:** If your infrastructure depends on WSL2, don't assume it starts on its own. Schedule it.

## What's Next

The pipeline is self-sustaining. Timers fire, alerts flow, lessons accumulate, summaries get written. The next things worth doing:

1. **Wait for natural promotion.** The 39 pending lessons need time. Some will converge and promote on their own. The ones that don't will tell us where Gemma is inconsistent.
2. **Fine-tuning (approach 4).** Once the labeled corpus from the teacher pass has a few hundred confirmed lessons, use the 4060 Ti to QLoRA fine-tune Qwen2 1.5B on those labels, export back to ONNX, ship to RV2. Real model improvement, not just caching.
3. **Embedding-based matching (approach 2).** Keyword AND-matching works for the home lab's narrow alert vocabulary. If the alert surface expands, semantic similarity via a small embedding model would generalize better.
4. **Research paper.** The self-supervised teacher loop (large model grading small model, conservative promotion, relaxed keyword matching) is a pattern that could generalize beyond IDS alert triage. Worth writing up.

This started as "can we use Gemma 4 for something useful" and turned into a self-improving alert triage system with a learning feedback loop, three-tier failure isolation, and a 75% latency reduction on the edge classifier. Not bad for a home lab Frankenstein.
