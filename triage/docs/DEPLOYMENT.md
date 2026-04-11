# Fleet Triage Deployment

Step-by-step install of the Fleet Triage pipeline on Pi2.

## Prerequisites

The pipeline assumes you already have:

| Requirement | Notes |
|---|---|
| **Pi2** with Python 3.10+ and systemd | The pipeline host. Runs both timers, holds the state directory. |
| **Wazuh manager** in a Docker container named `wazuh-manager` on Pi2 | The filter reads alerts via `docker exec wazuh-manager tail /var/ossec/logs/alerts/alerts.json`. The user running the filter must be in the `docker` group. |
| **RV2 LLM service** at `http://100.118.229.114:8090` | Qwen2 1.5B int4 served by `rv2-llm.service` via FastAPI. Endpoints: `/health`, `/triage_alert`. See `~/RiscV-KyX1-LLM-Demo/llm_api.py` on RV2 for the source. |
| **XPS Ollama** at `http://100.73.127.58:11434` | Gemma 4 e4b model pulled, daemon listening on 0.0.0.0 via `OLLAMA_HOST` env var. See `xps-ollama.md` in memory for setup. |
| **Tailscale** active on Pi2 | All external endpoints (RV2, XPS) are reached via Tailscale IPs because the PA-220 firewall blocks direct cross-zone traffic. |

If any of these are missing, install them first. The pipeline will not function without all four.

## Verify prerequisites

Run on Pi2 before installing:

```bash
# Wazuh container
docker ps --format '{{.Names}}' | grep -q '^wazuh-manager$' && echo "wazuh-manager: ok" || echo "MISSING"

# RV2 reachable
curl -sS --max-time 5 http://100.118.229.114:8090/health && echo
# expected: {"status":"ok","model":"qwen2-1.5b-int4","device":"rv2"}

# XPS reachable
curl -sS --max-time 5 http://100.73.127.58:11434/api/version && echo
# expected: {"version":"0.20.5"} (or whatever you have)

# Gemma 4 model present on XPS
curl -sS http://100.73.127.58:11434/api/tags | python3 -c 'import json,sys; tags=[m["name"] for m in json.load(sys.stdin)["models"]]; print("gemma4:e4b" in tags and "gemma4: ok" or "MISSING gemma4:e4b")'

# Docker group membership
groups | grep -q docker && echo "docker group: ok" || echo "MISSING (add user to docker group)"
```

All five should print `ok` lines.

## Install

From a checkout of this repo on a workstation that can SSH to Pi2:

```bash
cd /path/to/sentinelnet/triage

# Copy code to Pi2
scp lib/fleet_triage_common.py        pi2:/tmp/
scp tests/test_fleet_triage_common.py pi2:/tmp/
scp bin/fleet-triage-filter.py        pi2:/tmp/
scp bin/fleet-triage-summarize.py     pi2:/tmp/
scp bin/fleet-triage-lessons.py       pi2:/tmp/
scp systemd/fleet-triage-*.service    pi2:/tmp/
scp systemd/fleet-triage-*.timer      pi2:/tmp/

# Install on Pi2
ssh pi2 'sudo install -m 644 /tmp/fleet_triage_common.py        /usr/local/lib/'
ssh pi2 'sudo install -m 644 /tmp/test_fleet_triage_common.py   /usr/local/lib/'
ssh pi2 'sudo install -m 755 /tmp/fleet-triage-filter.py        /usr/local/bin/'
ssh pi2 'sudo install -m 755 /tmp/fleet-triage-summarize.py     /usr/local/bin/'
ssh pi2 'sudo install -m 755 /tmp/fleet-triage-lessons.py       /usr/local/bin/'
ssh pi2 'sudo install -m 644 /tmp/fleet-triage-filter.service    /etc/systemd/system/'
ssh pi2 'sudo install -m 644 /tmp/fleet-triage-filter.timer      /etc/systemd/system/'
ssh pi2 'sudo install -m 644 /tmp/fleet-triage-summarize.service /etc/systemd/system/'
ssh pi2 'sudo install -m 644 /tmp/fleet-triage-summarize.timer   /etc/systemd/system/'
ssh pi2 'sudo systemctl daemon-reload'
```

## Set up state directory

```bash
ssh pi2 '
sudo mkdir -p /var/lib/fleet-triage/summaries
sudo chown -R rafaeljg:rafaeljg /var/lib/fleet-triage
sudo chmod 755 /var/lib/fleet-triage /var/lib/fleet-triage/summaries
echo "{\"last_alert_id\": null, \"last_summary_ts\": null}" > /var/lib/fleet-triage/state.json
touch /var/lib/fleet-triage/queue.jsonl /var/lib/fleet-triage/lessons.jsonl
ls -la /var/lib/fleet-triage/
'
```

Expected output:

```
drwxr-xr-x  3 rafaeljg rafaeljg 4096 ... .
drwxr-xr-x ...                         ..
-rw-rw-r--  1 rafaeljg rafaeljg    0 ... lessons.jsonl
-rw-rw-r--  1 rafaeljg rafaeljg    0 ... queue.jsonl
-rw-r--r--  1 rafaeljg rafaeljg   49 ... state.json
drwxr-xr-x  2 rafaeljg rafaeljg 4096 ... summaries
```

The `rafaeljg` user matches the systemd unit's `User=rafaeljg` directive. If you deploy under a different user, change both this command and the `User=` field in the .service files before installing.

## Run unit tests

Before enabling the timers, verify the shared module works in the install location:

```bash
ssh pi2 'cd /usr/local/lib && python3 -m unittest test_fleet_triage_common -v'
```

Expected: `Ran 26 tests in <1s. OK`

If any test fails, fix it before proceeding. The failure modes the tests cover (atomic save, deterministic IDs, whitespace normalization) are the same ones that would silently corrupt production state.

## Verify lesson CLI

```bash
ssh pi2 'fleet-triage-lessons stats'
```

Expected: `(no lessons)` on a fresh install.

```bash
ssh pi2 'fleet-triage-lessons --help'
```

Should list six subcommands: list, show, promote, reject, add, stats.

## First run, manual

Run the filter once manually before starting the timer. This proves the pipeline can talk to RV2 and Wazuh end-to-end:

```bash
ssh pi2 'sudo systemctl start fleet-triage-filter.service'
ssh pi2 'sudo journalctl -u fleet-triage-filter.service --since "5 minutes ago" --no-pager'
```

The first manual run takes 8 to 10 minutes (10 alerts at 50 seconds each). Expected output shape:

```
[filter] starting, last_alert_id=None
[filter] loaded 0 lessons (0 authoritative)
[filter] first run: taking last 10 alerts as baseline
[filter] queued <id> sev=<severity> act=<action> via=rv2
... (9 more)
[filter] done, last_alert_id=<id>, queued 10 alerts (0 cache hits)
```

If you see `via=fallback-health`, RV2 is unreachable. Check `curl http://100.118.229.114:8090/health` from Pi2.

If you see `via=fallback-parse` for many alerts, RV2 is reachable but its responses are unparseable. This is normal occasionally with Qwen 1.5B. If it is happening to every alert, check the RV2 service logs for tokenizer issues.

After the manual run, verify the queue file:

```bash
ssh pi2 'wc -l /var/lib/fleet-triage/queue.jsonl'
```

Expected: 10.

## First summarizer run, manual

```bash
ssh pi2 'sudo systemctl start fleet-triage-summarize.service'
ssh pi2 'sudo journalctl -u fleet-triage-summarize.service --since "5 minutes ago" --no-pager'
```

The first run takes about 90 seconds (50s narrative + 5s per alert teacher pass on a small batch). Expected output shape:

```
[summarize] starting, last_summary_ts=None
[summarize] queue=10 relevant=N
[summarize] narrative prompt size: <bytes> chars
[summarize] wrote /var/lib/fleet-triage/summaries/YYYY-MM-DD-HH-MM.md (<seconds>s)
[summarize] narrative done, last_summary_ts=<ts>
[summarize] teacher: prompt size <bytes> chars, N alerts
[summarize] teacher: parsed N verifications in <seconds>s
[summarize] teacher: N reviewed, M disagreements, K promoted
```

Check the summary file:

```bash
ssh pi2 'ls -t /var/lib/fleet-triage/summaries/ | head -1 | xargs -I{} cat /var/lib/fleet-triage/summaries/{}'
```

You should see a markdown report with sections: Overview, Key Patterns, Priorities for Operator, False Positive Risk, and a Raw alert index.

Check that lessons were ingested:

```bash
ssh pi2 'fleet-triage-lessons stats'
ssh pi2 'fleet-triage-lessons list'
```

You should see one or more lessons with `status=pending`.

## Enable timers

Once the manual runs work end-to-end:

```bash
ssh pi2 'sudo systemctl enable --now fleet-triage-filter.timer fleet-triage-summarize.timer'
ssh pi2 'systemctl list-timers fleet-triage-* --no-pager'
```

Expected:

```
NEXT                            LEFT     LAST                       PASSED  UNIT                          ACTIVATES
... +5 minutes ...              4min     ...                        ...     fleet-triage-filter.timer    fleet-triage-filter.service
... +29 minutes ...              29min   ...                        ...     fleet-triage-summarize.timer fleet-triage-summarize.service
```

The pipeline is now live. It will catch up on the queue automatically. After 24 to 48 hours of natural operation, you should see authoritative lessons in `fleet-triage-lessons list --auth` and cache hits in `fleet-triage-lessons stats`.

## Verification checklist

| Check | Command | Expected |
|---|---|---|
| Code installed | `ssh pi2 'ls -la /usr/local/bin/fleet-triage-*.py /usr/local/lib/fleet_triage_common.py'` | All files present, executable |
| Tests pass | `ssh pi2 'cd /usr/local/lib && python3 -m unittest test_fleet_triage_common'` | `Ran 26 tests ... OK` |
| Units valid | `ssh pi2 'systemd-analyze verify /etc/systemd/system/fleet-triage-*'` | Empty output (no errors) |
| State dir | `ssh pi2 'ls -la /var/lib/fleet-triage/'` | state.json, queue.jsonl, lessons.jsonl, summaries/ |
| RV2 reachable | `ssh pi2 'curl -sS http://100.118.229.114:8090/health'` | `{"status":"ok",...}` |
| XPS reachable | `ssh pi2 'curl -sS http://100.73.127.58:11434/api/version'` | `{"version":"..."}` |
| Filter ran | `ssh pi2 'systemctl status fleet-triage-filter.service'` | Active or last exit clean |
| Summarizer ran | `ssh pi2 'systemctl status fleet-triage-summarize.service'` | Active or last exit clean |
| Lessons exist | `ssh pi2 'fleet-triage-lessons stats'` | Total > 0 after first summarizer run |
| Timers enabled | `ssh pi2 'systemctl list-timers fleet-triage-*'` | Both timers listed with future NEXT |

## Troubleshooting

### Filter logs `wazuh tail failed`

```
[filter] wazuh tail failed: Command '['docker', 'exec', 'wazuh-manager', ...]' returned non-zero exit status 1.
```

Check the user can run `docker exec`:

```bash
ssh pi2 'groups | grep docker'
ssh pi2 'docker exec wazuh-manager echo ok'
```

If `groups` does not list docker, add the user: `sudo usermod -aG docker rafaeljg` then log out and back in.

### Filter never produces cache hits

After 24 hours of operation:

```bash
ssh pi2 'fleet-triage-lessons stats'
```

If `total hits: 0` and `by status` shows no authoritative lessons, the teacher pass has not generated enough reinforcement to promote any pattern. Two possibilities:

1. Gemma 4 is too inconsistent. Look at pending lessons: `fleet-triage-lessons list --pending`. If you see the same pattern with multiple competing classifications, that is the conservative-promotion gate doing its job. Manually promote the verdict you trust with `fleet-triage-lessons promote <id_prefix>`.
2. The alert volume is too low. The teacher needs to see the same pattern at least three times to promote it. On a quiet fleet this can take days.

You can also seed lessons by hand with `fleet-triage-lessons add` if you already know patterns that should be cached.

### Summarizer logs `XPS health check failed`

```
[summarize] XPS health check failed; skipping this run (state not advanced)
```

XPS is unreachable. Check from Pi2:

```bash
ssh pi2 'curl -sS --max-time 5 http://100.73.127.58:11434/api/version'
```

If this hangs or errors, XPS is offline. Wait for it to come back. The summarizer will catch up automatically on the next firing.

If XPS is reachable from Pi2 but the summarizer still fails health check, check the Tailscale interface state on Pi2 and the routing table.

### Summarizer logs `teacher: could not parse JSON response`

```
[summarize] teacher: could not parse JSON response (head: '...'); skipping
```

Gemma 4 returned something that was not parseable JSON despite `format: "json"` being set. Check Ollama version on XPS:

```bash
ssh rjgar@100.73.127.58 'ollama --version'
```

JSON-mode requires Ollama 0.1.30 or later. If you are on an older version, upgrade with `curl -fsSL https://ollama.com/install.sh | sudo bash`.

If you are on a recent version and still see parse failures, the prompt may need tightening. Look at the actual model output by running the summarizer with verbose teacher prompt logging.

### Cache is wrong

A lesson is misclassifying alerts. Find it and reject it:

```bash
ssh pi2 'fleet-triage-lessons list --auth | grep <pattern>'
ssh pi2 'fleet-triage-lessons show <id_prefix>'
ssh pi2 'fleet-triage-lessons reject <id_prefix>'
```

The next filter run will not hit that lesson. The teacher will rediscover it (possibly with the same wrong verdict). If Gemma is consistently wrong about a pattern, the right fix is `fleet-triage-lessons add` to seed the correct verdict authoritatively. Operator-added lessons skip the threshold and become authoritative immediately.

## Rollback

To remove the pipeline entirely:

```bash
ssh pi2 '
sudo systemctl disable --now fleet-triage-filter.timer fleet-triage-summarize.timer
sudo systemctl stop fleet-triage-filter.service fleet-triage-summarize.service
sudo rm -f /etc/systemd/system/fleet-triage-*.service /etc/systemd/system/fleet-triage-*.timer
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/fleet-triage-*.py /usr/local/lib/fleet_triage_common.py /usr/local/lib/test_fleet_triage_common.py
# Optional: also wipe state
# sudo rm -rf /var/lib/fleet-triage
'
```

The state directory is left in place by default so re-installs can resume from the same queue and lesson cache. Delete it explicitly if you want a clean slate.

## Upgrade

To upgrade in place:

```bash
# On workstation
cd /path/to/sentinelnet/triage
git pull

# Re-run the install steps from above. systemd will pick up the new files
# on the next timer firing. If you change a .service or .timer unit, run
# 'sudo systemctl daemon-reload' on Pi2 and the next timer firing will
# use the new unit.
```

The shared module's API is intentionally stable. Internal refactors of the filter and summarizer scripts do not break existing state files. If a future change introduces a schema migration, it will be called out in this document.
