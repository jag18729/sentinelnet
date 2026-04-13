#!/usr/bin/env python3
"""Lesson store management CLI for the fleet triage pipeline.

Subcommands:
  list [--pending|--auth|--all]   List lessons (default --all)
  show <id_prefix>                Full detail of one lesson
  promote <id_prefix>              Manually flip pending to authoritative
  reject <id_prefix>               Delete a lesson
  add                              Interactive: prompt for fields and add
  stats                            Counts, hits, sources

Lesson IDs accept short prefixes (4+ chars).
"""
import argparse
import json
import sys
from collections import Counter

sys.path.insert(0, "/usr/local/lib")
import fleet_triage_common as ftc


def find_by_prefix(lessons, prefix):
    matches = [l for l in lessons if l.get("lesson_id", "").startswith(prefix)]
    if len(matches) == 0:
        print(f"no lesson matching prefix '{prefix}'", file=sys.stderr)
        sys.exit(1)
    if len(matches) > 1:
        print(f"prefix '{prefix}' is ambiguous, matches {len(matches)} lessons:", file=sys.stderr)
        for m in matches:
            print(f"  {m.get('lesson_id')}", file=sys.stderr)
        sys.exit(1)
    return matches[0]


def cmd_list(args):
    lessons = ftc.load_lessons()
    if args.pending:
        lessons = [l for l in lessons if l.get("status") == "pending"]
    elif args.auth:
        lessons = [l for l in lessons if l.get("status") == "authoritative"]

    if not lessons:
        print("(no lessons)")
        return

    print(f"{'ID':<18} {'STATUS':<14} {'PROMO':<6} {'HITS':<6} {'SRC':<14} PATTERN")
    print("-" * 100)
    for l in lessons:
        lid = l.get("lesson_id", "?")[:16]
        status = l.get("status", "?")
        promo = f"{l.get('promotion_count', 0)}/{l.get('promotion_threshold', '?')}"
        hits = l.get("hits", 0)
        src = l.get("source", "?")[:12]
        p = l.get("pattern", {})
        c = l.get("classification", {})
        kw = ",".join(p.get("log_keywords") or [])[:30]
        pattern = f"r{p.get('rule_id')} {p.get('agent')} [{kw}] -> {c.get('severity')}/{c.get('action')}"
        print(f"{lid:<18} {status:<14} {promo:<6} {hits:<6} {src:<14} {pattern}")


def cmd_show(args):
    lessons = ftc.load_lessons()
    lesson = find_by_prefix(lessons, args.id_prefix)
    print(json.dumps(lesson, indent=2))


def cmd_promote(args):
    lessons = ftc.load_lessons()
    lesson = find_by_prefix(lessons, args.id_prefix)
    if lesson.get("status") == "authoritative":
        print(f"lesson {lesson['lesson_id']} already authoritative")
        return
    lesson["status"] = "authoritative"
    lesson["last_promoted_at"] = ftc.utcnow_iso()
    ftc.save_lessons(lessons)
    print(f"promoted {lesson['lesson_id']} to authoritative")


def cmd_reject(args):
    lessons = ftc.load_lessons()
    lesson = find_by_prefix(lessons, args.id_prefix)
    lessons = [l for l in lessons if l.get("lesson_id") != lesson.get("lesson_id")]
    ftc.save_lessons(lessons)
    print(f"deleted {lesson.get('lesson_id')} ({lesson.get('classification', {}).get('severity')}/{lesson.get('classification', {}).get('action')})")


def cmd_add(args):
    print("Add a new authoritative lesson. Press Ctrl-C to cancel.")
    rule_id = input("rule_id: ").strip()
    agent = input("agent (e.g. pi0): ").strip()
    keywords_raw = input("log_keywords (comma-separated, 2-3 short phrases): ").strip()
    keywords = [k.strip().lower() for k in keywords_raw.split(",") if k.strip()]
    severity = input(f"severity ({'|'.join(ftc.VALID_SEVERITIES)}): ").strip().lower()
    action = input(f"action ({'|'.join(ftc.VALID_ACTIONS)}): ").strip().lower()
    reason = input("reason (one sentence): ").strip()

    if severity not in ftc.VALID_SEVERITIES:
        print(f"invalid severity '{severity}'", file=sys.stderr)
        sys.exit(1)
    if action not in ftc.VALID_ACTIONS:
        print(f"invalid action '{action}'", file=sys.stderr)
        sys.exit(1)

    lessons = ftc.load_lessons()
    pattern = {"rule_id": rule_id, "agent": agent, "log_keywords": keywords}
    classification = {"severity": severity, "action": action}
    lesson = ftc.ingest_lesson(lessons, pattern, classification, source="operator", reason=reason)
    # Operator-added lessons go straight to authoritative
    lesson["status"] = "authoritative"
    lesson["last_promoted_at"] = ftc.utcnow_iso()
    ftc.save_lessons(lessons)
    print(f"added {lesson['lesson_id']} as authoritative")


def cmd_stats(args):
    lessons = ftc.load_lessons()
    if not lessons:
        print("(no lessons)")
        return
    by_status = Counter(l.get("status") for l in lessons)
    by_source = Counter(l.get("source") for l in lessons)
    total_hits = sum(l.get("hits", 0) for l in lessons)
    auth_hits = sum(l.get("hits", 0) for l in lessons if l.get("status") == "authoritative")
    most_hit = sorted(lessons, key=lambda l: -l.get("hits", 0))[:5]

    print(f"Total lessons: {len(lessons)}")
    print(f"  by status:    {dict(by_status)}")
    print(f"  by source:    {dict(by_source)}")
    print(f"  total hits:   {total_hits} (authoritative only: {auth_hits})")
    if any(l.get("hits", 0) > 0 for l in lessons):
        print()
        print("Top 5 by hit count:")
        for l in most_hit:
            if l.get("hits", 0) == 0:
                break
            p = l.get("pattern", {})
            c = l.get("classification", {})
            print(f"  {l['lesson_id'][:12]} hits={l.get('hits')} {p.get('agent')}/r{p.get('rule_id')} -> {c.get('severity')}/{c.get('action')}")



def cmd_prune(args):
    lessons = ftc.load_lessons()
    before = len(lessons)
    lessons, removed = ftc.prune_stale_lessons(lessons, max_age_days=args.days)
    if removed > 0:
        ftc.save_lessons(lessons)
    print(f"pruned {removed} stale lessons ({before} -> {len(lessons)})")

def main():
    parser = argparse.ArgumentParser(prog="fleet-triage-lessons", description="Manage the fleet triage lesson store")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List lessons")
    g = p_list.add_mutually_exclusive_group()
    g.add_argument("--pending", action="store_true", help="Show only pending")
    g.add_argument("--auth", action="store_true", help="Show only authoritative")
    g.add_argument("--all", action="store_true", help="Show all (default)")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show full lesson detail")
    p_show.add_argument("id_prefix")
    p_show.set_defaults(func=cmd_show)

    p_promote = sub.add_parser("promote", help="Manually flip a pending lesson to authoritative")
    p_promote.add_argument("id_prefix")
    p_promote.set_defaults(func=cmd_promote)

    p_reject = sub.add_parser("reject", help="Delete a lesson")
    p_reject.add_argument("id_prefix")
    p_reject.set_defaults(func=cmd_reject)

    p_add = sub.add_parser("add", help="Interactively add a new authoritative lesson")
    p_add.set_defaults(func=cmd_add)

    p_stats = sub.add_parser("stats", help="Show summary statistics")
    p_stats.set_defaults(func=cmd_stats)

    p_prune = sub.add_parser("prune", help="Remove stale lessons older than N days")
    p_prune.add_argument("--days", type=int, default=90, help="Max age in days (default 90)")
    p_prune.set_defaults(func=cmd_prune)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        sys.exit(130)
