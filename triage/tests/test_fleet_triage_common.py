"""Unit tests for fleet_triage_common. Run with:
    python3 -m unittest /tmp/test_ftc.py -v
"""
import sys
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "/usr/local/lib")
import fleet_triage_common as ftc


class LessonIdTests(unittest.TestCase):
    def test_same_inputs_same_id(self):
        p = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo", "bar"]}
        c = {"severity": "noise", "action": "log"}
        self.assertEqual(ftc.lesson_id_for(p, c), ftc.lesson_id_for(p, c))

    def test_keyword_order_invariant(self):
        p1 = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo", "bar"]}
        p2 = {"rule_id": "510", "agent": "pi0", "log_keywords": ["bar", "foo"]}
        c = {"severity": "noise", "action": "log"}
        self.assertEqual(ftc.lesson_id_for(p1, c), ftc.lesson_id_for(p2, c))

    def test_keyword_case_invariant(self):
        p1 = {"rule_id": "510", "agent": "pi0", "log_keywords": ["FOO", "Bar"]}
        p2 = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo", "bar"]}
        c = {"severity": "noise", "action": "log"}
        self.assertEqual(ftc.lesson_id_for(p1, c), ftc.lesson_id_for(p2, c))

    def test_different_pattern_different_id(self):
        p1 = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo"]}
        p2 = {"rule_id": "511", "agent": "pi0", "log_keywords": ["foo"]}
        c = {"severity": "noise", "action": "log"}
        self.assertNotEqual(ftc.lesson_id_for(p1, c), ftc.lesson_id_for(p2, c))

    def test_different_classification_different_id(self):
        p = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo"]}
        c1 = {"severity": "noise", "action": "log"}
        c2 = {"severity": "high", "action": "investigate"}
        self.assertNotEqual(ftc.lesson_id_for(p, c1), ftc.lesson_id_for(p, c2))


class MatchLessonTests(unittest.TestCase):
    def setUp(self):
        self.lesson_auth = {
            "lesson_id": "abc123",
            "status": "authoritative",
            "pattern": {
                "rule_id": "510",
                "agent": "pi0",
                "log_keywords": ["trojaned version", "generic"],
            },
            "classification": {"severity": "noise", "action": "log"},
        }
        self.lesson_pending = dict(self.lesson_auth)
        self.lesson_pending["status"] = "pending"
        self.lesson_pending = {**self.lesson_auth, "status": "pending", "lesson_id": "def456"}

    def test_matches_when_keywords_present(self):
        alert = {
            "rule_id": "510",
            "agent": "pi0",
            "full_log": "Trojaned version of file '/bin/echo' detected. Signature: bash (Generic).",
        }
        self.assertEqual(ftc.match_lesson(alert, [self.lesson_auth]), self.lesson_auth)

    def test_keyword_matching_is_case_insensitive(self):
        alert = {
            "rule_id": "510",
            "agent": "pi0",
            "full_log": "TROJANED VERSION OF /bin/cat detected (GENERIC)",
        }
        self.assertEqual(ftc.match_lesson(alert, [self.lesson_auth]), self.lesson_auth)

    def test_no_match_when_agent_differs(self):
        alert = {
            "rule_id": "510",
            "agent": "pi1",
            "full_log": "Trojaned version of file detected (Generic)",
        }
        self.assertIsNone(ftc.match_lesson(alert, [self.lesson_auth]))

    def test_no_match_when_rule_id_differs(self):
        alert = {
            "rule_id": "999",
            "agent": "pi0",
            "full_log": "Trojaned version of file detected (Generic)",
        }
        self.assertIsNone(ftc.match_lesson(alert, [self.lesson_auth]))

    def test_no_match_when_keywords_missing(self):
        alert = {
            "rule_id": "510",
            "agent": "pi0",
            "full_log": "some other event entirely",
        }
        self.assertIsNone(ftc.match_lesson(alert, [self.lesson_auth]))

    def test_partial_keyword_match_fails(self):
        # one of the two required keywords is missing
        alert = {
            "rule_id": "510",
            "agent": "pi0",
            "full_log": "Trojaned version of file detected",  # missing 'generic'
        }
        self.assertIsNone(ftc.match_lesson(alert, [self.lesson_auth]))

    def test_pending_lessons_skipped_by_default(self):
        alert = {
            "rule_id": "510",
            "agent": "pi0",
            "full_log": "Trojaned version (Generic)",
        }
        self.assertIsNone(ftc.match_lesson(alert, [self.lesson_pending]))

    def test_status_none_returns_pending(self):
        alert = {
            "rule_id": "510",
            "agent": "pi0",
            "full_log": "Trojaned version (Generic)",
        }
        self.assertIsNotNone(ftc.match_lesson(alert, [self.lesson_pending], status=None))

    def test_empty_keywords_matches_on_rule_and_agent_only(self):
        broad = {
            "lesson_id": "broad",
            "status": "authoritative",
            "pattern": {"rule_id": "510", "agent": "pi0", "log_keywords": []},
            "classification": {"severity": "low", "action": "log"},
        }
        alert = {"rule_id": "510", "agent": "pi0", "full_log": "anything"}
        self.assertEqual(ftc.match_lesson(alert, [broad]), broad)


class IngestLessonTests(unittest.TestCase):
    def test_ingest_creates_pending(self):
        lessons = []
        result = ftc.ingest_lesson(
            lessons,
            pattern={"rule_id": "510", "agent": "pi0", "log_keywords": ["foo"]},
            classification={"severity": "noise", "action": "log"},
            reason="test",
        )
        self.assertEqual(len(lessons), 1)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["promotion_count"], 1)

    def test_ingest_increments_existing(self):
        lessons = []
        p = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo"]}
        c = {"severity": "noise", "action": "log"}
        ftc.ingest_lesson(lessons, p, c)
        ftc.ingest_lesson(lessons, p, c)
        ftc.ingest_lesson(lessons, p, c)
        self.assertEqual(len(lessons), 1)
        self.assertEqual(lessons[0]["promotion_count"], 3)

    def test_ingest_different_classification_creates_new(self):
        lessons = []
        p = {"rule_id": "510", "agent": "pi0", "log_keywords": ["foo"]}
        ftc.ingest_lesson(lessons, p, {"severity": "noise", "action": "log"})
        ftc.ingest_lesson(lessons, p, {"severity": "high", "action": "investigate"})
        self.assertEqual(len(lessons), 2)
        ids = {l["lesson_id"] for l in lessons}
        self.assertEqual(len(ids), 2)


class PromoteEligibleTests(unittest.TestCase):
    def test_promotes_at_threshold(self):
        lessons = [
            {"lesson_id": "a", "status": "pending", "promotion_count": 3, "promotion_threshold": 3},
            {"lesson_id": "b", "status": "pending", "promotion_count": 2, "promotion_threshold": 3},
            {"lesson_id": "c", "status": "pending", "promotion_count": 5, "promotion_threshold": 3},
            {"lesson_id": "d", "status": "authoritative", "promotion_count": 10, "promotion_threshold": 3},
        ]
        promoted = ftc.promote_eligible(lessons)
        self.assertEqual(promoted, 2)
        self.assertEqual(lessons[0]["status"], "authoritative")
        self.assertEqual(lessons[1]["status"], "pending")
        self.assertEqual(lessons[2]["status"], "authoritative")
        self.assertEqual(lessons[3]["status"], "authoritative")
        self.assertIsNotNone(lessons[0]["last_promoted_at"])


class SaveLoadTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.original_path = ftc.LESSONS_FILE
        ftc.LESSONS_FILE = Path(self.tmpdir) / "lessons.jsonl"

    def tearDown(self):
        ftc.LESSONS_FILE = self.original_path

    def test_round_trip(self):
        lessons = []
        ftc.ingest_lesson(
            lessons,
            pattern={"rule_id": "510", "agent": "pi0", "log_keywords": ["foo", "bar"]},
            classification={"severity": "noise", "action": "log"},
            reason="test reason",
        )
        ftc.save_lessons(lessons)
        loaded = ftc.load_lessons()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["pattern"]["rule_id"], "510")
        self.assertEqual(loaded[0]["classification"]["severity"], "noise")

    def test_save_atomic_no_partial_file_on_exception(self):
        # Write a known-good state, then attempt a save with bogus data that
        # would fail json serialization. The original file should still be
        # readable afterwards.
        good = []
        ftc.ingest_lesson(
            good,
            pattern={"rule_id": "510", "agent": "pi0", "log_keywords": ["foo"]},
            classification={"severity": "low", "action": "log"},
        )
        ftc.save_lessons(good)
        original_size = ftc.LESSONS_FILE.stat().st_size

        # Try to save something that breaks json (a set is not JSON serializable)
        with self.assertRaises(TypeError):
            ftc.save_lessons([{"bad": {1, 2, 3}}])

        # Original file untouched
        self.assertEqual(ftc.LESSONS_FILE.stat().st_size, original_size)
        loaded = ftc.load_lessons()
        self.assertEqual(len(loaded), 1)

    def test_load_missing_file_returns_empty(self):
        ftc.LESSONS_FILE = Path(self.tmpdir) / "nonexistent.jsonl"
        self.assertEqual(ftc.load_lessons(), [])

    def test_load_skips_corrupt_lines(self):
        ftc.LESSONS_FILE.write_text(
            '{"lesson_id":"a","status":"pending","promotion_count":1}\n'
            'this is not json\n'
            '{"lesson_id":"b","status":"pending","promotion_count":1}\n'
        )
        loaded = ftc.load_lessons()
        self.assertEqual(len(loaded), 2)


class NormalizationTests(unittest.TestCase):
    def test_severity_token(self):
        self.assertEqual(ftc.normalize_severity("HIGH"), "high")
        self.assertEqual(ftc.normalize_severity("[critical]"), "critical")
        self.assertEqual(ftc.normalize_severity("noise!"), "noise")
        self.assertIsNone(ftc.normalize_severity("root"))
        self.assertIsNone(ftc.normalize_severity(""))
        self.assertIsNone(ftc.normalize_severity(None))

    def test_action_token(self):
        self.assertEqual(ftc.normalize_action("Investigate"), "investigate")
        self.assertEqual(ftc.normalize_action("ESCALATE NOW"), "escalate")
        self.assertIsNone(ftc.normalize_action("execute"))
        self.assertIsNone(ftc.normalize_action(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class WhitespaceMatchingTests(unittest.TestCase):
    """Regression: Wazuh logs use tab and multi-space alignment, but Gemma
    extracts keywords with single spaces. Both sides must normalize."""
    def setUp(self):
        self.lesson = {
            "lesson_id": "ws01",
            "status": "authoritative",
            "pattern": {
                "rule_id": "533",
                "agent": "pi0",
                "log_keywords": ["netstat listening ports", "tcp6 0 0 :::2049"],
            },
            "classification": {"severity": "low", "action": "log"},
        }

    def test_matches_alert_with_tab_alignment(self):
        alert = {
            "rule_id": "533",
            "agent": "pi0",
            "full_log": "ossec: output: 'netstat listening ports':\ntcp6       0      0 :::2049                 :::*",
        }
        self.assertEqual(ftc.match_lesson(alert, [self.lesson]), self.lesson)

    def test_keyword_with_internal_whitespace_normalizes(self):
        broken = dict(self.lesson)
        broken["pattern"] = dict(self.lesson["pattern"])
        broken["pattern"]["log_keywords"] = ["tcp6\t0\t0\t:::2049"]
        alert = {
            "rule_id": "533",
            "agent": "pi0",
            "full_log": "tcp6 0 0 :::2049 LISTEN",
        }
        self.assertEqual(ftc.match_lesson(alert, [broken]), broken)
