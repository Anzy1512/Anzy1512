import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detector import EventError, analyze, load_jsonl, parse_event


BASE = {
    "timestamp": "2026-10-01T09:00:00Z", "host": "vpn-01", "user": "alice",
    "src_ip": "203.0.113.10", "event_type": "authentication", "outcome": "failure"
}


def event(minute, *, user="alice", ip="203.0.113.10", outcome="failure"):
    raw = dict(BASE, timestamp=f"2026-10-01T09:{minute:02d}:00Z", user=user,
               src_ip=ip, outcome=outcome)
    return parse_event(raw)


class DetectionTests(unittest.TestCase):
    def test_demo_generates_three_expected_alerts(self):
        path = Path(__file__).parents[1] / "data" / "auth_events.jsonl"
        findings = analyze(load_jsonl(path))
        self.assertEqual([a["rule"] for a in findings], [
            "repeated_login_failures", "success_after_failures", "possible_password_spray"])
        self.assertEqual(findings[1]["severity"], "high")

    def test_fewer_than_five_failures_not_bruteforce(self):
        self.assertEqual(analyze([event(i) for i in range(4)]), [])

    def test_failures_outside_five_minute_window_not_bruteforce(self):
        self.assertEqual(analyze([event(i) for i in (0, 3, 6, 9, 12)]), [])

    def test_success_after_failures_is_not_implied_compromise(self):
        findings = analyze([event(i) for i in range(3)] + [event(4, outcome="success")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "success_after_failures")

    def test_single_account_no_spray(self):
        findings = analyze([event(i) for i in range(5)])
        self.assertEqual([a["rule"] for a in findings], ["repeated_login_failures"])

    def test_distinct_users_trigger_spray(self):
        users = ["a", "b", "c", "a", "b"]
        findings = analyze([event(i, user=u) for i, u in enumerate(users)])
        self.assertEqual([a["rule"] for a in findings], ["possible_password_spray"])

    def test_duplicate_failures_trigger_one_group_alert(self):
        findings = analyze([event(i) for i in range(9)])
        self.assertEqual(len(findings), 1)

    def test_invalid_input_has_line_number(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "log.jsonl"
            p.write_text(json.dumps(BASE) + "\nnot json\n", encoding="utf-8")
            with self.assertRaisesRegex(EventError, "line 2"):
                load_jsonl(p)

    def test_reject_naive_timestamp(self):
        with self.assertRaisesRegex(EventError, "timestamp"):
            parse_event(dict(BASE, timestamp="2026-10-01T09:00:00"))

    def test_reject_invalid_ip(self):
        with self.assertRaisesRegex(EventError, "IP"):
            parse_event(dict(BASE, src_ip="not-an-ip"))

    def test_normalizes_timezone_offsets(self):
        e = parse_event(dict(BASE, timestamp="2026-10-01T14:30:00+05:30"))
        self.assertEqual(e["_dt"].isoformat(), "2026-10-01T09:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
