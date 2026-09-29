import tempfile
import unittest
from pathlib import Path
from sentinelf.scope import Scope
from sentinelf.scanner import AP
from sentinelf.store import connect, save_scan, evaluate, review_finding, list_findings, report
from sentinelf.html_report import render

class FindingTests(unittest.TestCase):
    def test_rules_triage_and_scope(self):
        with tempfile.TemporaryDirectory() as root:
            db = connect(Path(root) / "db.sqlite")
            scope = Scope("LAB", frozenset(), frozenset({"AA:BB:CC:DD:EE:FF"}))
            authorized = AP("AA:BB:CC:DD:EE:FF", "<test>", 2412, 1, -40, "Open/Unknown", (), "unknown")
            outside = AP("11:22:33:44:55:66", "OTHER", 2412, 1, -50, "WPA", (), "unknown")
            scan = save_scan(db, scope, [authorized, outside])
            found = evaluate(db, scope, scan)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["rule"], "open_or_unknown")
            review_finding(db, "LAB", found[0]["id"], "confirmed", "Validated against configuration")
            again = evaluate(db, scope, scan)
            self.assertEqual(len(again), 1)
            self.assertEqual(again[0]["status"], "confirmed")
            self.assertEqual(len(report(db, "LAB")["findings"]), 1)
            with self.assertRaises(ValueError):
                review_finding(db, "OTHER", found[0]["id"], "dismissed", "No access")
            with self.assertRaises(ValueError):
                evaluate(db, scope, scan, {"flag_open": "yes"})
            html = render(report(db, "LAB"), [])
            self.assertIn("&lt;test&gt;", html)
            db.close()

    def test_pmf_rule(self):
        with tempfile.TemporaryDirectory() as root:
            db = connect(Path(root) / "db.sqlite")
            scope = Scope("LAB", frozenset(), frozenset({"AA:BB:CC:DD:EE:FF"}))
            scan = save_scan(db, scope, [AP("AA:BB:CC:DD:EE:FF", "LAB", 2412, 1, -40, "WPA2", (), "capable")])
            result = evaluate(db, scope, scan, {"flag_open": False, "flag_legacy_wpa": False, "require_pmf": True})
            self.assertEqual(result[0]["rule"], "pmf_not_required")
            db.close()
