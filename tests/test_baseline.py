import tempfile
import unittest
from pathlib import Path
from sentinelf.scope import Scope
from sentinelf.scanner import AP
from sentinelf.store import connect, save_scan, set_baseline, alerts, report
from sentinelf.html_report import render

class BaselineTests(unittest.TestCase):
    def test_alerts_and_html_escaping(self):
        with tempfile.TemporaryDirectory() as temp:
            db = connect(Path(temp) / "db.sqlite")
            scope = Scope("LAB", frozenset(), frozenset({"AA:BB:CC:DD:EE:FF"}))
            original = AP("AA:BB:CC:DD:EE:FF", "LAB", 2412, 1, -40, "WPA2", ("PSK",), "capable")
            first = save_scan(db, scope, [original])
            set_baseline(db, "LAB", first)
            changed = AP("AA:BB:CC:DD:EE:FF", "LAB", 2412, 1, -40, "Open/Unknown", (), "unknown")
            unknown = AP("11:22:33:44:55:66", "LAB", 2412, 1, -50, "Open/Unknown", (), "unknown")
            second = save_scan(db, scope, [changed, unknown])
            result = alerts(db, scope, second)
            self.assertEqual({x["kind"] for x in result}, {"attribute_changed", "same_ssid_unknown_bssid"})
            self.assertTrue(any(x.get("field") == "security" for x in result))
            self.assertRaises(ValueError, set_baseline, db, "OTHER", first)
            html = render(dict(report(db, "LAB"), engagement="<script>alert(1)</script>"), result)
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)
            db.close()

if __name__ == "__main__":
    unittest.main()
