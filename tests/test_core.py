import tempfile
import unittest
from pathlib import Path
from sentinelf.scope import Scope, mac
from sentinelf.scanner import parse_iw
from sentinelf.store import connect, save_scan, changes, report, add_evidence

SAMPLE = '''BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tfreq: 2412
\tsignal: -42.00 dBm
\tSSID: LAB-WIFI
\tDS Parameter set: channel 1
\tRSN:
\t\tAuthentication suites: PSK
\t\tManagement frame protection capable
'''

class CoreTests(unittest.TestCase):
    def test_parse_and_scope(self):
        ap = parse_iw(SAMPLE)[0]
        self.assertEqual((ap.channel, ap.security, ap.pmf), (1, "WPA2", "capable"))
        scope = Scope("LAB", frozenset({"LAB-WIFI"}), frozenset({mac("aa:bb:cc:dd:ee:ff")}))
        self.assertTrue(scope.allows(ap.ssid, ap.bssid))
        self.assertFalse(scope.allows("LAB-WIFI", "11:22:33:44:55:66"))

    def test_history_report_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            db = connect(Path(temp) / "state.sqlite")
            scope = Scope("LAB", frozenset(), frozenset({"AA:BB:CC:DD:EE:FF"}))
            first = save_scan(db, scope, parse_iw(SAMPLE))
            second = save_scan(db, scope, parse_iw(SAMPLE.replace("channel 1", "channel 6")))
            self.assertEqual(changes(db, "LAB", second)[0]["field"], "channel")
            file = Path(temp) / "sample.txt"
            file.write_bytes(b"sample")
            _, digest = add_evidence(db, file, second)
            self.assertEqual(len(digest), 64)
            self.assertEqual(len(report(db, "LAB")["scans"]), 2)
            db.close()

if __name__ == "__main__":
    unittest.main()
