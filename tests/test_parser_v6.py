import unittest
from pathlib import Path
from sentinelf.scanner import parse_iw, frequency_channel

class ParserTests(unittest.TestCase):
    def test_variants(self):
        aps = parse_iw((Path(__file__).parent / "fixtures/iw_variants.txt").read_text())
        self.assertEqual(len(aps), 4)
        self.assertEqual([(ap.security, ap.channel, ap.pmf) for ap in aps], [
            ("WPA2/WPA3-Transition", 36, "capable"),
            ("OWE", 5, "required"),
            ("WPA2-Enterprise", 1, "capable"),
            ("Open/Unknown", 14, "unknown")])
        self.assertEqual(aps[3].ssid, "")
        self.assertIsNone(frequency_channel(1234))
