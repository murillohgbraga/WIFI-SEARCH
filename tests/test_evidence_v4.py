import tempfile
import unittest
from pathlib import Path
from sentinelf.scanner import AP
from sentinelf.scope import Scope
from sentinelf.store import connect, save_scan, import_evidence, verify_evidence

class EvidenceTests(unittest.TestCase):
    def test_copy_verify_tamper_and_missing(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            db = connect(root / "state.sqlite")
            scope = Scope("LAB", frozenset(), frozenset({"AA:BB:CC:DD:EE:FF"}))
            scan = save_scan(db, scope, [AP("AA:BB:CC:DD:EE:FF", "LAB", 2412, 1, -40, "WPA2", (), "unknown")])
            original = root / "capture.pcapng"
            original.write_bytes(b"test capture")
            id_, digest = import_evidence(db, original, root / "vault", scan)
            stored = Path(db.execute("SELECT path FROM evidence WHERE id=?", (id_,)).fetchone()[0])
            original.write_bytes(b"different")
            self.assertEqual(verify_evidence(db, "LAB")[0]["status"], "verified")
            self.assertEqual(len(digest), 64)
            stored.write_bytes(b"tampered")
            self.assertEqual(verify_evidence(db, "LAB")[0]["status"], "mismatch")
            stored.unlink()
            self.assertEqual(verify_evidence(db, "LAB")[0]["status"], "missing")
            self.assertEqual(verify_evidence(db, "OTHER"), [])
            db.close()

    def test_reject_symlink_and_unknown_scan(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            db = connect(root / "state.sqlite")
            original = root / "original"
            original.write_bytes(b"x")
            link = root / "link"
            link.symlink_to(original)
            with self.assertRaises(ValueError):
                import_evidence(db, link, root / "vault", 1)
            with self.assertRaises(ValueError):
                import_evidence(db, original, root / "vault", 1)
            db.close()
