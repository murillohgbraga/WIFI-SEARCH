import sqlite3
import tempfile
import unittest
from pathlib import Path
from sentinelf.store import connect

class MigrationTests(unittest.TestCase):
    def test_old_database_adds_tables_without_losing_scans(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "old.sqlite3"
            old = sqlite3.connect(path)
            old.execute("CREATE TABLE scans(id INTEGER PRIMARY KEY, engagement TEXT NOT NULL, observed_at TEXT NOT NULL)")
            old.execute("INSERT INTO scans(engagement,observed_at) VALUES('LAB','2026-01-01')")
            old.commit()
            old.close()
            current = connect(path)
            self.assertEqual(current.execute("SELECT count(*) FROM scans").fetchone()[0], 1)
            self.assertIsNotNone(current.execute("SELECT name FROM sqlite_master WHERE name='findings'").fetchone())
            current.close()
