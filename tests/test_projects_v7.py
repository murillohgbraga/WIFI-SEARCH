import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile
from sentinelf.projects import init_project, export_project
from sentinelf.scope import load
from sentinelf.scanner import AP
from sentinelf.store import connect, save_scan, evaluate

class ProjectTests(unittest.TestCase):
    def test_init_and_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "client"
            init_project(root, "LAB-001", ["aa:bb:cc:dd:ee:ff"])
            self.assertEqual(load(root / "scope.json").engagement, "LAB-001")
            with self.assertRaises(ValueError):
                init_project(root, "LAB-001", ["AA:BB:CC:DD:EE:FF"])
            db = connect(root / ".sentinelf/state.sqlite3")
            scope = load(root / "scope.json")
            scan = save_scan(db, scope, [AP("AA:BB:CC:DD:EE:FF", "LAB", 2412, 1, -40, "Open/Unknown", (), "unknown")])
            evaluate(db, scope, scan)
            db.close()
            bundle = root / "exports/report.zip"
            export_project(root, bundle)
            with ZipFile(bundle) as archive:
                self.assertEqual(set(archive.namelist()), {"report.json", "report.html", "evidence-manifest.json", "README.txt"})
                data = json.loads(archive.read("report.json"))
                self.assertEqual(len(data["findings"]), 1)
                self.assertNotIn("state.sqlite3", archive.namelist())
            with self.assertRaises(ValueError):
                export_project(root, bundle)
