"""Project setup and portable, redacted-path report bundle."""
import json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from .scope import mac, load
from .store import connect, report, alerts, verify_evidence
from .html_report import render


def init_project(path, engagement, bssids):
    root = Path(path)
    if root.exists():
        raise ValueError("Project path already exists")
    if not engagement.strip() or not bssids:
        raise ValueError("Engagement and at least one authorized BSSID are required")
    normalized = sorted({mac(value) for value in bssids})
    root.mkdir(parents=True)
    (root / ".sentinelf").mkdir(mode=0o700)
    (root / "scope.json").write_text(json.dumps({"engagement": engagement, "authorized": {"ssids": [], "bssids": normalized}}, indent=2) + "\n", encoding="utf-8")
    (root / "rules.json").write_text(json.dumps({"flag_open": True, "flag_legacy_wpa": True, "require_pmf": False}, indent=2) + "\n", encoding="utf-8")
    (root / ".gitignore").write_text(".sentinelf/\nexports/\n*.pcap\n*.pcapng\n", encoding="utf-8")
    db = connect(root / ".sentinelf/state.sqlite3")
    db.close()
    return root


def export_project(root, output):
    root, output = Path(root), Path(output)
    scope = load(root / "scope.json")
    database = root / ".sentinelf/state.sqlite3"
    if not database.is_file():
        raise ValueError("Project database is missing")
    db = connect(database)
    try:
        data = report(db, scope.engagement)
        if not data["scans"]:
            raise ValueError("Project has no scans")
        latest = data["scans"][-1]["id"]
        try:
            baseline_alerts = alerts(db, scope, latest)
        except ValueError as exc:
            if str(exc) != "No baseline selected for this engagement":
                raise
            baseline_alerts = []
        manifest = {"schema": 1, "engagement": scope.engagement, "evidence": verify_evidence(db, scope.engagement)}
        html = render(data, baseline_alerts)
    finally:
        db.close()
    if output.resolve().is_relative_to(root.resolve() / ".sentinelf"):
        raise ValueError("Export cannot be placed in the private project state directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError("Export already exists")
    with ZipFile(output, "x", compression=ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        archive.writestr("report.html", html)
        archive.writestr("evidence-manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        archive.writestr("README.txt", "SentinelRF report bundle. Contains sensitive wireless inventory and analyst notes. No PCAP, raw evidence, or SQLite database. Verify hashes against separately retained evidence.\n")
    return output
