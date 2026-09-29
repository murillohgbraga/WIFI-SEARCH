import hashlib
import json
import sqlite3
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, engagement TEXT NOT NULL, observed_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS observations(scan_id INTEGER NOT NULL REFERENCES scans(id), bssid TEXT NOT NULL, ssid TEXT NOT NULL, data TEXT NOT NULL, in_scope INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, scan_id INTEGER REFERENCES scans(id), path TEXT NOT NULL, sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS baselines(engagement TEXT PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id), created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, engagement TEXT NOT NULL, scan_id INTEGER NOT NULL REFERENCES scans(id), bssid TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL, detail TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','confirmed','dismissed')), note TEXT NOT NULL DEFAULT '', reviewed_at TEXT, UNIQUE(scan_id,bssid,rule));
    """)
    return db


def event(db, action, detail):
    db.execute("INSERT INTO events(at,action,detail) VALUES(?,?,?)", (now(), action, detail))


def save_scan(db, scope, aps):
    with db:
        cursor = db.execute("INSERT INTO scans(engagement,observed_at) VALUES(?,?)", (scope.engagement, now()))
        scan_id = cursor.lastrowid
        for ap in aps:
            db.execute("INSERT INTO observations VALUES(?,?,?,?,?)", (scan_id, ap.bssid, ap.ssid, json.dumps(ap.record(), sort_keys=True), int(scope.allows(ap.ssid, ap.bssid))))
        event(db, "scan", json.dumps({"scan_id": scan_id, "count": len(aps)}))
    return scan_id


def changes(db, engagement, scan_id):
    rows = db.execute("SELECT id FROM scans WHERE engagement=? AND id<? ORDER BY id DESC LIMIT 1", (engagement, scan_id)).fetchone()
    if not rows:
        return []
    def snapshot(id_):
        return {bssid: json.loads(data) for bssid, data in db.execute("SELECT bssid,data FROM observations WHERE scan_id=?", (id_,))}
    old, new = snapshot(rows[0]), snapshot(scan_id)
    changes_ = []
    for key in sorted(old.keys() | new.keys()):
        if key not in old:
            changes_.append({"bssid": key, "type": "new"})
        elif key not in new:
            changes_.append({"bssid": key, "type": "missing"})
        else:
            for field in ("ssid", "channel", "security", "pmf"):
                if old[key][field] != new[key][field]:
                    changes_.append({"bssid": key, "type": "changed", "field": field, "before": old[key][field], "after": new[key][field]})
    return changes_


def add_evidence(db, file, scan_id=None):
    file = Path(file).resolve(strict=True)
    if not file.is_file():
        raise ValueError("Evidence must be a regular file")
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    with db:
        cursor = db.execute("INSERT INTO evidence(scan_id,path,sha256,recorded_at) VALUES(?,?,?,?)", (scan_id, str(file), digest.hexdigest(), now()))
        event(db, "evidence", json.dumps({"id": cursor.lastrowid, "sha256": digest.hexdigest()}))
    return cursor.lastrowid, digest.hexdigest()


def import_evidence(db, file, vault, scan_id):
    """Copy evidence into a private vault, then register its digest."""
    source = Path(file)
    if source.is_symlink() or not source.is_file():
        raise ValueError("Evidence source must be a regular non-symlink file")
    if not db.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone():
        raise ValueError("Unknown scan ID")
    vault = Path(vault)
    vault.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Avoid a user-supplied filename becoming part of the stored path.
    dest = vault / (uuid.uuid4().hex + ".bin")
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=vault, prefix=".incoming-", delete=False) as out:
            temp = Path(out.name)
            with source.open("rb") as incoming:
                shutil.copyfileobj(incoming, out, 1024 * 1024)
        temp.chmod(0o600)
        temp.replace(dest)
        temp = None
        try:
            return add_evidence(db, dest, scan_id)
        except Exception:
            dest.unlink(missing_ok=True)
            raise
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def verify_evidence(db, engagement=None):
    query = "SELECT e.id,e.path,e.sha256,e.scan_id FROM evidence e"
    params = ()
    if engagement is not None:
        query += " JOIN scans s ON e.scan_id=s.id WHERE s.engagement=?"
        params = (engagement,)
    items = []
    for id_, path, expected, scan_id in db.execute(query + " ORDER BY e.id", params):
        file = Path(path)
        if not file.is_file():
            status = "missing"
        else:
            digest = hashlib.sha256()
            try:
                with file.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                status = "verified" if digest.hexdigest() == expected else "mismatch"
            except OSError:
                status = "unreadable"
        items.append({"id": id_, "scan_id": scan_id, "sha256": expected, "status": status})
    return items


def report(db, engagement):
    scans = db.execute("SELECT id,observed_at FROM scans WHERE engagement=? ORDER BY id", (engagement,)).fetchall()
    return {"schema": 2, "engagement": engagement, "scans": [{"id": id_, "observed_at": at, "observations": [dict(json.loads(data), in_scope=bool(allowed)) for data, allowed in db.execute("SELECT data,in_scope FROM observations WHERE scan_id=? ORDER BY bssid", (id_,))], "changes": changes(db, engagement, id_)} for id_, at in scans], "evidence": [dict(id=id_, sha256=hash_, recorded_at=at) for id_, hash_, at in db.execute("SELECT id,sha256,recorded_at FROM evidence WHERE scan_id IN (SELECT id FROM scans WHERE engagement=?) ORDER BY id", (engagement,))], "findings": list_findings(db, engagement)}


DEFAULT_RULES = {"flag_open": True, "flag_legacy_wpa": True, "require_pmf": False}


def validate_rules(data):
    if not isinstance(data, dict) or set(data) != set(DEFAULT_RULES) or any(type(value) is not bool for value in data.values()):
        raise ValueError("Rules must contain exactly flag_open, flag_legacy_wpa, require_pmf as booleans")
    return data


def evaluate(db, scope, scan_id, rules=None):
    rules = validate_rules(DEFAULT_RULES.copy() if rules is None else rules)
    if not db.execute("SELECT 1 FROM scans WHERE id=? AND engagement=?", (scan_id, scope.engagement)).fetchone():
        raise ValueError("Scan does not belong to this engagement")
    candidates = []
    for bssid, data in db.execute("SELECT bssid,data FROM observations WHERE scan_id=? AND in_scope=1", (scan_id,)):
        ap = json.loads(data)
        if rules["flag_open"] and ap["security"] == "Open/Unknown":
            candidates.append((bssid, "open_or_unknown", "review", "No supported security suite recognized in iw output"))
        if rules["flag_legacy_wpa"] and ap["security"] == "WPA":
            candidates.append((bssid, "legacy_wpa", "review", "Legacy WPA suite observed"))
        if rules["require_pmf"] and ap["pmf"] == "capable":
            candidates.append((bssid, "pmf_not_required", "review", "PMF capable but not reported as required"))
    with db:
        for bssid, rule, severity, detail in candidates:
            db.execute("INSERT OR IGNORE INTO findings(engagement,scan_id,bssid,rule,severity,detail) VALUES(?,?,?,?,?,?)", (scope.engagement, scan_id, bssid, rule, severity, detail))
        event(db, "evaluate", json.dumps({"engagement": scope.engagement, "scan_id": scan_id, "candidates": len(candidates)}))
    return list_findings(db, scope.engagement, scan_id)


def list_findings(db, engagement, scan_id=None):
    query = "SELECT id,scan_id,bssid,rule,severity,detail,status,note,reviewed_at FROM findings WHERE engagement=?"
    params = [engagement]
    if scan_id is not None:
        query += " AND scan_id=?"
        params.append(scan_id)
    return [dict(zip(("id", "scan_id", "bssid", "rule", "severity", "detail", "status", "note", "reviewed_at"), row)) for row in db.execute(query + " ORDER BY id", params)]


def review_finding(db, engagement, finding_id, status, note):
    if status not in ("confirmed", "dismissed", "open") or not note.strip() or len(note) > 2000:
        raise ValueError("Review requires a valid status and a note of 1–2000 characters")
    with db:
        cursor = db.execute("UPDATE findings SET status=?,note=?,reviewed_at=? WHERE id=? AND engagement=?", (status, note.strip(), now(), finding_id, engagement))
        if cursor.rowcount != 1:
            raise ValueError("Finding not found in this engagement")
        event(db, "review", json.dumps({"engagement": engagement, "finding_id": finding_id, "status": status}))


def set_baseline(db, engagement, scan_id):
    row = db.execute("SELECT id FROM scans WHERE id=? AND engagement=?", (scan_id, engagement)).fetchone()
    if not row:
        raise ValueError("Scan does not belong to this engagement")
    count = db.execute("SELECT count(*) FROM observations WHERE scan_id=? AND in_scope=1", (scan_id,)).fetchone()[0]
    if not count:
        raise ValueError("Baseline requires at least one authorized AP")
    with db:
        db.execute("INSERT INTO baselines VALUES(?,?,?) ON CONFLICT(engagement) DO UPDATE SET scan_id=excluded.scan_id,created_at=excluded.created_at", (engagement, scan_id, now()))
        event(db, "baseline", json.dumps({"engagement": engagement, "scan_id": scan_id}))


def alerts(db, scope, scan_id):
    baseline = db.execute("SELECT scan_id FROM baselines WHERE engagement=?", (scope.engagement,)).fetchone()
    if not baseline:
        raise ValueError("No baseline selected for this engagement")
    if not db.execute("SELECT 1 FROM scans WHERE id=? AND engagement=?", (scan_id, scope.engagement)).fetchone():
        raise ValueError("Scan does not belong to this engagement")
    def rows(id_):
        return {bssid: json.loads(data) for bssid, data in db.execute("SELECT bssid,data FROM observations WHERE scan_id=? AND in_scope=1", (id_,))}
    expected, observed = rows(baseline[0]), rows(scan_id)
    findings = []
    for bssid, ap in sorted(expected.items()):
        if bssid not in observed:
            findings.append({"severity": "info", "kind": "not_observed", "bssid": bssid})
            continue
        current = observed[bssid]
        for field in ("ssid", "security", "pmf", "channel"):
            if ap[field] != current[field]:
                findings.append({"severity": "review", "kind": "attribute_changed", "bssid": bssid, "field": field, "expected": ap[field], "observed": current[field]})
    for bssid, ap in sorted(observed.items()):
        if bssid not in expected:
            findings.append({"severity": "review", "kind": "new_authorized_bssid", "bssid": bssid})
    known_ssids = {ap["ssid"] for ap in expected.values() if ap["ssid"]}
    for bssid, data in db.execute("SELECT bssid,data FROM observations WHERE scan_id=? AND in_scope=0", (scan_id,)):
        ap = json.loads(data)
        if ap["ssid"] in known_ssids:
            findings.append({"severity": "review", "kind": "same_ssid_unknown_bssid", "bssid": bssid, "ssid": ap["ssid"]})
    return findings
