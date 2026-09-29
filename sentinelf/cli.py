import argparse
import json
from pathlib import Path
from .scope import load
from .scanner import interfaces, scan, parse_iw
from .store import connect, save_scan, changes, add_evidence, import_evidence, verify_evidence, report, set_baseline, alerts, evaluate, list_findings, review_finding
from .html_report import render
from .projects import init_project, export_project


def main(argv=None):
    p = argparse.ArgumentParser(prog="sentinelf", description="SentinelRF 0.7 — scoped wireless assessment")
    p.add_argument("--db", type=Path, default=Path(".sentinelf/state.sqlite3"))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("interfaces")
    s = sub.add_parser("scope")
    s.add_argument("file", type=Path)
    s = sub.add_parser("scan")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--interface", required=True)
    s.add_argument("--input", type=Path, help="Parse a saved iw scan output without hardware")
    s = sub.add_parser("history")
    s.add_argument("--scope", type=Path, required=True)
    s = sub.add_parser("evidence")
    s.add_argument("file", type=Path)
    s.add_argument("--scan-id", type=int)
    s.add_argument("--vault", type=Path, help="Copy evidence into a private vault; requires --scan-id")
    s = sub.add_parser("verify-evidence")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--output", type=Path, help="Write a JSON verification manifest")
    s = sub.add_parser("report")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("baseline")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--scan-id", type=int, required=True)
    s = sub.add_parser("alerts")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--scan-id", type=int, required=True)
    s = sub.add_parser("report-html")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    s.add_argument("--scan-id", type=int, help="Scan to compare with baseline; defaults to latest")
    s = sub.add_parser("evaluate")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--scan-id", type=int, required=True)
    s.add_argument("--rules", type=Path, help="JSON rule configuration")
    s = sub.add_parser("findings")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--scan-id", type=int)
    s = sub.add_parser("review")
    s.add_argument("--scope", type=Path, required=True)
    s.add_argument("--finding-id", type=int, required=True)
    s.add_argument("--status", choices=("open", "confirmed", "dismissed"), required=True)
    s.add_argument("--note", required=True)
    s = sub.add_parser("project-init")
    s.add_argument("path", type=Path)
    s.add_argument("--engagement", required=True)
    s.add_argument("--bssid", action="append", required=True)
    s = sub.add_parser("project-export")
    s.add_argument("path", type=Path)
    s.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.command == "project-init":
            print(init_project(args.path, args.engagement, args.bssid))
        elif args.command == "project-export":
            print(export_project(args.path, args.output))
        elif args.command == "interfaces":
            print("\n".join(interfaces()) or "No wireless interface found")
        elif args.command == "scope":
            scope = load(args.file)
            print(json.dumps({"engagement": scope.engagement, "ssids": sorted(scope.ssids), "bssids": sorted(scope.bssids)}, indent=2))
        else:
            db = connect(args.db)
            try:
                if args.command == "scan":
                    scope = load(args.scope)
                    aps = parse_iw(args.input.read_text(encoding="utf-8")) if args.input else scan(args.interface)
                    scan_id = save_scan(db, scope, aps)
                    print(f"Scan {scan_id}: {len(aps)} APs")
                    print("BSSID             CH  SIGNAL  SECURITY          PMF       SCOPE  SSID")
                    for ap in aps:
                        print(f"{ap.bssid:17} {str(ap.channel or '-'):>3} {str(ap.signal_dbm or '-'):>7}  {ap.security:17} {ap.pmf:9} {'IN' if scope.allows(ap.ssid, ap.bssid) else 'OUT':5}  {ap.ssid}")
                    print(json.dumps(changes(db, scope.engagement, scan_id), indent=2))
                elif args.command == "history":
                    scope = load(args.scope)
                    for item in report(db, scope.engagement)["scans"]:
                        print(f"{item['id']}  {item['observed_at']}  APs={len(item['observations'])}  changes={len(item['changes'])}")
                elif args.command == "evidence":
                    if args.vault and args.scan_id is None:
                        raise ValueError("--vault requires --scan-id")
                    id_, digest = import_evidence(db, args.file, args.vault, args.scan_id) if args.vault else add_evidence(db, args.file, args.scan_id)
                    print(f"EV-{id_:06d} SHA256 {digest}")
                elif args.command == "verify-evidence":
                    scope = load(args.scope)
                    items = verify_evidence(db, scope.engagement)
                    manifest = {"schema": 1, "engagement": scope.engagement, "evidence": items}
                    payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
                    if args.output:
                        args.output.parent.mkdir(parents=True, exist_ok=True)
                        args.output.write_text(payload, encoding="utf-8")
                    else:
                        print(payload, end="")
                    if any(item["status"] != "verified" for item in items):
                        p.exit(1, "Evidence verification failed\n")
                elif args.command == "baseline":
                    scope = load(args.scope)
                    set_baseline(db, scope.engagement, args.scan_id)
                    print(f"Baseline set to scan {args.scan_id}")
                elif args.command == "alerts":
                    scope = load(args.scope)
                    print(json.dumps(alerts(db, scope, args.scan_id), indent=2, ensure_ascii=False))
                elif args.command == "evaluate":
                    scope = load(args.scope)
                    rules = json.loads(args.rules.read_text(encoding="utf-8")) if args.rules else None
                    print(json.dumps(evaluate(db, scope, args.scan_id, rules), indent=2, ensure_ascii=False))
                elif args.command == "findings":
                    scope = load(args.scope)
                    print(json.dumps(list_findings(db, scope.engagement, args.scan_id), indent=2, ensure_ascii=False))
                elif args.command == "review":
                    scope = load(args.scope)
                    review_finding(db, scope.engagement, args.finding_id, args.status, args.note)
                    print(f"Finding {args.finding_id}: {args.status}")
                elif args.command == "report-html":
                    scope = load(args.scope)
                    latest = db.execute("SELECT id FROM scans WHERE engagement=? ORDER BY id DESC LIMIT 1", (scope.engagement,)).fetchone()
                    if not latest:
                        raise ValueError("No scans for engagement")
                    findings = alerts(db, scope, args.scan_id or latest[0])
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(render(report(db, scope.engagement), findings), encoding="utf-8")
                    print(args.output)
                elif args.command == "report":
                    scope = load(args.scope)
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(report(db, scope.engagement), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    print(args.output)
            finally:
                db.close()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        p.exit(2, f"Error: {error}\n")
    except Exception as error:
        import subprocess
        if isinstance(error, subprocess.SubprocessError):
            p.exit(2, f"Scan failed: {error}\n")
        raise


if __name__ == "__main__":
    main()
