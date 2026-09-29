"""Self-contained, escaped HTML rendering of local inventory data."""
from html import escape


def render(data, findings):
    e = lambda value: escape(str(value), quote=True)
    rows = []
    for scan in data["scans"]:
        for ap in scan["observations"]:
            rows.append("<tr>" + "".join(f"<td>{e(value)}</td>" for value in (
                scan["id"], scan["observed_at"], ap["bssid"], ap["ssid"],
                ap["channel"], ap["signal_dbm"], ap["security"], ap["pmf"],
                "yes" if ap["in_scope"] else "no")) + "</tr>")
    alert_rows = ["<tr>" + "".join(f"<td>{e(value)}</td>" for value in (
        item["severity"], item["kind"], item["bssid"], item.get("field", ""),
        item.get("expected", ""), item.get("observed", ""))) + "</tr>" for item in findings]
    evidence = [f"<li>EV-{item['id']:06d}: SHA-256 {e(item['sha256'])}</li>" for item in data["evidence"]]
    findings = ["<tr>" + "".join(f"<td>{e(value)}</td>" for value in (item["id"], item["scan_id"], item["bssid"], item["rule"], item["status"], item["note"])) + "</tr>" for item in data.get("findings", [])]
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelRF — {e(data['engagement'])}</title><style>body{{font:16px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#162334;background:#f7f9fc}}h1,h2{{color:#163e67}}table{{border-collapse:collapse;width:100%;background:white}}th,td{{padding:.55rem;border:1px solid #cad4e0;text-align:left}}th{{background:#e7eff8}}section{{overflow-x:auto;margin:2rem 0}}small{{color:#586779}}</style></head><body><h1>SentinelRF: {e(data['engagement'])}</h1><small>Inventory observations; alerts require analyst validation. No credential material is included.</small><section><h2>Rule findings</h2><table><thead><tr><th>ID</th><th>Scan</th><th>BSSID</th><th>Rule</th><th>Status</th><th>Analyst note</th></tr></thead><tbody>{''.join(findings)}</tbody></table></section><section><h2>Baseline alerts</h2><table><thead><tr><th>Severity</th><th>Type</th><th>BSSID</th><th>Field</th><th>Expected</th><th>Observed</th></tr></thead><tbody>{''.join(alert_rows)}</tbody></table></section><section><h2>Access points</h2><table><thead><tr><th>Scan</th><th>UTC</th><th>BSSID</th><th>SSID</th><th>Channel</th><th>dBm</th><th>Security</th><th>PMF</th><th>Scope</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section><section><h2>Evidence hashes</h2><ul>{''.join(evidence)}</ul></section></body></html>'''
