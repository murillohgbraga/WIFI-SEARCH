# SentinelRF 0.7

Python 3.11+ wireless inventory with baseline alerts and a local HTML report for authorized assessments. It reads `iw` scan results, records snapshots in SQLite, compares security/channel/SSID/PMF changes, hashes imported evidence and exports JSON. No frame injection, captive portal, password auditing or privileged helper is included. Scanning with `iw dev IFACE scan` can issue active probe requests depending on driver and configuration; use only where permitted. `--input` parses saved output without radio activity.

## Install (Kali/Linux)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
cp configs/scope.example.json scope.json
```

Edit `scope.json` to your actual engagement. The example BSSID is a placeholder. A BSSID allowlist takes precedence over SSIDs to avoid treating a spoofed SSID as authorized. Scope labels observations; it does not prevent the operating system from seeing nearby APs during inventory.

```bash
sentinelf interfaces
sentinelf scope scope.json
sentinelf scan --scope scope.json --interface wlan0
sentinelf scan --scope scope.json --interface wlan0 --input saved-iw-output.txt
sentinelf history --scope scope.json
sentinelf baseline --scope scope.json --scan-id 1
sentinelf alerts --scope scope.json --scan-id 2
sentinelf report-html --scope scope.json --output report.html
sentinelf evidence capture.pcapng --scan-id 1 --vault .sentinelf/vault
sentinelf verify-evidence --scope scope.json --output manifest.json
sentinelf evaluate --scope scope.json --scan-id 2 --rules configs/rules.example.json
sentinelf findings --scope scope.json
sentinelf review --scope scope.json --finding-id 1 --status confirmed --note "Validated with AP configuration"
sentinelf report --scope scope.json --output report.json
```

`iw` must be installed and a wireless interface available for live scanning. Driver permissions may require elevated privileges for `iw`; do not run the entire application as root when importing saved output. Reports omit evidence paths but include SHA-256. SQLite audit entries are editable by anyone with write access to the DB; this version does not provide tamper-proof chain of custody. Treat scan output and reports as potentially sensitive. No dependency downloads or auto-update happen at runtime.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The parser recognizes common `iw` RSN/WPA suite text; unusual drivers may format capabilities differently. Security and PMF classifications should be verified against raw capture before making a formal finding.

## Baseline review

Inspect a known good scan, then explicitly select its ID with `baseline`. The HTML report requires a baseline and compares the latest scan unless `--scan-id` is supplied. A same-SSID unknown-BSSID alert, missing AP, or capability change is a lead for investigation, not proof of an attack. The baseline is stored in editable SQLite and is not cryptographically signed. HTML escapes observed strings but may include sensitive SSIDs and BSSIDs; keep exports private.

## Evidence integrity

`evidence FILE --scan-id N --vault DIR` stores a private copy with a random filename, records its SHA-256, and leaves the original untouched. `verify-evidence` compares current file bytes with the recorded digest and exits with status 1 for missing, unreadable or changed files. The JSON manifest omits local file paths. Do not put the vault or manifest in a public repository. A matching digest only shows consistency with the stored database value; the SQLite database and manifest are not signed or tamper-proof. Preserve the original acquisition record separately for formal chain of custody. Evidence can contain sensitive traffic.

## Rule review workflow

`evaluate` inspects only AP observations marked in scope. The default rules flag Open/Unknown and legacy WPA; `require_pmf` is opt-in. The JSON file must contain all three booleans. "Open/Unknown" may mean an unrecognized driver output, so validate against device configuration or a trusted capture. `findings` lists all rule results. `review` requires a note and records `open`, `confirmed`, or `dismissed`. Re-evaluating the same scan leaves prior analyst decisions intact. JSON and HTML reports include these findings. This is analyst triage, not an automated vulnerability verdict. Store the SQLite database securely; review records can be edited by its owner.

## Parts 6 and 7: parser and projects

The `iw` parser handles common indented RSN/WPA sections, transition mode (PSK + SAE), OWE, 802.1X, PMF hints and inferred channels in 2.4/5/6 GHz. Tests use representative fixtures, not captures from your adapter. It is still a best-effort parser: verify capabilities in raw output before asserting a finding.

Create a separate local project and run commands from its root:

```bash
sentinelf project-init client-lab --engagement LAB-001 --bssid AA:BB:CC:DD:EE:FF
cd client-lab
sentinelf scan --scope scope.json --interface wlan0 --input saved-iw-output.txt
sentinelf evaluate --scope scope.json --scan-id 1 --rules rules.json
sentinelf project-export . --output exports/report.zip
```

Omit `--input` only when testing on permitted wireless hardware. `project-init` requires a BSSID and refuses to overwrite an existing directory. The bundle contains JSON, HTML and an evidence verification manifest; it excludes PCAPs, the vault and SQLite. It still contains sensitive SSIDs/BSSIDs and analyst notes. Keep it private. The project root's `.gitignore` excludes local state and exports. To update an older project, keep its `.sentinelf/state.sqlite3` and run the newer CLI in that directory; the missing tables are created automatically.
