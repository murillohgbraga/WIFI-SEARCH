"""Parse human-readable `iw dev IFACE scan` output; no raw frame capture."""
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

BSS = re.compile(r"^BSS ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\((?:on )?[^)]*\)")
FREQ = re.compile(r"^\s*freq:\s*(\d+)", re.M)
SIGNAL = re.compile(r"^\s*signal:\s*(-?\d+(?:\.\d+)?)", re.M)
CHANNEL = re.compile(r"(?:primary channel|DS Parameter set: channel)\s*(\d+)")


@dataclass(frozen=True)
class AP:
    bssid: str
    ssid: str
    frequency: int | None
    channel: int | None
    signal_dbm: float | None
    security: str
    akm: tuple[str, ...]
    pmf: str

    def record(self):
        return asdict(self)


def frequency_channel(freq):
    if freq == 2484:
        return 14
    if freq is not None and 2412 <= freq <= 2472 and (freq - 2407) % 5 == 0:
        return (freq - 2407) // 5
    if freq is not None and 5000 <= freq <= 5895 and (freq - 5000) % 5 == 0:
        return (freq - 5000) // 5
    if freq is not None and 5955 <= freq <= 7115 and (freq - 5950) % 5 == 0:
        return (freq - 5950) // 5
    return None


def parse_iw(output):
    blocks, current = [], []
    for line in output.splitlines():
        if BSS.match(line):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append(current)
    result = []
    for block in blocks:
        raw = "\n".join(block)
        bssid = BSS.match(block[0]).group(1).upper()
        ssid = next((x.strip()[6:] for x in block if x.strip().startswith("SSID: ")), "")
        def number(pattern, kind):
            found = pattern.search(raw)
            return kind(found.group(1)) if found else None
        freq = number(FREQ, int)
        channel = number(CHANNEL, int) or frequency_channel(freq)
        # Restrict suites to the RSN/WPA section to avoid unrelated IE fields.
        suites, section = [], None
        pmf_lines = []
        for line in block[1:]:
            indent = len(line) - len(line.lstrip())
            value = line.strip().lstrip("* ")
            if value.startswith("RSN:"):
                section = ("RSN", indent)
            elif value.startswith("WPA:"):
                section = ("WPA", indent)
            elif section and indent <= section[1] and value:
                section = None
            if section:
                if value.startswith("Authentication suites:"):
                    suites.extend(value.partition(":")[2].strip().split())
                if "Management frame protection" in value:
                    pmf_lines.append(value.lower())
        akm = tuple(sorted(set(suites)))
        rsn = any(x.strip().startswith("RSN:") for x in block)
        wpa = any(x.strip().startswith("WPA:") for x in block)
        suite_text = " ".join(akm).upper()
        if "OWE" in suite_text:
            security = "OWE"
        elif "SAE" in suite_text and "PSK" in suite_text:
            security = "WPA2/WPA3-Transition"
        elif "SAE" in suite_text:
            security = "WPA3/SAE"
        elif "802.1X" in suite_text or "EAP" in suite_text:
            security = "WPA2-Enterprise" if rsn else "WPA-Enterprise"
        elif rsn:
            security = "WPA2"
        elif wpa:
            security = "WPA"
        else:
            security = "Open/Unknown"
        pmf = "required" if any("required" in x for x in pmf_lines) else ("capable" if any("capable" in x for x in pmf_lines) else "unknown")
        result.append(AP(bssid, ssid, freq, channel, number(SIGNAL, float), security, akm, pmf))
    return result


def interfaces():
    root = Path("/sys/class/net")
    return sorted(p.name for p in root.iterdir() if (p / "wireless").exists() or (p / "phy80211").exists()) if root.exists() else []


def scan(interface):
    if interface not in interfaces():
        raise ValueError("Interface is not a detected wireless interface")
    result = subprocess.run(["iw", "dev", interface, "scan"], capture_output=True, text=True, timeout=45, check=True)
    return parse_iw(result.stdout)
