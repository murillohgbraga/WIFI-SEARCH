import json
import re
from dataclasses import dataclass
from pathlib import Path

MAC = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")


def mac(value):
    value = value.strip().upper()
    if not MAC.fullmatch(value):
        raise ValueError(f"Invalid BSSID: {value}")
    return value


@dataclass(frozen=True)
class Scope:
    engagement: str
    ssids: frozenset[str]
    bssids: frozenset[str]

    def allows(self, ssid, bssid):
        # BSSID restriction takes priority when supplied; SSID-only matching is opt-in.
        return bssid.upper() in self.bssids or (not self.bssids and ssid in self.ssids)


def load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    auth = data["authorized"]
    engagement = data["engagement"]
    ssids = auth.get("ssids", [])
    bssids = auth.get("bssids", [])
    if not isinstance(engagement, str) or not engagement.strip() or not isinstance(ssids, list) or not isinstance(bssids, list):
        raise ValueError("Invalid scope document")
    if not bssids and not ssids:
        raise ValueError("Scope must specify at least one target")
    return Scope(engagement, frozenset(ssids), frozenset(mac(x) for x in bssids))
