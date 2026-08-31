"""Who is your ISP, and which endpoints work on *their* network.

An endpoint that is perfect on Irancell can be a black hole on TCI thirty
kilometres away, because filtering in a censored country is applied per operator,
not per country. That single fact is why a "best WARP endpoint" list published on
the internet is close to worthless, and why WarpEP works the other way round:
detect the network you are actually on, then keep a private, local memory of what
answered on *that* network so the next scan starts from what already worked.

Two pieces:

* :func:`detect` asks Cloudflare's own edge who it thinks you are - the same
  ``/meta`` and ``/cdn-cgi/trace`` endpoints the speed test uses. That gives an
  ASN, the operator name, the country and the colo you land in. No third-party
  geo-IP service, no API key, and it is one HTTPS request.
* :func:`remember` / :func:`recall` keep a per-ASN cache of endpoints that really
  answered, with their score and the date. That cache never leaves the machine;
  it lives next to the account file under the user's config directory.

The operator table below only maps ASNs to human names and their local aliases,
because those are stable facts. Which endpoints or ports are good for an operator
is deliberately *not* hardcoded - it is measured, per user, and learned. Anything
else would be a guess dressed up as data.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .account import config_dir
from .util import run_bounded
from .version import user_agent

__all__ = [
    "NetworkProfile",
    "OPERATORS",
    "detect",
    "lookup",
    "networks_dir",
    "remember",
    "recall",
    "forget",
    "seed_endpoints",
    "all_networks",
]

META_URL = "https://speed.cloudflare.com/meta"
TRACE_URLS = (
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://one.one.one.one/cdn-cgi/trace",
)

# ASN -> (English name, local/common name). Iranian operators first, because
# that is where WARP endpoint hunting is a daily chore, then a few globals so the
# panel says something useful wherever you run it.
OPERATORS: Dict[int, Tuple[str, str]] = {
    58224: ("Iran Telecommunication Company (TCI)", "مخابرات ایران"),
    197207: ("Mobile Communication Company of Iran (MCI)", "همراه اول"),
    44244: ("Irancell (MTN)", "ایرانسل"),
    57218: ("Rightel", "رایتل"),
    12880: ("Information Technology Company (ITC)", "شرکت فناوری اطلاعات"),
    49666: ("Telecommunication Infrastructure Company (TIC)", "زیرساخت"),
    31549: ("Aria Shatel", "شاتل"),
    34369: ("Aria Shatel", "شاتل"),
    42337: ("Respina Networks", "رسپینا"),
    43754: ("Asiatech", "آسیاتک"),
    60077: ("Asre Dadeha (Asiatech)", "عصر داده‌ها"),
    16322: ("Pars Online", "پارس آنلاین"),
    50810: ("MobinNet", "مبین‌نت"),
    49100: ("Pishgaman", "پیشگامان"),
    25184: ("Afranet", "افرانت"),
    39501: ("NGSAS / Parvaresh Dadeha", "پرورش داده‌ها"),
    25124: ("Datak", "داتک"),
    41881: ("Fanava Group", "فناوا"),
    202468: ("ArvanCloud", "ابر آروان"),
    206065: ("Pasargad Arian (FanAP)", "فن‌آپ"),
    24631: ("Pasargad Arian (FanAP)", "فن‌آپ"),
    13335: ("Cloudflare", "Cloudflare"),
}


@dataclass
class NetworkProfile:
    """The network a scan is running on."""

    asn: int = 0
    organisation: str = ""
    country: str = ""
    city: str = ""
    colo: str = ""
    ip: str = ""
    http: str = ""
    warp: str = ""
    detected_via: str = ""
    error: Optional[str] = None
    detected_at: float = field(default_factory=time.time)

    @property
    def known(self) -> bool:
        return bool(self.asn or self.organisation)

    @property
    def operator(self) -> str:
        english, _ = lookup(self.asn)
        return english or self.organisation or "unknown network"

    @property
    def local_name(self) -> str:
        _, local = lookup(self.asn)
        return local

    @property
    def key(self) -> str:
        """Stable cache key for this network."""
        if self.asn:
            return f"as{self.asn}"
        if self.organisation:
            return "org-" + "".join(c if c.isalnum() else "-" for c in self.organisation.lower())[:40]
        return "unknown"

    @property
    def behind_warp(self) -> bool:
        return self.warp in {"on", "plus"}

    def label(self) -> str:
        bits = [self.operator]
        if self.asn:
            bits.append(f"AS{self.asn}")
        if self.country:
            bits.append(self.country.upper())
        if self.colo:
            bits.append(f"via {self.colo}")
        return "  ".join(bits)

    def as_dict(self) -> dict:
        return {
            "asn": self.asn,
            "operator": self.operator,
            "operator_local": self.local_name,
            "organisation": self.organisation,
            "country": self.country,
            "city": self.city,
            "colo": self.colo,
            "client_ip": self.ip,
            "behind_warp": self.behind_warp,
            "detected_via": self.detected_via,
            "cache_key": self.key,
            "error": self.error,
        }


def lookup(asn: int) -> Tuple[str, str]:
    return OPERATORS.get(int(asn or 0), ("", ""))


def _get(url: str, timeout: float) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent()})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def _from_meta(payload: str) -> NetworkProfile:
    data = json.loads(payload)
    return NetworkProfile(
        asn=int(data.get("asn") or 0),
        organisation=str(data.get("asOrganization") or ""),
        country=str(data.get("country") or ""),
        city=str(data.get("city") or ""),
        colo=str(data.get("colo") or ""),
        ip=str(data.get("clientIp") or ""),
        http=str(data.get("httpProtocol") or ""),
        detected_via="speed.cloudflare.com/meta",
    )


def _from_trace(payload: str) -> NetworkProfile:
    fields = {}
    for line in payload.splitlines():
        key, _, value = line.partition("=")
        if key:
            fields[key.strip()] = value.strip()
    return NetworkProfile(
        country=fields.get("loc", ""),
        colo=fields.get("colo", ""),
        ip=fields.get("ip", ""),
        http=fields.get("http", ""),
        warp=fields.get("warp", ""),
        detected_via="cdn-cgi/trace",
    )


def detect(timeout: float = 4.0) -> NetworkProfile:
    """Ask Cloudflare's edge which network we are on.

    Never raises, and never blocks longer than ``timeout`` per attempt even when
    the resolver itself is black-holed - see :func:`warpep.util.run_bounded`.
    """
    result = run_bounded(lambda: _detect(timeout), timeout + 4.0)
    if result is None:
        return NetworkProfile(error="network detection timed out")
    return result


def _detect(timeout: float) -> NetworkProfile:
    last_error = ""
    try:
        profile = _from_meta(_get(META_URL, timeout))
        if profile.known:
            # /meta has the ASN but not the warp flag; trace has the warp flag.
            try:
                trace = _from_trace(_get(TRACE_URLS[0], timeout))
                profile.warp = trace.warp
            except (OSError, urllib.error.URLError, ValueError):
                pass
            return profile
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        last_error = str(getattr(exc, "reason", exc))

    for url in TRACE_URLS:
        try:
            profile = _from_trace(_get(url, timeout))
            if profile.ip or profile.colo:
                return profile
        except (OSError, urllib.error.URLError, ValueError) as exc:
            last_error = str(getattr(exc, "reason", exc))

    return NetworkProfile(error=last_error or "no answer from Cloudflare's edge")


# -- per-operator memory ---------------------------------------------------


def networks_dir() -> Path:
    return config_dir() / "networks"


def _network_path(profile: NetworkProfile) -> Path:
    return networks_dir() / f"{profile.key}.json"


def remember(profile: NetworkProfile, entries: Sequence[dict], keep: int = 40) -> Optional[Path]:
    """Merge freshly measured endpoints into this network's memory."""
    if not entries:
        return None
    path = _network_path(profile)
    memory = recall(profile)
    known = {entry["endpoint"]: entry for entry in memory.get("endpoints", [])}
    now = time.time()
    for entry in entries:
        record = dict(entry)
        record["seen_at"] = now
        record["hits"] = known.get(record["endpoint"], {}).get("hits", 0) + 1
        known[record["endpoint"]] = record
    ranked = sorted(
        known.values(),
        key=lambda e: (not e.get("verified"), -(e.get("hits") or 0), e.get("avg_ms") if e.get("avg_ms") is not None else 1e9),
    )[:keep]
    payload = {
        "network": profile.as_dict(),
        "updated_at": now,
        "endpoints": ranked,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        return None
    return path


def recall(profile: NetworkProfile) -> dict:
    """What answered last time on this network. Empty dict when nothing known."""
    path = _network_path(profile)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def forget(profile: NetworkProfile) -> bool:
    path = _network_path(profile)
    try:
        path.unlink()
        return True
    except OSError:
        return False


def seed_endpoints(profile: NetworkProfile, limit: int = 24) -> List[str]:
    """``ip:port`` strings worth re-probing first on this network."""
    memory = recall(profile)
    entries = memory.get("endpoints", []) if isinstance(memory, dict) else []
    return [entry["endpoint"] for entry in entries[:limit] if entry.get("endpoint")]


def all_networks() -> List[dict]:
    """Every network WarpEP has learned about on this machine."""
    directory = networks_dir()
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data["_file"] = str(path)
            out.append(data)
    return out
