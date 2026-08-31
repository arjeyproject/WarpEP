"""Turn scan results into things you can actually paste somewhere.

WireGuard and AmneziaWG configs, sing-box / Hiddify outbounds, ``warp://`` links,
plain ``ip:port`` lines, JSON and CSV. Everything is generated from a real scan,
and the exports deliberately only contain endpoints WarpEP is willing to call
healthy - shipping a nice config file pointed at a dead endpoint is the exact
failure this project exists to remove.
"""

from __future__ import annotations

import csv
import io
import json
from typing import List, Optional, Sequence

from .endpoints import Endpoint
from .engine import EndpointResult, ScanReport
from .identity import WARP_RESPONDER_PUBLIC_KEY_B64
from .obfuscation import ObfuscationProfile
from .version import BRAND, REPO, __version__

__all__ = [
    "wireguard_conf",
    "amneziawg_conf",
    "singbox_outbound",
    "warp_uri_list",
    "warp_links",
    "results_json",
    "results_csv",
    "results_text",
    "memory_entries",
    "FORMATS",
]

FORMATS = ("wireguard", "amneziawg", "singbox", "warp", "endpoint")

DEFAULT_DNS = "1.1.1.1, 2606:4700:4700::1111"


def _usable(results: Sequence[EndpointResult]) -> List[EndpointResult]:
    """Verified first, then healthy, then anything that answered. Never the dead."""
    verified = [r for r in results if r.verified]
    healthy = [r for r in results if not r.verified and r.responsive and r.health >= 70]
    rest = [r for r in results if r.responsive and r not in verified and r not in healthy]
    return verified + healthy + rest


def wireguard_conf(
    endpoint: Endpoint,
    private_key: str,
    address_v4: str = "172.16.0.2",
    address_v6: str = "",
    peer_public_key: str = WARP_RESPONDER_PUBLIC_KEY_B64,
    mtu: int = 1280,
    dns: str = DEFAULT_DNS,
    obfuscation: Optional[ObfuscationProfile] = None,
    note: str = "",
) -> str:
    addresses = [f"{address_v4}/32"]
    if address_v6:
        addresses.append(f"{address_v6}/128")
    lines = [
        f"# {BRAND} v{__version__} - {REPO}",
        f"# Endpoint selected by a real WARP handshake scan: {endpoint}",
    ]
    if note:
        lines.append(f"# {note}")
    lines += [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {', '.join(addresses)}",
        f"DNS = {dns}",
        f"MTU = {mtu}",
    ]
    if obfuscation is not None and obfuscation.active:
        lines.append("# AmneziaWG obfuscation: import this file into an AmneziaWG client.")
        lines += obfuscation.wireguard_fields()
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {peer_public_key}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {endpoint}",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


def amneziawg_conf(endpoint: Endpoint, private_key: str, **kwargs) -> str:
    """A WireGuard config that always carries the AmneziaWG junk parameters."""
    from .obfuscation import awg_profile

    profile = kwargs.pop("obfuscation", None) or awg_profile()
    return wireguard_conf(endpoint, private_key, obfuscation=profile, **kwargs)


def singbox_outbound(
    endpoint: Endpoint,
    private_key: str,
    address_v4: str = "172.16.0.2",
    address_v6: str = "",
    peer_public_key: str = WARP_RESPONDER_PUBLIC_KEY_B64,
    mtu: int = 1280,
    tag: str = "warpep",
) -> str:
    local = [f"{address_v4}/32"]
    if address_v6:
        local.append(f"{address_v6}/128")
    outbound = {
        "type": "wireguard",
        "tag": tag,
        "server": endpoint.address,
        "server_port": endpoint.port,
        "local_address": local,
        "private_key": private_key,
        "peer_public_key": peer_public_key,
        "mtu": mtu,
        "reserved": [0, 0, 0],
    }
    return json.dumps({"outbounds": [outbound]}, indent=2) + "\n"


def warp_uri_list(results: Sequence[EndpointResult], limit: int = 10) -> str:
    """``warp://`` links, the one-tap format Hiddify and NekoBox understand."""
    lines = []
    for index, result in enumerate(_usable(results)[:limit], start=1):
        tag = "verified" if result.verified else result.grade
        lines.append(f"warp://{result.endpoint}/?ifp=5-10#WarpEP-{index}-{tag}-{result.health}")
    return "\n".join(lines) + ("\n" if lines else "")


def warp_links(results: Sequence[EndpointResult], limit: int = 10) -> str:
    """Plain ``ip:port`` lines, the format every WARP client asks you to paste."""
    lines = [str(r.endpoint) for r in _usable(results)][:limit]
    return "\n".join(lines) + ("\n" if lines else "")


def results_json(
    results: Sequence[EndpointResult],
    meta: Optional[dict] = None,
    report: Optional[ScanReport] = None,
) -> str:
    payload = {
        "tool": BRAND,
        "version": __version__,
        "repository": REPO,
        "meta": meta or {},
        "scan": report.as_dict() if report is not None else {},
        "results": [r.as_dict() for r in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def results_csv(results: Sequence[EndpointResult]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "endpoint", "address", "port", "health", "grade", "status", "verified",
            "sent", "received", "loss_percent", "best_ms", "avg_ms", "worst_ms",
            "jitter_ms", "obfuscated",
        ]
    )
    for result in results:
        row = result.as_dict()
        writer.writerow(
            [
                row["endpoint"], row["address"], row["port"], row["health"], row["grade"],
                row["badge"], row["verified"], row["sent"], row["received"],
                row["loss_percent"], row["best_ms"], row["avg_ms"], row["worst_ms"],
                row["jitter_ms"], row["obfuscated"],
            ]
        )
    return buffer.getvalue()


def results_text(results: Sequence[EndpointResult], limit: int = 10) -> str:
    lines = []
    for index, result in enumerate(results[:limit], start=1):
        avg = f"{result.avg:.1f} ms" if result.avg is not None else "-"
        lines.append(
            f"{index:>2}. {str(result.endpoint):<26} {avg:>10}  "
            f"loss {result.loss:>3.0f}%  health {result.health:>3}  {result.badge}"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def memory_entries(results: Sequence[EndpointResult], limit: int = 20) -> List[dict]:
    """Compact records for the per-operator memory in :mod:`warpep.operator`."""
    entries = []
    for result in _usable(results)[:limit]:
        entries.append(
            {
                "endpoint": str(result.endpoint),
                "avg_ms": round(result.avg, 2) if result.avg is not None else None,
                "loss_percent": round(result.loss, 2),
                "health": result.health,
                "verified": result.verified,
                "transport": "wireguard",
            }
        )
    return entries
