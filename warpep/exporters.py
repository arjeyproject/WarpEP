"""Turn scan results into things you can actually paste somewhere.

WireGuard configs, sing-box / Hiddify outbounds, warp:// endpoint lines, JSON and
CSV. All generated from the winning endpoint of a real scan.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable, List, Optional, Sequence

from .endpoints import Endpoint
from .engine import EndpointResult, WARP_PUBLIC_KEY_B64
from .version import BRAND, REPO, __version__

__all__ = ["wireguard_conf", "singbox_outbound", "warp_links", "results_json", "results_csv", "results_text"]

DEFAULT_DNS = "1.1.1.1, 2606:4700:4700::1111"


def wireguard_conf(
    endpoint: Endpoint,
    private_key: str,
    address_v4: str = "172.16.0.2",
    address_v6: str = "",
    peer_public_key: str = WARP_PUBLIC_KEY_B64,
    mtu: int = 1280,
    dns: str = DEFAULT_DNS,
) -> str:
    addresses = [f"{address_v4}/32"]
    if address_v6:
        addresses.append(f"{address_v6}/128")
    return "\n".join(
        [
            f"# {BRAND} v{__version__} - {REPO}",
            f"# Endpoint selected by a real WARP handshake scan: {endpoint}",
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {', '.join(addresses)}",
            f"DNS = {dns}",
            f"MTU = {mtu}",
            "",
            "[Peer]",
            f"PublicKey = {peer_public_key}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = {endpoint}",
            "PersistentKeepalive = 25",
            "",
        ]
    )


def singbox_outbound(
    endpoint: Endpoint,
    private_key: str,
    address_v4: str = "172.16.0.2",
    address_v6: str = "",
    peer_public_key: str = WARP_PUBLIC_KEY_B64,
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


def warp_links(results: Sequence[EndpointResult], limit: int = 10) -> str:
    """Plain ``ip:port`` lines, the format every WARP client asks you to paste."""
    lines = [str(r.endpoint) for r in results if r.alive][:limit]
    return "\n".join(lines) + ("\n" if lines else "")


def results_json(results: Sequence[EndpointResult], meta: Optional[dict] = None) -> str:
    payload = {
        "tool": BRAND,
        "version": __version__,
        "repository": REPO,
        "meta": meta or {},
        "results": [r.as_dict() for r in results],
    }
    return json.dumps(payload, indent=2) + "\n"


def results_csv(results: Sequence[EndpointResult]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["endpoint", "address", "port", "sent", "received", "loss_percent", "best_ms", "avg_ms", "worst_ms", "jitter_ms"])
    for result in results:
        row = result.as_dict()
        writer.writerow(
            [
                row["endpoint"],
                row["address"],
                row["port"],
                row["sent"],
                row["received"],
                row["loss_percent"],
                row["best_ms"],
                row["avg_ms"],
                row["worst_ms"],
                row["jitter_ms"],
            ]
        )
    return buffer.getvalue()


def results_text(results: Sequence[EndpointResult], limit: int = 10) -> str:
    lines = []
    for index, result in enumerate(results[:limit], start=1):
        avg = f"{result.avg:.1f} ms" if result.avg is not None else "-"
        lines.append(f"{index:>2}. {str(result.endpoint):<26} {avg:>10}  loss {result.loss:.0f}%")
    return "\n".join(lines) + ("\n" if lines else "")
