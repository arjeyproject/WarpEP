"""``warpep doctor``: work out what is actually broken, and say it in plain words.

A scanner that prints four thousand dead rows has told the user nothing. The
doctor answers the only question that matters when a scan comes back empty: is it
the identity, the network, the address family, the port, or the transport? Each
check is a real measurement, and each failure carries the fix.
"""

from __future__ import annotations

import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from . import masque, operator as operator_mod
from .endpoints import ALL_PORTS, Endpoint, PRIMARY_PORTS
from .engine import CONTROL_ENDPOINTS, CONTROL_ENDPOINTS_V6, ScanConfig, Scanner
from .identity import IdentityError, resolve as resolve_identity
from .output import Console, Progress
from .util import run_bounded
from .version import __version__

__all__ = ["Finding", "diagnose", "run"]

WARP_API_HOST = "api.cloudflareclient.com"
WARP_DNS_NAME = "engage.cloudflareclient.com"


@dataclass
class Finding:
    name: str
    ok: bool
    detail: str
    fix: str = ""

    @property
    def status(self) -> str:
        return "PASS" if self.ok else "FAIL"


def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> Optional[float]:
    def attempt() -> Optional[float]:
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return (time.perf_counter() - started) * 1000.0
        except OSError:
            return None

    return run_bounded(attempt, timeout + 2.0)


def _resolve(name: str, timeout: float = 5.0) -> Optional[list]:
    return run_bounded(
        lambda: socket.getaddrinfo(name, 2408, proto=socket.IPPROTO_UDP), timeout
    )


def diagnose(console: Console, settings=None) -> List[Finding]:
    findings: List[Finding] = []
    progress = Progress(console)

    # 1. the machine itself
    findings.append(
        Finding(
            "this machine",
            sys.version_info >= (3, 8),
            f"WarpEP {__version__} on Python {platform.python_version()}, "
            f"{platform.system()} {platform.machine()}",
            "WarpEP needs Python 3.8 or newer",
        )
    )

    # 2. can we even open a UDP socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.sendto(b"", ("127.0.0.1", 9))
        findings.append(Finding("UDP sockets", True, "outbound UDP works from this process"))
    except OSError as exc:
        findings.append(
            Finding("UDP sockets", False, str(exc), "a sandbox or firewall is blocking raw UDP from this process")
        )

    # 3. the identity - the single most common cause of a totally dead scan
    identity = None
    try:
        identity = resolve_identity()
        findings.append(
            Finding(
                "scan identity",
                identity.registered,
                identity.describe(),
                "" if identity.registered else "run 'warpep register' so Cloudflare will answer your probes",
            )
        )
    except IdentityError as exc:
        findings.append(Finding("scan identity", False, str(exc), "run 'warpep register'"))

    # 4. who does Cloudflare think we are
    profile = operator_mod.detect()
    findings.append(
        Finding(
            "operator detection",
            profile.known or bool(profile.ip),
            profile.label() if (profile.known or profile.ip) else (profile.error or "no answer"),
            "HTTPS to Cloudflare is blocked or intercepted here" if profile.error else "",
        )
    )
    if profile.behind_warp:
        findings.append(
            Finding(
                "existing WARP tunnel",
                False,
                "this machine is already connected through WARP",
                "turn WARP off before scanning, or every measurement goes through the tunnel you are trying to replace",
            )
        )

    # 5. DNS
    resolved = _resolve(WARP_DNS_NAME)
    if resolved:
        addresses = sorted({item[4][0] for item in resolved})
        findings.append(Finding("DNS", True, f"{WARP_DNS_NAME} resolves to {', '.join(addresses[:3])}"))
    else:
        findings.append(
            Finding(
                "DNS",
                False,
                f"cannot resolve {WARP_DNS_NAME}",
                "your resolver is broken or poisoned: set 1.1.1.1 or 8.8.8.8",
            )
        )

    # 6. registration API
    api_ms = _tcp_reachable(WARP_API_HOST, 443)
    findings.append(
        Finding(
            "WARP registration API",
            api_ms is not None,
            f"{WARP_API_HOST}:443 answered in {api_ms:.0f} ms" if api_ms else f"{WARP_API_HOST}:443 unreachable",
            "" if api_ms else "registration is blocked here; scanning still works on the bundled enrolled identity",
        )
    )

    # 7. the actual WireGuard control probe
    if identity is not None:
        for family_label, controls, ipv6 in (
            ("WireGuard over IPv4", CONTROL_ENDPOINTS, False),
            ("WireGuard over IPv6", CONTROL_ENDPOINTS_V6, True),
        ):
            scanner = Scanner(
                identity=identity,
                config=ScanConfig(timeout=1.5, rate=200, ipv6=ipv6, verify_top=0),
                progress=progress.hook,
            )
            results = scanner.scan(list(controls), probes=2, phase="preflight")
            progress.clear()
            answering = [r for r in results if r.responsive]
            cookies = [r for r in results if r.cookies]
            if answering:
                fastest = min(answering, key=lambda r: r.avg or 1e9)
                findings.append(
                    Finding(family_label, True, f"{fastest.endpoint} handshook in {fastest.avg:.0f} ms")
                )
            elif cookies:
                findings.append(
                    Finding(family_label, True, "control endpoints are rate limiting but alive")
                )
            else:
                findings.append(
                    Finding(
                        family_label,
                        False,
                        "no control endpoint completed a handshake",
                        "this address family or its UDP ports are filtered here",
                    )
                )

        # 8. which ports get out at all
        scanner = Scanner(
            identity=identity,
            config=ScanConfig(timeout=1.2, rate=400, verify_top=0),
            progress=progress.hook,
        )
        open_ports = scanner.discover_ports(
            [endpoint.address for endpoint in CONTROL_ENDPOINTS], list(ALL_PORTS), sample=4
        )
        progress.clear()
        findings.append(
            Finding(
                "open WARP ports",
                bool(open_ports),
                ", ".join(str(port) for port in open_ports[:12]) if open_ports else "none of the published ports answered",
                "" if open_ports else "UDP to Cloudflare looks blocked wholesale: try the MASQUE transport",
            )
        )

    # 9. MASQUE over TCP - the escape hatch when UDP is dead
    masque_targets = [Endpoint(masque.MASQUE_QUIC_V4[1], 443), Endpoint(masque.MASQUE_QUIC_V4[0], 443)]
    h2 = masque.scan(masque_targets, transport="masque-h2", timeout=5.0, attempts=1, workers=2)
    alive_h2 = [r for r in h2 if r.alive]
    findings.append(
        Finding(
            "MASQUE over TCP/443",
            bool(alive_h2),
            f"{alive_h2[0].endpoint} negotiated {alive_h2[0].alpn} in {alive_h2[0].avg:.0f} ms"
            if alive_h2
            else (h2[0].error or "no answer"),
            "" if alive_h2 else "even HTTPS to the MASQUE pool is filtered or intercepted here",
        )
    )
    h3 = masque.scan([Endpoint(masque.MASQUE_QUIC_V4[1], 443)], transport="masque-h3", timeout=3.0, attempts=2, workers=1)
    findings.append(
        Finding(
            "MASQUE over QUIC/443",
            bool(h3 and h3[0].alive),
            f"QUIC version negotiation returned in {h3[0].avg:.0f} ms" if h3 and h3[0].alive
            else (h3[0].error if h3 else "no answer"),
            "" if (h3 and h3[0].alive) else "UDP/443 is filtered: the HTTP/2 fallback is your route",
        )
    )
    return findings


def _prescribe(findings: Sequence[Finding]) -> List[str]:
    """Turn the findings into the two or three sentences the user actually needs."""
    index = {finding.name: finding for finding in findings}
    advice: List[str] = []

    identity = index.get("scan identity")
    if identity is not None and not identity.ok:
        advice.append(
            "Your probes are unsigned, so Cloudflare drops them and every endpoint looks dead. "
            "Fix this first: run 'warpep register'."
        )

    v4 = index.get("WireGuard over IPv4")
    v6 = index.get("WireGuard over IPv6")
    ports = index.get("open WARP ports")
    h2 = index.get("MASQUE over TCP/443")
    h3 = index.get("MASQUE over QUIC/443")

    if v4 is not None and v4.ok:
        advice.append("WireGuard works here. 'warpep scan' is all you need; add --deep if the fast preset is thin.")
    elif v6 is not None and v6.ok:
        advice.append("IPv4 WARP is filtered but IPv6 is not. Scan with 'warpep scan -6'.")
    elif ports is not None and ports.ok:
        advice.append(
            "The default ports are blocked but others are open. Try 'warpep scan --ports all --skip-port-scan'."
        )
    elif h2 is not None and h2.ok:
        advice.append(
            "UDP WireGuard is dead on this network, but MASQUE over TCP/443 answers. "
            "Run 'warpep masque' and use the result with a MASQUE client such as usque."
        )
    elif h3 is not None and h3.ok:
        advice.append("Only QUIC/443 answered. Run 'warpep masque --transport masque-h3'.")
    else:
        advice.append(
            "Nothing Cloudflare-shaped gets out of this network right now, on any transport. "
            "That is upstream of WarpEP: change network, or try again later."
        )

    if index.get("existing WARP tunnel") is not None:
        advice.append("Turn your existing WARP connection off first, otherwise you are measuring it, not the endpoints.")
    if index.get("operator detection") is not None and not index["operator detection"].ok:
        advice.append("Operator detection failed, so per-operator memory is disabled this session.")
    return advice


def run(console: Console, panel=None) -> int:
    console.rule("NETWORK DOCTOR", "bright_magenta")
    console.info("running real measurements, this takes a few seconds")
    console.write()
    findings = diagnose(console)
    failures = 0
    for finding in findings:
        console.write(
            "  " + console.paint(f" {finding.status} ", "on_green" if finding.ok else "on_red")
            + "  " + console.paint(finding.name, "bold")
        )
        console.write("        " + finding.detail)
        if not finding.ok:
            failures += 1
            if finding.fix:
                console.write("        " + console.paint("fix: " + finding.fix, "bright_yellow"))
    console.write()
    advice = _prescribe(findings)
    console.panel(
        "WHAT TO DO",
        [(f"{index}.", line) for index, line in enumerate(advice, start=1)],
        "bright_green" if not failures else "bright_yellow",
    )
    if panel is not None:
        profile = operator_mod.detect()
        if profile.known:
            panel.network = profile
            panel._network_checked = True
    return 0 if failures == 0 else 1
