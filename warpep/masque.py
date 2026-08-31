"""MASQUE probing: Cloudflare's newest WARP transport, measured for real.

Background
----------
WARP no longer speaks only WireGuard. Cloudflare's current client can also carry
the tunnel over **MASQUE** - IP proxying (CONNECT-IP, RFC 9484) over HTTP/3/QUIC,
with an HTTP/2-over-TCP fallback. It is served from its own anycast blocks, on its
own ports, and it is the reason a network that has learnt to kill WireGuard's UDP
handshake can still be beaten: MASQUE-over-TCP/443 is, on the wire, an ordinary
HTTPS connection.

WarpEP measures both halves, and measures them honestly - no pure-Python QUIC or
TLS stack is pretending to build a tunnel here:

* ``probe_quic`` sends a QUIC long-header packet carrying a deliberately
  unsupported version. **Every** QUIC server, by RFC 9000 section 6, must answer
  that with a Version Negotiation packet, and that packet has to echo our
  connection IDs back with the roles swapped. So a reply is cryptographically
  pointless but structurally unforgeable by a dumb middlebox: it proves a real
  QUIC server is listening at that address and port, and it costs one packet.
* ``probe_h2`` opens TCP, completes a TLS handshake with the SNI the WARP client
  uses and ALPN ``h2``, and reports the negotiated protocol and TLS version. That
  is exactly the reachability question that matters for the fallback transport.

What this does *not* claim: a MASQUE probe is a reachability measurement, not a
tunnel. The end-to-end proof in WarpEP is still the WireGuard path in
``engine.verify_endpoint``, which pushes real ICMP through a real tunnel. The
table labels the two differently and so should you.

Addresses and ports below are Cloudflare's published MASQUE pools, cross-checked
against usque and warpscout.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from .endpoints import Endpoint

__all__ = [
    "MASQUE_SNI",
    "MASQUE_PORTS",
    "MASQUE_QUIC_V4",
    "MASQUE_QUIC_V6",
    "MASQUE_H2_PREFIXES_V4",
    "MASQUE_H2_V6",
    "MasqueResult",
    "probe_quic",
    "probe_h2",
    "scan",
    "default_targets",
]

# The SNI the official client presents. It never matches the endpoint address:
# the peer is pinned by public key instead, so the name is free, which is what
# makes it the MASQUE equivalent of an AmneziaWG magic packet.
MASQUE_SNI = "consumer-masque.cloudflareclient.com"

# Handed out per account by the API, but identical everywhere, so: a constant.
MASQUE_PORTS = (443, 4443, 8443, 500, 1701, 4500, 8095)

# QUIC/HTTP3 MASQUE is served from the ::1 and ::2 of each block only.
MASQUE_QUIC_V4 = ("162.159.198.1", "162.159.198.2")
MASQUE_QUIC_V6 = (
    "2606:4700:103::1",
    "2606:4700:103::2",
    "2606:4700:104::1",
    "2606:4700:104::2",
)

# The HTTP/2-over-TCP fallback answers across whole blocks, not just those hosts.
MASQUE_H2_PREFIXES_V4 = ("162.159.198.0/24", "162.159.199.0/24")
MASQUE_H2_V6 = (
    "2606:4700:103::1",
    "2606:4700:103::2",
    "2606:4700:104::1",
    "2606:4700:104::2",
)

# RFC 9000 s6: any version with the pattern 0x?a?a?a?a is reserved to force
# version negotiation, and a conforming server must never claim to support it.
_FORCE_VN_VERSION = 0x0A0A0A0A
_QUIC_MIN_DATAGRAM = 1200
_CID_LEN = 8

ProgressHook = Callable[[str, int, int], None]


@dataclass
class MasqueResult:
    """One MASQUE reachability measurement."""

    endpoint: Endpoint
    transport: str  # "masque-h3" or "masque-h2"
    rtts: List[float] = field(default_factory=list)
    attempts: int = 0
    alpn: str = ""
    tls_version: str = ""
    error: Optional[str] = None

    @property
    def alive(self) -> bool:
        return bool(self.rtts)

    @property
    def best(self) -> Optional[float]:
        return min(self.rtts) if self.rtts else None

    @property
    def avg(self) -> Optional[float]:
        return sum(self.rtts) / len(self.rtts) if self.rtts else None

    @property
    def loss(self) -> float:
        if not self.attempts:
            return 100.0
        return 100.0 * (self.attempts - len(self.rtts)) / self.attempts

    def as_dict(self) -> dict:
        return {
            "endpoint": str(self.endpoint),
            "transport": self.transport,
            "alive": self.alive,
            "attempts": self.attempts,
            "replies": len(self.rtts),
            "best_ms": round(self.best, 3) if self.best is not None else None,
            "avg_ms": round(self.avg, 3) if self.avg is not None else None,
            "loss_percent": round(self.loss, 2),
            "alpn": self.alpn or None,
            "tls_version": self.tls_version or None,
            "error": self.error,
        }


def _version_negotiation_trigger(destination_cid: bytes, source_cid: bytes) -> bytes:
    """A long-header QUIC packet with a reserved version, padded to 1200 bytes."""
    first = 0xC0 | (os.urandom(1)[0] & 0x0F)
    packet = bytearray()
    packet.append(first)
    packet += struct.pack(">I", _FORCE_VN_VERSION)
    packet.append(len(destination_cid))
    packet += destination_cid
    packet.append(len(source_cid))
    packet += source_cid
    if len(packet) < _QUIC_MIN_DATAGRAM:
        packet += os.urandom(_QUIC_MIN_DATAGRAM - len(packet))
    return bytes(packet)


def _is_version_negotiation(packet: bytes, sent_dcid: bytes, sent_scid: bytes) -> bool:
    """Validate the answer really is a VN packet replying to *our* packet.

    Layout: header byte, four zero version bytes, then DCID and SCID with the
    roles swapped relative to what we sent. A censor's RST-style injection or a
    stray UDP responder cannot produce this by accident.
    """
    if len(packet) < 7 or not packet[0] & 0x80:
        return False
    if struct.unpack(">I", packet[1:5])[0] != 0:
        return False
    offset = 5
    dcid_len = packet[offset]
    offset += 1
    if len(packet) < offset + dcid_len + 1:
        return False
    dcid = packet[offset : offset + dcid_len]
    offset += dcid_len
    scid_len = packet[offset]
    offset += 1
    if len(packet) < offset + scid_len:
        return False
    scid = packet[offset : offset + scid_len]
    # The server echoes our source CID as its destination, and ours as its source.
    return dcid == sent_scid and scid == sent_dcid


def probe_quic(endpoint: Endpoint, timeout: float = 2.0, attempts: int = 2) -> MasqueResult:
    """Measure a MASQUE/HTTP3 endpoint with QUIC version negotiation."""
    result = MasqueResult(endpoint=endpoint, transport="masque-h3")
    family = socket.AF_INET6 if endpoint.is_ipv6 else socket.AF_INET
    for _ in range(max(1, attempts)):
        result.attempts += 1
        dcid, scid = os.urandom(_CID_LEN), os.urandom(_CID_LEN)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect((endpoint.address, endpoint.port))
            started = time.perf_counter()
            sock.send(_version_negotiation_trigger(dcid, scid))
            deadline = started + timeout
            while time.perf_counter() < deadline:
                try:
                    packet = sock.recv(2048)
                except (socket.timeout, TimeoutError):
                    break
                if _is_version_negotiation(packet, dcid, scid):
                    result.rtts.append((time.perf_counter() - started) * 1000.0)
                    break
        except OSError as exc:
            result.error = str(exc)
        finally:
            sock.close()
    if not result.rtts and not result.error:
        result.error = "no QUIC version negotiation reply"
    return result


def _tls_context(sni: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Cloudflare never signs the MASQUE client certificate and the SNI never
    # matches the endpoint address: authentication is the enrolled key, not the
    # chain. So chain validation is meaningless here and is turned off on
    # purpose - this probe measures reachability, it never carries data.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(["h2"])
    except NotImplementedError:  # pragma: no cover - ancient OpenSSL
        pass
    return context


def probe_h2(
    endpoint: Endpoint,
    timeout: float = 3.0,
    attempts: int = 1,
    sni: str = MASQUE_SNI,
) -> MasqueResult:
    """Measure the MASQUE HTTP/2-over-TCP fallback: connect, TLS, ALPN."""
    result = MasqueResult(endpoint=endpoint, transport="masque-h2")
    context = _tls_context(sni)
    for _ in range(max(1, attempts)):
        result.attempts += 1
        try:
            started = time.perf_counter()
            raw = socket.create_connection((endpoint.address, endpoint.port), timeout=timeout)
            try:
                raw.settimeout(timeout)
                with context.wrap_socket(raw, server_hostname=sni) as tls:
                    elapsed = (time.perf_counter() - started) * 1000.0
                    alpn = tls.selected_alpn_protocol() or ""
                    result.alpn = alpn
                    result.tls_version = tls.version() or ""
                    if alpn == "h2":
                        result.rtts.append(elapsed)
                    else:
                        result.error = f"TLS came up but ALPN negotiated {alpn or 'nothing'}"
            finally:
                try:
                    raw.close()
                except OSError:
                    pass
        except ssl.SSLError as exc:
            result.error = f"TLS rejected: {exc.reason or exc}"
        except (socket.timeout, TimeoutError):
            result.error = "timed out"
        except OSError as exc:
            result.error = str(exc)
    return result


def default_targets(transport: str = "masque-h2", ipv6: bool = False, ports: Optional[Sequence[int]] = None) -> List[Endpoint]:
    """The published MASQUE pools for a transport, as scannable endpoints."""
    from .endpoints import expand_prefixes

    chosen = list(ports or MASQUE_PORTS)
    if transport == "masque-h3":
        addresses = list(MASQUE_QUIC_V6 if ipv6 else MASQUE_QUIC_V4)
    else:
        addresses = list(MASQUE_H2_V6) if ipv6 else expand_prefixes(MASQUE_H2_PREFIXES_V4)
    return [Endpoint(address, port) for address in addresses for port in chosen]


def scan(
    targets: Sequence[Endpoint],
    transport: str = "masque-h2",
    timeout: float = 3.0,
    attempts: int = 2,
    workers: int = 64,
    sni: str = MASQUE_SNI,
    progress: Optional[ProgressHook] = None,
) -> List[MasqueResult]:
    """Probe MASQUE endpoints concurrently and rank the survivors."""
    if not targets:
        return []
    hook = progress or (lambda phase, done, total: None)
    total = len(targets)
    done = 0
    results: List[MasqueResult] = []

    def one(target: Endpoint) -> MasqueResult:
        if transport == "masque-h3":
            return probe_quic(target, timeout=timeout, attempts=attempts)
        return probe_h2(target, timeout=timeout, attempts=attempts, sni=sni)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, total))) as pool:
        for result in pool.map(one, targets):
            results.append(result)
            done += 1
            hook(transport, done, total)
    hook(transport, total, total)
    results.sort(key=lambda r: (not r.alive, r.avg if r.avg is not None else float("inf"), str(r.endpoint)))
    return results
