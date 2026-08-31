"""The WarpEP scan engine.

Design notes, because the details are what make this fast *and* honest:

* One non-blocking UDP socket per address family carries every probe. No thread
  per target, no 4000 file descriptors: a single send/receive loop paced by a
  token-bucket rate limiter, matching replies back to probes by WireGuard sender
  index. That is how a full /24 sweep finishes in seconds on a phone.
* Every probe is a distinct, valid handshake initiation (unique sender index,
  fresh TAI64N timestamp) and every reply is verified cryptographically before
  it counts. A reply from the wrong source address is discarded.
* Timings are measured with ``time.perf_counter`` around the actual send, so the
  RTT is the endpoint's, not the scheduler's.
"""

from __future__ import annotations

import selectors
import socket
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .endpoints import Endpoint
from .wireguard import noise
from .wireguard.chacha20poly1305 import InvalidTag
from .wireguard.noise import CookieReply, Ephemeral, HandshakeError, Initiator, PeerIdentity, Keypair
from .wireguard import transport

__all__ = ["ScanConfig", "EndpointResult", "Scanner", "TunnelCheck", "verify_endpoint", "WARP_PUBLIC_KEY_B64"]

# Cloudflare's published WARP WireGuard responder public key. Every WARP client
# (official app, wgcf, warp-plus) handshakes against this exact key.
WARP_PUBLIC_KEY_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

ProgressHook = Callable[[str, int, int], None]


def warp_public_key() -> bytes:
    import base64

    return base64.b64decode(WARP_PUBLIC_KEY_B64)


@dataclass
class ScanConfig:
    probes: int = 3
    timeout: float = 1.2
    rate: int = 1500
    max_inflight: int = 512
    pool_size: int = 24
    source_ip: Optional[str] = None
    ipv6: bool = False


@dataclass
class EndpointResult:
    endpoint: Endpoint
    sent: int = 0
    received: int = 0
    cookies: int = 0
    rtts: List[float] = field(default_factory=list)

    @property
    def alive(self) -> bool:
        return self.received > 0 or self.cookies > 0

    @property
    def loss(self) -> float:
        if not self.sent:
            return 100.0
        return 100.0 * (self.sent - self.received) / self.sent

    @property
    def best(self) -> Optional[float]:
        return min(self.rtts) if self.rtts else None

    @property
    def avg(self) -> Optional[float]:
        return statistics.fmean(self.rtts) if self.rtts else None

    @property
    def worst(self) -> Optional[float]:
        return max(self.rtts) if self.rtts else None

    @property
    def jitter(self) -> Optional[float]:
        """Mean deviation between consecutive samples, like ping's mdev."""
        if len(self.rtts) < 2:
            return 0.0 if self.rtts else None
        deltas = [abs(b - a) for a, b in zip(self.rtts, self.rtts[1:])]
        return statistics.fmean(deltas)

    @property
    def score(self) -> float:
        """Lower is better. Loss dominates, then latency, then jitter."""
        if not self.rtts:
            return float("inf")
        return (self.avg or 0) + (self.jitter or 0) * 0.5 + self.loss * 10.0

    def as_dict(self) -> dict:
        return {
            "endpoint": str(self.endpoint),
            "address": self.endpoint.address,
            "port": self.endpoint.port,
            "sent": self.sent,
            "received": self.received,
            "cookie_replies": self.cookies,
            "loss_percent": round(self.loss, 2),
            "best_ms": round(self.best, 3) if self.best is not None else None,
            "avg_ms": round(self.avg, 3) if self.avg is not None else None,
            "worst_ms": round(self.worst, 3) if self.worst is not None else None,
            "jitter_ms": round(self.jitter, 3) if self.jitter is not None else None,
        }


@dataclass
class _Probe:
    endpoint: Endpoint
    initiator: Initiator
    sent_at: float


class _RateLimiter:
    """Token bucket, so we never look like a flood to Cloudflare or to your ISP."""

    def __init__(self, rate: int):
        self.rate = max(1, rate)
        self._allowance = float(self.rate)
        self._last = time.perf_counter()

    def take(self) -> None:
        while True:
            now = time.perf_counter()
            self._allowance += (now - self._last) * self.rate
            self._last = now
            if self._allowance > self.rate:
                self._allowance = float(self.rate)
            if self._allowance >= 1.0:
                self._allowance -= 1.0
                return
            time.sleep(max(0.0005, (1.0 - self._allowance) / self.rate))


class Scanner:
    """Probes WARP endpoints with real WireGuard handshakes."""

    def __init__(
        self,
        static: Optional[Keypair] = None,
        responder_public: Optional[bytes] = None,
        config: Optional[ScanConfig] = None,
        progress: Optional[ProgressHook] = None,
    ):
        self.config = config or ScanConfig()
        self.identity = PeerIdentity(static or Keypair.generate(), responder_public or warp_public_key())
        self._pool = [Ephemeral(self.identity) for _ in range(max(1, self.config.pool_size))]
        self._pool_index = 0
        self._progress = progress or (lambda phase, done, total: None)

    # -- public API ---------------------------------------------------------

    def discover_ports(self, addresses: Sequence[str], ports: Sequence[int], sample: int = 6) -> List[int]:
        """Find which WARP ports this network actually lets through."""
        probe_set = list(addresses)[: max(1, sample)]
        targets = [Endpoint(address, port) for address in probe_set for port in ports]
        results = self.scan(targets, probes=1, phase="ports")
        open_ports = sorted({r.endpoint.port for r in results if r.alive}, key=lambda p: ports.index(p))
        return open_ports

    def scan(
        self,
        targets: Sequence[Endpoint],
        probes: Optional[int] = None,
        phase: str = "scan",
    ) -> List[EndpointResult]:
        if not targets:
            return []
        rounds = probes if probes is not None else self.config.probes
        results: Dict[Endpoint, EndpointResult] = {t: EndpointResult(t) for t in targets}
        family = socket.AF_INET6 if self.config.ipv6 else socket.AF_INET

        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if self.config.source_ip:
            sock.bind((self.config.source_ip, 0))
        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ)
        limiter = _RateLimiter(self.config.rate)
        inflight: Dict[int, _Probe] = {}
        total = len(targets) * rounds
        done = 0

        try:
            for _ in range(rounds):
                for target in targets:
                    while len(inflight) >= self.config.max_inflight:
                        done += self._pump(selector, sock, inflight, results, 0.02)
                        done += self._expire(inflight, results)
                        self._progress(phase, done, total)
                    limiter.take()
                    probe = self._send(sock, target)
                    if probe is None:
                        result = results[target]
                        result.sent += 1
                        done += 1
                        continue
                    inflight[probe.initiator.sender_index] = probe
                    results[target].sent += 1
                    done += self._pump(selector, sock, inflight, results, 0)
                    self._progress(phase, done, total)

                deadline = time.perf_counter() + self.config.timeout
                while inflight and time.perf_counter() < deadline:
                    done += self._pump(selector, sock, inflight, results, 0.05)
                    done += self._expire(inflight, results)
                    self._progress(phase, done, total)
                done += self._expire(inflight, results, force=True)
                self._progress(phase, done, total)
        finally:
            selector.close()
            sock.close()

        self._progress(phase, total, total)
        ordered = sorted(results.values(), key=lambda r: (r.score, str(r.endpoint)))
        return ordered

    # -- internals ---------------------------------------------------------

    def _next_ephemeral(self) -> Ephemeral:
        ephemeral = self._pool[self._pool_index % len(self._pool)]
        self._pool_index += 1
        return ephemeral

    def _send(self, sock: socket.socket, target: Endpoint) -> Optional[_Probe]:
        initiator = Initiator(self.identity, ephemeral=self._next_ephemeral())
        packet = initiator.initiation()
        try:
            sock.sendto(packet, (target.address, target.port))
        except OSError:
            return None
        return _Probe(endpoint=target, initiator=initiator, sent_at=time.perf_counter())

    def _pump(
        self,
        selector: selectors.BaseSelector,
        sock: socket.socket,
        inflight: Dict[int, _Probe],
        results: Dict[Endpoint, EndpointResult],
        wait: float,
    ) -> int:
        completed = 0
        if not selector.select(wait):
            return 0
        while True:
            try:
                packet, peer = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return completed
            except OSError:
                return completed
            completed += self._handle(packet, peer, inflight, results)

    def _handle(
        self,
        packet: bytes,
        peer: Tuple,
        inflight: Dict[int, _Probe],
        results: Dict[Endpoint, EndpointResult],
    ) -> int:
        import struct

        kind = noise.message_type(packet)
        if kind == noise.MSG_RESPONSE and len(packet) == noise.MESSAGE_RESPONSE_SIZE:
            index = struct.unpack("<I", packet[8:12])[0]
        elif kind == noise.MSG_COOKIE_REPLY and len(packet) >= 8:
            index = struct.unpack("<I", packet[4:8])[0]
        else:
            return 0

        probe = inflight.get(index)
        if probe is None:
            return 0
        # Anti-spoofing: the answer has to come from the endpoint we asked.
        if peer and peer[0] != probe.endpoint.address:
            return 0

        elapsed = (time.perf_counter() - probe.sent_at) * 1000.0
        result = results[probe.endpoint]
        try:
            probe.initiator.consume_response(packet)
        except CookieReply:
            result.cookies += 1
            del inflight[index]
            return 1
        except (HandshakeError, InvalidTag, ValueError):
            del inflight[index]
            return 1

        result.received += 1
        result.rtts.append(elapsed)
        del inflight[index]
        return 1

    def _expire(
        self,
        inflight: Dict[int, _Probe],
        results: Dict[Endpoint, EndpointResult],
        force: bool = False,
    ) -> int:
        if not inflight:
            return 0
        now = time.perf_counter()
        timeout = self.config.timeout
        stale = [i for i, p in inflight.items() if force or now - p.sent_at >= timeout]
        for index in stale:
            del inflight[index]
        return len(stale)


@dataclass
class TunnelCheck:
    """Result of a deep, does-it-actually-carry-traffic verification."""

    endpoint: Endpoint
    handshake_ms: Optional[float] = None
    tunnel_rtts: List[float] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return bool(self.tunnel_rtts)

    @property
    def avg_tunnel_ms(self) -> Optional[float]:
        return statistics.fmean(self.tunnel_rtts) if self.tunnel_rtts else None

    def as_dict(self) -> dict:
        return {
            "endpoint": str(self.endpoint),
            "handshake_ms": round(self.handshake_ms, 3) if self.handshake_ms is not None else None,
            "tunnel_ok": self.ok,
            "tunnel_avg_ms": round(self.avg_tunnel_ms, 3) if self.avg_tunnel_ms else None,
            "echoes": len(self.tunnel_rtts),
            "error": self.error,
        }


def verify_endpoint(
    static: Keypair,
    endpoint: Endpoint,
    responder_public: Optional[bytes] = None,
    client_ip: str = "172.16.0.2",
    target_ip: str = "162.159.192.1",
    echoes: int = 3,
    timeout: float = 2.0,
) -> TunnelCheck:
    """Complete a handshake and push real ICMP traffic through the tunnel."""
    check = TunnelCheck(endpoint=endpoint)
    identity = PeerIdentity(static, responder_public or warp_public_key())
    initiator = Initiator(identity)
    family = socket.AF_INET6 if endpoint.is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((endpoint.address, endpoint.port))
        started = time.perf_counter()
        sock.send(initiator.initiation())
        keys = None
        while keys is None:
            packet = sock.recv(2048)
            try:
                keys = initiator.consume_response(packet)
            except CookieReply:
                check.error = "endpoint answered with a cookie challenge (rate limited)"
                return check
        check.handshake_ms = (time.perf_counter() - started) * 1000.0

        identifier = keys.sender_index & 0xFFFF
        for sequence in range(1, echoes + 1):
            inner = transport.icmp_echo_request(client_ip, target_ip, identifier, sequence)
            sent_at = time.perf_counter()
            sock.send(transport.seal(keys, sequence, inner))
            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                try:
                    reply = sock.recv(2048)
                except socket.timeout:
                    break
                try:
                    _, payload = transport.open_packet(keys, reply)
                except InvalidTag:
                    continue
                if not payload:  # keepalive
                    continue
                if transport.parse_icmp_echo_reply(payload, identifier) == sequence:
                    check.tunnel_rtts.append((time.perf_counter() - sent_at) * 1000.0)
                    break
    except HandshakeError as exc:
        check.error = str(exc)
    except (socket.timeout, TimeoutError):
        check.error = "timed out" if check.handshake_ms is None else "handshake ok, no traffic returned"
    except OSError as exc:
        check.error = str(exc)
    finally:
        sock.close()
    return check
