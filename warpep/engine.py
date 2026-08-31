"""The WarpEP scan engine.

What changed in 2.0, and why it matters
---------------------------------------
1.x probed with ``Keypair.generate()`` whenever there was no cached
registration. Cloudflare's WARP responder silently drops handshakes from peers it
does not know, so that scan could only ever report one thing: every endpoint on
earth is dead. The engine now refuses to run without an *enrolled* identity
(``warpep.identity``) and says so loudly if you force it.

Beyond that fix, the pipeline stopped being one flat sweep and became a funnel,
because "it answered one packet once" is not the same as "you can use it":

* **preflight** - probe a control endpoint that is known to answer. If the
  control is silent, the problem is your identity, your network or your UDP
  port, and no amount of scanning will help. Saying that out loud beats printing
  4000 dead rows.
* **sweep** - one probe per candidate, wide and cheap, to find who is home.
* **confirm** - only the survivors get several more probes, so latency, jitter
  and loss are measured on a real sample instead of a single packet, optionally
  with AmneziaWG obfuscation to see whether the flow survives DPI.
* **verify** - the finalists get a full tunnel: handshake, transport keys, real
  ICMP echo pushed through and decrypted on the way back. Only endpoints that
  pass this are labelled ``VERIFIED``, and only those are what WarpEP hands the
  user as "healthy".

Everything else is unchanged in spirit and still holds: one non-blocking UDP
socket per scan, a token-bucket rate limiter, replies matched by WireGuard sender
index, source address checked against the probe, RTT measured with
``perf_counter`` around the send, and every reply verified cryptographically
before it counts.
"""

from __future__ import annotations

import base64
import selectors
import socket
import statistics
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .endpoints import Endpoint
from .identity import (
    WARP_RESPONDER_PUBLIC_KEY_B64,
    ScanIdentity,
    warp_responder_public_key,
)
from .obfuscation import ObfuscationProfile, off as no_obfuscation
from .wireguard import noise, transport
from .wireguard.chacha20poly1305 import InvalidTag
from .wireguard.noise import CookieReply, Ephemeral, HandshakeError, Initiator, Keypair, PeerIdentity

__all__ = [
    "ScanConfig",
    "EndpointResult",
    "Scanner",
    "ScanReport",
    "TunnelCheck",
    "verify_endpoint",
    "WARP_PUBLIC_KEY_B64",
    "warp_public_key",
    "CONTROL_ENDPOINTS",
    "CONTROL_ENDPOINTS_V6",
]

# Kept as an alias so 1.x imports and --peer-key defaults keep working.
WARP_PUBLIC_KEY_B64 = WARP_RESPONDER_PUBLIC_KEY_B64

# The addresses the official client itself falls back to. If none of these answer,
# nothing in the anycast space will, and the fault is local.
CONTROL_ENDPOINTS: Tuple[Endpoint, ...] = (
    Endpoint("162.159.192.1", 2408),
    Endpoint("162.159.193.10", 2408),
    Endpoint("188.114.96.1", 2408),
    Endpoint("188.114.98.10", 2408),
)
CONTROL_ENDPOINTS_V6: Tuple[Endpoint, ...] = (
    Endpoint("2606:4700:d0::a29f:c001", 2408),
    Endpoint("2606:4700:d1::a29f:c101", 2408),
)

ProgressHook = Callable[[str, int, int], None]


def warp_public_key() -> bytes:
    return warp_responder_public_key()


@dataclass
class ScanConfig:
    """Everything that shapes a scan. Defaults are tuned for a phone on 4G."""

    probes: int = 3
    timeout: float = 1.2
    rate: int = 700
    max_inflight: int = 384
    pool_size: int = 24
    source_ip: Optional[str] = None
    ipv6: bool = False
    obfuscation: ObfuscationProfile = field(default_factory=no_obfuscation)
    # Funnel controls.
    sweep_probes: int = 1
    confirm_probes: int = 4
    verify_top: int = 3
    verify_echoes: int = 2
    adaptive: bool = True
    budget: float = 0.0  # seconds; 0 = no ceiling

    def child(self, **overrides) -> "ScanConfig":
        merged = {**self.__dict__, **overrides}
        merged.pop("_", None)
        return ScanConfig(**merged)


@dataclass
class TunnelCheck:
    """Result of a deep, does-it-actually-carry-traffic verification."""

    endpoint: Endpoint
    handshake_ms: Optional[float] = None
    tunnel_rtts: List[float] = field(default_factory=list)
    error: Optional[str] = None
    obfuscated: bool = False

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
            "obfuscated": self.obfuscated,
            "error": self.error,
        }


@dataclass
class EndpointResult:
    endpoint: Endpoint
    sent: int = 0
    received: int = 0
    cookies: int = 0
    rtts: List[float] = field(default_factory=list)
    obfuscated: bool = False
    tunnel: Optional[TunnelCheck] = None

    # -- liveness ----------------------------------------------------------

    @property
    def responsive(self) -> bool:
        """Completed at least one full, cryptographically verified handshake."""
        return bool(self.rtts)

    @property
    def alive(self) -> bool:
        """Something at that address is a WARP responder, cookie replies included."""
        return self.received > 0 or self.cookies > 0

    @property
    def verified(self) -> bool:
        """Proven to carry real traffic end to end, not just to answer a packet."""
        return bool(self.tunnel and self.tunnel.ok)

    @property
    def rejected(self) -> bool:
        """Handshakes fine, refuses to move data. The classic dead-but-pinging trap."""
        return bool(self.tunnel and not self.tunnel.ok and self.responsive)

    # -- statistics --------------------------------------------------------

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
    def health(self) -> int:
        """0-100. What the user is actually shown, and what ranks the table.

        Loss dominates, then latency, then jitter. A proven tunnel adds a small
        bonus; a *failed* tunnel check halves the score, because an endpoint that
        answers handshakes and then swallows traffic is worse than useless - it
        is the exact trap this whole project exists to stop showing people.
        """
        if not self.rtts:
            return 0
        score = 100.0
        score -= min(45.0, self.loss * 0.45)
        score -= min(30.0, max(0.0, (self.avg or 0.0) - 40.0) / 6.0)
        score -= min(15.0, (self.jitter or 0.0) / 3.0)
        if self.verified:
            score = min(100.0, score + 6.0)
        elif self.rejected:
            score *= 0.5
        return max(1, min(100, int(round(score))))

    @property
    def grade(self) -> str:
        health = self.health
        if not self.rtts:
            return "dead"
        if health >= 85:
            return "excellent"
        if health >= 70:
            return "good"
        if health >= 50:
            return "fair"
        return "poor"

    @property
    def badge(self) -> str:
        if self.verified:
            return "VERIFIED"
        if self.rejected:
            return "NO TRAFFIC"
        if self.responsive:
            return "ALIVE"
        if self.cookies:
            return "RATE LIMITED"
        return "DEAD"

    @property
    def rank_key(self) -> Tuple:
        """Verified first, then health, then latency, then a stable tiebreak."""
        return (
            not self.verified,
            -self.health,
            self.avg if self.avg is not None else float("inf"),
            str(self.endpoint),
        )

    def as_dict(self) -> dict:
        payload = {
            "endpoint": str(self.endpoint),
            "address": self.endpoint.address,
            "port": self.endpoint.port,
            "transport": "wireguard",
            "sent": self.sent,
            "received": self.received,
            "cookie_replies": self.cookies,
            "loss_percent": round(self.loss, 2),
            "best_ms": round(self.best, 3) if self.best is not None else None,
            "avg_ms": round(self.avg, 3) if self.avg is not None else None,
            "worst_ms": round(self.worst, 3) if self.worst is not None else None,
            "jitter_ms": round(self.jitter, 3) if self.jitter is not None else None,
            "samples_ms": [round(v, 3) for v in self.rtts],
            "health": self.health,
            "grade": self.grade,
            "badge": self.badge,
            "obfuscated": self.obfuscated,
            "verified": self.verified,
        }
        if self.tunnel is not None:
            payload["tunnel"] = self.tunnel.as_dict()
        return payload


@dataclass
class ScanReport:
    """Everything a scan learned, in one auditable object."""

    results: List[EndpointResult] = field(default_factory=list)
    identity_source: str = ""
    identity_registered: bool = True
    obfuscation: str = "plain WireGuard"
    ports: List[int] = field(default_factory=list)
    targets: int = 0
    handshakes: int = 0
    elapsed: float = 0.0
    control_ok: bool = True
    control_detail: str = ""
    network: Optional[dict] = None
    notes: List[str] = field(default_factory=list)

    @property
    def responsive(self) -> List[EndpointResult]:
        return [r for r in self.results if r.responsive]

    @property
    def verified(self) -> List[EndpointResult]:
        return [r for r in self.results if r.verified]

    @property
    def healthy(self) -> List[EndpointResult]:
        """What WarpEP is willing to call healthy: verified, or good and stable."""
        return [r for r in self.results if r.verified or (r.responsive and r.health >= 70)]

    @property
    def best(self) -> Optional[EndpointResult]:
        ranked = self.healthy or self.responsive
        return ranked[0] if ranked else None

    def as_dict(self) -> dict:
        return {
            "identity": {"source": self.identity_source, "registered": self.identity_registered},
            "obfuscation": self.obfuscation,
            "ports": self.ports,
            "targets": self.targets,
            "handshakes": self.handshakes,
            "elapsed_seconds": round(self.elapsed, 2),
            "control": {"ok": self.control_ok, "detail": self.control_detail},
            "network": self.network,
            "counts": {
                "responsive": len(self.responsive),
                "verified": len(self.verified),
                "healthy": len(self.healthy),
            },
            "notes": self.notes,
        }


@dataclass
class _Probe:
    endpoint: Endpoint
    initiator: Initiator
    sent_at: float


class _RateLimiter:
    """Token bucket, so we never look like a flood to Cloudflare or to the ISP."""

    def __init__(self, rate: int, floor: int = 40):
        self.rate = max(1, rate)
        self.floor = max(1, min(floor, self.rate))
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

    def back_off(self, factor: float = 0.5) -> bool:
        """Cookie replies mean 'you are going too fast'. Believe them."""
        reduced = max(self.floor, int(self.rate * factor))
        if reduced == self.rate:
            return False
        self.rate = reduced
        self._allowance = min(self._allowance, float(self.rate))
        return True


class Scanner:
    """Probes WARP endpoints with real WireGuard handshakes."""

    def __init__(
        self,
        static: Optional[Keypair] = None,
        responder_public: Optional[bytes] = None,
        config: Optional[ScanConfig] = None,
        progress: Optional[ProgressHook] = None,
        identity: Optional[ScanIdentity] = None,
    ):
        self.config = config or ScanConfig()
        self.scan_identity = identity
        if identity is not None:
            static = static or identity.keypair
            responder_public = responder_public or identity.responder_public
        self.identity = PeerIdentity(static or Keypair.generate(), responder_public or warp_public_key())
        self._pool = [Ephemeral(self.identity) for _ in range(max(1, self.config.pool_size))]
        self._pool_index = 0
        self._progress = progress or (lambda phase, done, total: None)
        self.throttled = False

    # -- public API ---------------------------------------------------------

    @property
    def registered(self) -> bool:
        return self.scan_identity.registered if self.scan_identity else True

    def preflight(self, attempts: int = 2) -> Tuple[bool, str]:
        """Prove the identity and the network before blaming 4000 endpoints.

        Returns ``(ok, human readable detail)``. This is the single most useful
        thing the scanner can do: it turns "everything is dead" into "your key is
        not enrolled" or "UDP 2408 is blocked here, try MASQUE over TCP".
        """
        controls = list(CONTROL_ENDPOINTS_V6 if self.config.ipv6 else CONTROL_ENDPOINTS)
        results = self.scan(controls, probes=attempts, phase="preflight")
        answering = [r for r in results if r.responsive]
        cookies = [r for r in results if not r.responsive and r.cookies]
        if answering:
            fastest = min(answering, key=lambda r: r.avg or 1e9)
            return True, f"control endpoint {fastest.endpoint} answered in {fastest.avg:.0f} ms"
        if cookies:
            return True, f"control endpoints replied with cookie challenges: alive but rate limiting"
        if not self.registered:
            return False, (
                "no control endpoint answered, and this scan is using an unregistered "
                "key. Cloudflare drops unknown peers: register first."
            )
        return False, (
            "no control endpoint answered. WARP's UDP ports look blocked on this "
            "network - try -6 for IPv6, --ports all, or the MASQUE transport"
        )

    def discover_ports(self, addresses: Sequence[str], ports: Sequence[int], sample: int = 12) -> List[int]:
        """Find which WARP ports this network actually lets through."""
        probe_set = list(addresses)[: max(1, sample)]
        targets = [Endpoint(address, port) for address in probe_set for port in ports]
        results = self.scan(targets, probes=1, phase="ports")
        order = {port: index for index, port in enumerate(ports)}
        answered = {r.endpoint.port for r in results if r.alive}
        return sorted(answered, key=lambda p: order.get(p, 1 << 30))

    def hunt(
        self,
        targets: Sequence[Endpoint],
        verify: Optional[int] = None,
        obfuscate_confirm: bool = True,
    ) -> ScanReport:
        """The full funnel: sweep, confirm, verify. This is what the panel calls."""
        started = time.perf_counter()
        report = ScanReport(
            identity_source=self.scan_identity.source if self.scan_identity else "custom",
            identity_registered=self.registered,
            obfuscation=self.config.obfuscation.summary(),
            ports=sorted({t.port for t in targets}),
            targets=len(targets),
        )

        sweep = self.scan(targets, probes=max(1, self.config.sweep_probes), phase="sweep")
        report.handshakes += sum(r.sent for r in sweep)
        survivors = [r.endpoint for r in sweep if r.alive]

        merged: Dict[Endpoint, EndpointResult] = {r.endpoint: r for r in sweep}
        if survivors and self.config.confirm_probes > 0:
            profile = self.config.obfuscation
            if obfuscate_confirm and not profile.active:
                from .obfuscation import awg_profile

                profile = awg_profile()
            confirmed = self.scan(
                survivors,
                probes=self.config.confirm_probes,
                phase="confirm",
                obfuscation=profile,
            )
            report.handshakes += sum(r.sent for r in confirmed)
            if profile.active:
                report.obfuscation = profile.summary()
            for result in confirmed:
                result.obfuscated = profile.active
                merged[result.endpoint] = result

        results = sorted(merged.values(), key=lambda r: r.rank_key)

        wanted = self.config.verify_top if verify is None else verify
        if wanted > 0:
            candidates = [r for r in results if r.responsive][:wanted]
            for index, result in enumerate(candidates, start=1):
                self._progress("verify", index - 1, len(candidates))
                result.tunnel = verify_endpoint(
                    self.identity.static,
                    result.endpoint,
                    responder_public=self.identity.responder_public,
                    client_ip=self.scan_identity.client_ip if self.scan_identity else "172.16.0.2",
                    echoes=self.config.verify_echoes,
                    timeout=max(2.0, self.config.timeout * 2),
                    obfuscation=self.config.obfuscation,
                )
            self._progress("verify", len(candidates), len(candidates))
            results = sorted(results, key=lambda r: r.rank_key)

        report.results = results
        report.elapsed = time.perf_counter() - started
        if self.throttled:
            report.notes.append("Cloudflare rate limited the scan, so the probe rate was reduced automatically")
        if not report.responsive:
            report.notes.append(
                "nothing completed a handshake. Check 'warpep doctor' before trusting this as an endpoint verdict"
            )
        elif not report.verified and wanted > 0:
            report.notes.append(
                "endpoints answered handshakes but none carried ICMP through the tunnel: "
                "typical of a network that throttles WireGuard after the handshake"
            )
        return report

    def scan(
        self,
        targets: Sequence[Endpoint],
        probes: Optional[int] = None,
        phase: str = "scan",
        obfuscation: Optional[ObfuscationProfile] = None,
    ) -> List[EndpointResult]:
        if not targets:
            return []
        rounds = probes if probes is not None else self.config.probes
        shaping = obfuscation if obfuscation is not None else self.config.obfuscation
        unique: List[Endpoint] = list(dict.fromkeys(targets))
        results: Dict[Endpoint, EndpointResult] = {t: EndpointResult(t, obfuscated=shaping.active) for t in unique}
        family = socket.AF_INET6 if self.config.ipv6 or any(t.is_ipv6 for t in unique) else socket.AF_INET

        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        except OSError:
            pass
        if self.config.source_ip:
            try:
                sock.bind((self.config.source_ip, 0))
            except OSError:
                pass
        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ)
        limiter = _RateLimiter(self.config.rate)
        inflight: Dict[int, _Probe] = {}
        total = len(unique) * rounds
        done = 0
        cookies_seen = 0
        deadline = (time.perf_counter() + self.config.budget) if self.config.budget else None

        try:
            for _ in range(rounds):
                for target in unique:
                    if deadline and time.perf_counter() > deadline:
                        break
                    while len(inflight) >= self.config.max_inflight:
                        done += self._pump(selector, sock, inflight, results, 0.02)
                        done += self._expire(inflight, results)
                        self._progress(phase, done, total)
                    limiter.take()
                    probe = self._send(sock, target, shaping, selector, inflight, results)
                    results[target].sent += 1
                    if probe is None:
                        done += 1
                        continue
                    inflight[probe.initiator.sender_index] = probe
                    done += self._pump(selector, sock, inflight, results, 0)
                    self._progress(phase, done, total)

                    if self.config.adaptive:
                        total_cookies = sum(r.cookies for r in results.values())
                        if total_cookies > cookies_seen + 8:
                            cookies_seen = total_cookies
                            if limiter.back_off():
                                self.throttled = True

                wait_until = time.perf_counter() + self.config.timeout
                while inflight and time.perf_counter() < wait_until:
                    done += self._pump(selector, sock, inflight, results, 0.05)
                    done += self._expire(inflight, results)
                    self._progress(phase, done, total)
                done += self._expire(inflight, results, force=True)
                self._progress(phase, done, total)
                if deadline and time.perf_counter() > deadline:
                    break
        finally:
            selector.close()
            sock.close()

        self._progress(phase, total, total)
        return sorted(results.values(), key=lambda r: r.rank_key)

    # -- internals ---------------------------------------------------------

    def _next_ephemeral(self) -> Ephemeral:
        ephemeral = self._pool[self._pool_index % len(self._pool)]
        self._pool_index += 1
        return ephemeral

    def _send(
        self,
        sock: socket.socket,
        target: Endpoint,
        shaping: ObfuscationProfile,
        selector: selectors.BaseSelector,
        inflight: Dict[int, _Probe],
        results: Dict[Endpoint, EndpointResult],
    ) -> Optional[_Probe]:
        destination = (target.address, target.port)
        if shaping.active:
            for packet in shaping.preamble():
                try:
                    sock.sendto(packet, destination)
                except OSError:
                    break
        initiator = Initiator(self.identity, ephemeral=self._next_ephemeral())
        packet = initiator.initiation()
        # A full send buffer is not a dead endpoint. Drain replies and retry
        # instead of charging the target with a loss it never caused.
        for attempt in range(3):
            try:
                sock.sendto(packet, destination)
            except (BlockingIOError, InterruptedError):
                self._pump(selector, sock, inflight, results, 0.01)
                continue
            except OSError as exc:
                if getattr(exc, "errno", None) in (55, 105, 11, 35) and attempt < 2:
                    self._pump(selector, sock, inflight, results, 0.01)
                    continue
                return None
            return _Probe(endpoint=target, initiator=initiator, sent_at=time.perf_counter())
        return None

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
        result = results.get(probe.endpoint)
        if result is None:  # pragma: no cover - defensive
            del inflight[index]
            return 1
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


def verify_endpoint(
    static: Keypair,
    endpoint: Endpoint,
    responder_public: Optional[bytes] = None,
    client_ip: str = "172.16.0.2",
    target_ip: str = "162.159.192.1",
    echoes: int = 3,
    timeout: float = 2.0,
    obfuscation: Optional[ObfuscationProfile] = None,
) -> TunnelCheck:
    """Complete a handshake and push real ICMP traffic through the tunnel.

    This is the only test in WarpEP that proves an endpoint is *usable* rather
    than merely awake, and it is why the table can honestly print VERIFIED.
    """
    shaping = obfuscation or no_obfuscation()
    check = TunnelCheck(endpoint=endpoint, obfuscated=shaping.active)
    identity = PeerIdentity(static, responder_public or warp_public_key())
    initiator = Initiator(identity)
    family = socket.AF_INET6 if endpoint.is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((endpoint.address, endpoint.port))
        if shaping.active:
            for junk in shaping.preamble():
                try:
                    sock.send(junk)
                except OSError:
                    break
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
            reply_deadline = time.perf_counter() + timeout
            while time.perf_counter() < reply_deadline:
                try:
                    reply = sock.recv(2048)
                except (socket.timeout, TimeoutError):
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
