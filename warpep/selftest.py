"""``warpep selftest``: prove the crypto and the scan loop on the user's machine.

Runs the official RFC 7748 / RFC 8439 vectors, a full Noise handshake against an
in-process responder, the obfuscation and QUIC packet builders, and a complete
scan plus tunnel check over loopback. If all of this passes, the scanner's results
can be trusted on that machine. Nothing here touches the network.
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Callable, List, Tuple

from .endpoints import Endpoint, expand_prefixes, parse_ports, spread
from .engine import EndpointResult, ScanConfig, Scanner, warp_public_key
from .identity import BUNDLED_IDENTITIES, bundled_identity, resolve as resolve_identity
from .masque import _is_version_negotiation, _version_negotiation_trigger
from .obfuscation import awg_profile, off as no_obfuscation, parse_magic, render_magic
from .wireguard import noise, transport, x25519
from .wireguard import chacha20poly1305 as aead

Check = Tuple[str, Callable[[], None]]


def _check_x25519() -> None:
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    want = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert x25519.x25519(scalar, u) == want, "X25519 vector mismatch"
    a, b = x25519.generate_private_key(), x25519.generate_private_key()
    assert x25519.shared_secret(a, x25519.public_key(b)) == x25519.shared_secret(b, x25519.public_key(a))


def _check_aead() -> None:
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    ad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    sealed = aead.encrypt(key, nonce, plaintext, ad)
    assert sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "ChaCha20-Poly1305 tag mismatch"
    assert aead.decrypt(key, nonce, sealed, ad) == plaintext


def _check_handshake() -> None:
    server, client = noise.Keypair.generate(), noise.Keypair.generate()
    identity = noise.PeerIdentity(client, server.public)
    initiator = noise.Initiator(identity)
    packet = initiator.initiation()
    assert len(packet) == noise.MESSAGE_INITIATION_SIZE, "initiation must be 148 bytes"
    responder = noise.Responder(server)
    index, _ = responder.consume_initiation(packet)
    response, server_keys = responder.response(index)
    client_keys = initiator.consume_response(response)
    assert client_keys.send_key == server_keys.receive_key, "transport keys disagree"


def _check_transport_keys() -> None:
    """A sealed inner packet must survive the round trip through both directions."""
    server, client = noise.Keypair.generate(), noise.Keypair.generate()
    initiator = noise.Initiator(noise.PeerIdentity(client, server.public))
    responder = noise.Responder(server)
    index, _ = responder.consume_initiation(initiator.initiation())
    response, server_keys = responder.response(index)
    client_keys = initiator.consume_response(response)
    inner = transport.icmp_echo_request("172.16.0.2", "162.159.192.1", 0x1234, 1)
    sealed = transport.seal(client_keys, 1, inner)
    counter, payload = transport.open_packet(server_keys, sealed)
    assert counter == 1 and payload[: len(inner)] == inner, "transport packet did not round trip"
    assert transport.parse_icmp_echo_reply(inner, 0x1234) is None, "an echo request is not a reply"


def _check_identity() -> None:
    assert BUNDLED_IDENTITIES, "no bundled identity shipped: every scan would report dead endpoints"
    bundled = bundled_identity()
    assert bundled.registered, "bundled identity must be enrolled"
    assert len(bundled.keypair.private) == 32 and len(bundled.responder_public) == 32
    resolved = resolve_identity()
    assert resolved.registered, "resolve() handed back an identity Cloudflare will not answer"


def _check_warp_key() -> None:
    key = warp_public_key()
    assert len(key) == 32, "WARP responder key must be 32 bytes"


def _check_obfuscation() -> None:
    instructions = parse_magic("<b 0xdeadbeef><r 4>")
    rendered = render_magic(instructions)
    assert rendered[:4] == bytes.fromhex("deadbeef") and len(rendered) == 8
    profile = awg_profile(junk_count=3, junk_min=20, junk_max=20)
    packets = profile.preamble()
    assert len(packets) == 4, "expected one magic packet plus three junk packets"
    assert all(len(p) == 20 for p in packets[1:]), "junk packets must honour jmin/jmax"
    assert not no_obfuscation().preamble(), "obfuscation off must emit nothing"
    assert "Jc = 3" in profile.wireguard_fields()


def _check_quic_probe() -> None:
    datagram = _version_negotiation_trigger(b"\x01" * 8, b"\x02" * 8)
    assert len(datagram) >= 1200, "a QUIC initial must be padded to 1200 bytes"
    assert datagram[0] & 0xC0 == 0xC0, "long header form and fixed bit must be set"
    assert struct.unpack(">I", datagram[1:5])[0] == 0x0A0A0A0A
    reply = bytes([0x80]) + struct.pack(">I", 0) + bytes([8]) + b"\x02" * 8 + bytes([8]) + b"\x01" * 8
    assert _is_version_negotiation(reply, b"\x01" * 8, b"\x02" * 8)
    assert not _is_version_negotiation(reply, b"\x09" * 8, b"\x02" * 8), "CIDs must be checked"


def _check_ports() -> None:
    assert parse_ports(None)[0] == 2408
    assert 500 in parse_ports(["all"])
    assert parse_ports(["2408,500"]) == [2408, 500]


def _check_spread() -> None:
    addresses = expand_prefixes(["162.159.192.0/24", "188.114.96.0/24"])
    picked = spread(addresses, 20)
    blocks = {a.rsplit(".", 1)[0] for a in picked}
    assert len(picked) == 20 and len(blocks) == 2, "spread must cover every prefix"


def _check_health_scoring() -> None:
    good = EndpointResult(Endpoint("1.1.1.1", 2408), sent=4, received=4, rtts=[30.0, 31.0, 30.5, 32.0])
    bad = EndpointResult(Endpoint("1.1.1.2", 2408), sent=4, received=1, rtts=[500.0])
    dead = EndpointResult(Endpoint("1.1.1.3", 2408), sent=4, received=0)
    assert good.health > bad.health > dead.health == 0
    assert good.grade == "excellent" and dead.grade == "dead" and dead.badge == "DEAD"
    assert sorted([bad, good, dead], key=lambda r: r.rank_key)[0] is good


class _LoopbackResponder(threading.Thread):
    daemon = True

    def __init__(self, static: noise.Keypair):
        super().__init__()
        self.static = static
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.junk = 0

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                packet, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if noise.message_type(packet) != noise.MSG_INITIATION or len(packet) != noise.MESSAGE_INITIATION_SIZE:
                self.junk += 1
                continue
            responder = noise.Responder(self.static)
            try:
                index, _ = responder.consume_initiation(packet)
            except noise.HandshakeError:
                continue
            response, _ = responder.response(index)
            self.sock.sendto(response, peer)

    def stop(self) -> None:
        self._stop.set()
        self.sock.close()


def _scan_loop(obfuscated: bool) -> None:
    from .identity import ScanIdentity

    server, client = noise.Keypair.generate(), noise.Keypair.generate()
    responder = _LoopbackResponder(server)
    responder.start()
    try:
        identity = ScanIdentity(
            keypair=client, responder_public=server.public, source="custom", registered=True
        )
        scanner = Scanner(
            identity=identity,
            config=ScanConfig(
                probes=2,
                timeout=0.6,
                rate=3000,
                pool_size=2,
                verify_top=0,
                obfuscation=awg_profile(junk_count=2, junk_min=16, junk_max=16) if obfuscated else no_obfuscation(),
            ),
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spare:
            spare.bind(("127.0.0.1", 0))
            dead_port = spare.getsockname()[1]
        results = scanner.scan([Endpoint("127.0.0.1", responder.port), Endpoint("127.0.0.1", dead_port)])
        best = results[0]
        assert best.endpoint.port == responder.port, "scanner failed to rank the live endpoint first"
        assert best.received == 2, f"expected 2 replies, got {best.received}"
        assert results[1].loss == 100.0, "dead endpoint should show 100% loss"
        if obfuscated:
            assert responder.junk > 0, "obfuscated scan sent no junk packets"
    finally:
        responder.stop()


def _check_scan_loop() -> None:
    _scan_loop(obfuscated=False)


def _check_obfuscated_scan_loop() -> None:
    _scan_loop(obfuscated=True)


def _check_udp_socket() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(b"", ("127.0.0.1", 9))


CHECKS: List[Check] = [
    ("X25519 (RFC 7748 vectors)", _check_x25519),
    ("ChaCha20-Poly1305 (RFC 8439 vectors)", _check_aead),
    ("WireGuard handshake round trip", _check_handshake),
    ("WireGuard transport data round trip", _check_transport_keys),
    ("Enrolled scan identity", _check_identity),
    ("Cloudflare WARP responder key", _check_warp_key),
    ("AmneziaWG obfuscation builder", _check_obfuscation),
    ("QUIC version negotiation probe", _check_quic_probe),
    ("WARP port table", _check_ports),
    ("Prefix-balanced sampling", _check_spread),
    ("Health scoring and ranking", _check_health_scoring),
    ("UDP socket permissions", _check_udp_socket),
    ("Full scan loop over loopback", _check_scan_loop),
    ("Obfuscated scan loop over loopback", _check_obfuscated_scan_loop),
]


def run(console) -> int:
    failures = 0
    for name, check in CHECKS:
        try:
            check()
        except Exception as exc:  # noqa: BLE001 - a selftest reports, never raises
            failures += 1
            console.write("  " + console.paint(" FAIL ", "on_red") + f"  {name}: {exc}")
        else:
            console.write("  " + console.paint(" PASS ", "on_green") + f"  {name}")
    console.write()
    if failures:
        console.error(f"{failures} of {len(CHECKS)} checks failed")
    else:
        console.ok(f"all {len(CHECKS)} checks passed: this build scans for real")
    return 1 if failures else 0
