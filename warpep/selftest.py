"""``warpep selftest``: prove the crypto and the scan loop on the user's machine.

Runs the official RFC 7748 / RFC 8439 vectors, a full Noise handshake against an
in-process responder, and a complete scan plus tunnel check over loopback. If all
of this passes, the scanner's results can be trusted on that machine.
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Callable, List, Tuple

from .endpoints import Endpoint, parse_ports
from .engine import ScanConfig, Scanner, warp_public_key
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


def _check_warp_key() -> None:
    key = warp_public_key()
    assert len(key) == 32, "WARP responder key must be 32 bytes"


def _check_ports() -> None:
    assert parse_ports(None)[0] == 2408
    assert 500 in parse_ports(["all"])


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
        self.sessions = {}

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                packet, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if noise.message_type(packet) != noise.MSG_INITIATION:
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


def _check_scan_loop() -> None:
    server, client = noise.Keypair.generate(), noise.Keypair.generate()
    responder = _LoopbackResponder(server)
    responder.start()
    try:
        scanner = Scanner(
            static=client,
            responder_public=server.public,
            config=ScanConfig(probes=2, timeout=0.6, rate=2000, pool_size=2),
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spare:
            spare.bind(("127.0.0.1", 0))
            dead_port = spare.getsockname()[1]
        results = scanner.scan([Endpoint("127.0.0.1", responder.port), Endpoint("127.0.0.1", dead_port)])
        best = results[0]
        assert best.endpoint.port == responder.port, "scanner failed to rank the live endpoint first"
        assert best.received == 2, f"expected 2 replies, got {best.received}"
        assert results[1].loss == 100.0, "dead endpoint should show 100% loss"
    finally:
        responder.stop()


def _check_udp_socket() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(b"", ("127.0.0.1", 9))


CHECKS: List[Check] = [
    ("X25519 (RFC 7748 vectors)", _check_x25519),
    ("ChaCha20-Poly1305 (RFC 8439 vectors)", _check_aead),
    ("WireGuard handshake round trip", _check_handshake),
    ("Cloudflare WARP responder key", _check_warp_key),
    ("WARP port table", _check_ports),
    ("UDP socket permissions", _check_udp_socket),
    ("Full scan loop over loopback", _check_scan_loop),
]


def run(console) -> int:
    failures = 0
    for name, check in CHECKS:
        try:
            check()
        except Exception as exc:  # noqa: BLE001 - a selftest reports, never raises
            failures += 1
            console.write(console.paint("  FAIL  ", "bright_red", "bold") + f"{name}: {exc}")
        else:
            console.write(console.paint("  PASS  ", "bright_green", "bold") + name)
    console.write()
    if failures:
        console.error(f"{failures} of {len(CHECKS)} checks failed")
    else:
        console.ok(f"all {len(CHECKS)} checks passed: this build scans for real")
    return 1 if failures else 0
