"""The real WireGuard handshake (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s).

This module is what makes WarpEP a *real* endpoint scanner instead of a UDP port
poker. Every probe is a cryptographically valid WireGuard handshake initiation
addressed to Cloudflare's WARP responder key, and every reply is verified three
ways before an endpoint is called alive:

1. the response MAC1 must be keyed with our own static public key,
2. the mixed chaining key must decrypt the response's empty AEAD payload,
3. the receiver index must match the sender index we sent.

A random UDP responder, a middlebox or a captive portal cannot fake any of that.
Cookie replies (message type 3) are recognised too: they mean the endpoint is
alive but rate limiting, which is useful signal rather than a failure.

Reference: "WireGuard: Next Generation Kernel Network Tunnel", section 5.4.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

from . import x25519
from .chacha20poly1305 import InvalidTag, decrypt, encrypt

__all__ = [
    "CONSTRUCTION",
    "IDENTIFIER",
    "MESSAGE_INITIATION_SIZE",
    "MESSAGE_RESPONSE_SIZE",
    "MSG_COOKIE_REPLY",
    "MSG_DATA",
    "MSG_INITIATION",
    "MSG_RESPONSE",
    "CookieReply",
    "HandshakeError",
    "Keypair",
    "TransportKeys",
    "Initiator",
    "Responder",
    "message_type",
]

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

MSG_INITIATION = 1
MSG_RESPONSE = 2
MSG_COOKIE_REPLY = 3
MSG_DATA = 4

MESSAGE_INITIATION_SIZE = 148
MESSAGE_RESPONSE_SIZE = 92
MESSAGE_COOKIE_REPLY_SIZE = 64

_ZERO_NONCE = bytes(12)
_ZERO_PSK = bytes(32)
_BLANK_MAC2 = bytes(16)


class HandshakeError(Exception):
    """A handshake message was malformed, unauthenticated or unexpected."""


class CookieReply(HandshakeError):
    """The responder replied with a cookie challenge: alive, but under load."""


def _hash(*chunks: bytes) -> bytes:
    digest = hashlib.blake2s(digest_size=32)
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def _mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def _kdf(key: bytes, data: bytes, outputs: int) -> Tuple[bytes, ...]:
    tau0 = _hmac(key, data)
    result = []
    previous = b""
    for index in range(1, outputs + 1):
        previous = _hmac(tau0, previous + bytes([index]))
        result.append(previous)
    return tuple(result)


def tai64n(now: Optional[float] = None) -> bytes:
    """12-byte TAI64N timestamp as used by WireGuard's replay protection."""
    if now is None:
        now = time.time()
    seconds = int(now)
    nanoseconds = int((now - seconds) * 1e9)
    # WireGuard truncates the nanosecond field for monotonicity friendliness.
    return struct.pack(">Q", 0x400000000000000A + seconds) + struct.pack(">I", nanoseconds)


def message_type(packet: bytes) -> int:
    if not packet:
        return 0
    return packet[0]


@dataclass(frozen=True)
class Keypair:
    """A Curve25519 static or ephemeral keypair."""

    private: bytes
    public: bytes

    @classmethod
    def generate(cls) -> "Keypair":
        private = x25519.generate_private_key()
        return cls(private=private, public=x25519.public_key(private))

    @classmethod
    def from_private(cls, private: bytes) -> "Keypair":
        if len(private) != 32:
            raise ValueError("private key must be 32 bytes")
        return cls(private=private, public=x25519.public_key(private))

    @classmethod
    def from_base64(cls, encoded: str) -> "Keypair":
        import base64

        return cls.from_private(base64.b64decode(encoded.strip() + "=" * (-len(encoded.strip()) % 4)))

    @property
    def private_b64(self) -> str:
        import base64

        return base64.b64encode(self.private).decode()

    @property
    def public_b64(self) -> str:
        import base64

        return base64.b64encode(self.public).decode()


@dataclass(frozen=True)
class TransportKeys:
    """Post-handshake data keys plus the indices needed to talk on the wire."""

    send_key: bytes
    receive_key: bytes
    sender_index: int
    receiver_index: int


@dataclass
class _Symmetric:
    chaining_key: bytes
    hash: bytes

    def mix_hash(self, data: bytes) -> None:
        self.hash = _hash(self.hash, data)

    def mix_key(self, data: bytes) -> bytes:
        self.chaining_key, key = _kdf(self.chaining_key, data, 2)
        return key

    def mix_key_only(self, data: bytes) -> None:
        (self.chaining_key,) = _kdf(self.chaining_key, data, 1)


def _initial_state(responder_static_public: bytes) -> _Symmetric:
    chaining_key = _hash(CONSTRUCTION)
    handshake_hash = _hash(chaining_key, IDENTIFIER)
    handshake_hash = _hash(handshake_hash, responder_static_public)
    return _Symmetric(chaining_key=chaining_key, hash=handshake_hash)


class PeerIdentity:
    """Caches the expensive, reusable half of the handshake maths.

    ``DH(Spriv_i, Spub_r)`` and the MAC1 keys never change for a given
    (client static key, server static key) pair, so the scanner computes them
    once and then builds thousands of handshake packets almost for free.
    """

    __slots__ = ("static", "responder_public", "_static_static", "_mac1_key_out", "_mac1_key_in")

    def __init__(self, static: Keypair, responder_public: bytes):
        if len(responder_public) != 32:
            raise ValueError("responder public key must be 32 bytes")
        self.static = static
        self.responder_public = responder_public
        self._static_static = x25519.shared_secret(static.private, responder_public)
        self._mac1_key_out = _hash(LABEL_MAC1, responder_public)
        self._mac1_key_in = _hash(LABEL_MAC1, static.public)

    @property
    def static_static(self) -> bytes:
        return self._static_static

    @property
    def mac1_key_out(self) -> bytes:
        return self._mac1_key_out

    @property
    def mac1_key_in(self) -> bytes:
        return self._mac1_key_in


class Ephemeral:
    """An ephemeral keypair with its server DH precomputed.

    Reused across endpoints during a scan: each endpoint still receives a unique,
    fresh, fully valid handshake (unique sender index and TAI64N timestamp), but
    we pay the Curve25519 cost once per pool slot instead of once per probe.
    """

    __slots__ = ("keypair", "ephemeral_static")

    def __init__(self, identity: PeerIdentity, keypair: Optional[Keypair] = None):
        self.keypair = keypair or Keypair.generate()
        self.ephemeral_static = x25519.shared_secret(self.keypair.private, identity.responder_public)


class Initiator:
    """Builds a handshake initiation and validates the responder's answer."""

    __slots__ = ("identity", "ephemeral", "sender_index", "_state", "_consumed")

    def __init__(
        self,
        identity: PeerIdentity,
        ephemeral: Optional[Ephemeral] = None,
        sender_index: Optional[int] = None,
    ):
        self.identity = identity
        self.ephemeral = ephemeral or Ephemeral(identity)
        self.sender_index = sender_index if sender_index is not None else struct.unpack("<I", os.urandom(4))[0]
        self._state = _initial_state(identity.responder_public)
        self._consumed = False

    def initiation(self, timestamp: Optional[bytes] = None, cookie: Optional[bytes] = None) -> bytes:
        state = self._state
        ephemeral_public = self.ephemeral.keypair.public

        state.mix_key_only(ephemeral_public)
        state.mix_hash(ephemeral_public)

        key = state.mix_key(self.ephemeral.ephemeral_static)
        encrypted_static = encrypt(key, _ZERO_NONCE, self.identity.static.public, state.hash)
        state.mix_hash(encrypted_static)

        key = state.mix_key(self.identity.static_static)
        encrypted_timestamp = encrypt(key, _ZERO_NONCE, timestamp or tai64n(), state.hash)
        state.mix_hash(encrypted_timestamp)

        body = (
            struct.pack("<B3x I", MSG_INITIATION, self.sender_index)
            + ephemeral_public
            + encrypted_static
            + encrypted_timestamp
        )
        mac1 = _mac(self.identity.mac1_key_out, body)
        mac2 = _BLANK_MAC2
        if cookie:
            mac2 = _mac(cookie, body + mac1)
        packet = body + mac1 + mac2
        assert len(packet) == MESSAGE_INITIATION_SIZE
        return packet

    def consume_response(self, packet: bytes, preshared_key: bytes = _ZERO_PSK) -> TransportKeys:
        if len(packet) == MESSAGE_COOKIE_REPLY_SIZE and message_type(packet) == MSG_COOKIE_REPLY:
            raise CookieReply("responder issued a cookie challenge")
        if len(packet) != MESSAGE_RESPONSE_SIZE:
            raise HandshakeError(f"expected a {MESSAGE_RESPONSE_SIZE}-byte response, got {len(packet)}")
        if message_type(packet) != MSG_RESPONSE:
            raise HandshakeError(f"unexpected message type {message_type(packet)}")
        if self._consumed:
            raise HandshakeError("handshake already completed")

        sender_index, receiver_index = struct.unpack("<II", packet[4:12])
        if receiver_index != self.sender_index:
            raise HandshakeError("response addressed to a different handshake")

        expected_mac1 = _mac(self.identity.mac1_key_in, packet[:60])
        if not hmac.compare_digest(expected_mac1, packet[60:76]):
            raise HandshakeError("response MAC1 mismatch: not a reply from a WireGuard peer")

        peer_ephemeral = packet[12:44]
        encrypted_nothing = packet[44:60]

        state = self._state
        state.mix_key_only(peer_ephemeral)
        state.mix_hash(peer_ephemeral)
        state.mix_key_only(x25519.shared_secret(self.ephemeral.keypair.private, peer_ephemeral))
        state.mix_key_only(x25519.shared_secret(self.identity.static.private, peer_ephemeral))

        state.chaining_key, tau, key = _kdf(state.chaining_key, preshared_key, 3)
        state.mix_hash(tau)
        try:
            decrypt(key, _ZERO_NONCE, encrypted_nothing, state.hash)
        except InvalidTag as exc:
            raise HandshakeError("response failed authentication") from exc
        state.mix_hash(encrypted_nothing)

        send_key, receive_key = _kdf(state.chaining_key, b"", 2)
        self._consumed = True
        return TransportKeys(
            send_key=send_key,
            receive_key=receive_key,
            sender_index=self.sender_index,
            receiver_index=sender_index,
        )


class Responder:
    """A minimal responder.

    WarpEP does not run a server, but the offline test suite needs a second party
    to prove the initiator is protocol-correct without touching the network.
    """

    __slots__ = ("static", "sender_index", "_state", "peer_static_public", "_peer_ephemeral")

    def __init__(self, static: Keypair, sender_index: Optional[int] = None):
        self.static = static
        self.sender_index = sender_index if sender_index is not None else struct.unpack("<I", os.urandom(4))[0]
        self._state = _initial_state(static.public)
        self.peer_static_public = b""
        self._peer_ephemeral = b""

    def consume_initiation(self, packet: bytes) -> Tuple[int, bytes]:
        if len(packet) != MESSAGE_INITIATION_SIZE or message_type(packet) != MSG_INITIATION:
            raise HandshakeError("malformed handshake initiation")
        if not hmac.compare_digest(_mac(_hash(LABEL_MAC1, self.static.public), packet[:116]), packet[116:132]):
            raise HandshakeError("initiation MAC1 mismatch")

        (peer_index,) = struct.unpack("<I", packet[4:8])
        peer_ephemeral = packet[8:40]
        encrypted_static = packet[40:88]
        encrypted_timestamp = packet[88:116]

        state = self._state
        state.mix_key_only(peer_ephemeral)
        state.mix_hash(peer_ephemeral)

        key = state.mix_key(x25519.shared_secret(self.static.private, peer_ephemeral))
        try:
            peer_static = decrypt(key, _ZERO_NONCE, encrypted_static, state.hash)
        except InvalidTag as exc:
            raise HandshakeError("could not decrypt peer static key") from exc
        state.mix_hash(encrypted_static)

        key = state.mix_key(x25519.shared_secret(self.static.private, peer_static))
        try:
            timestamp = decrypt(key, _ZERO_NONCE, encrypted_timestamp, state.hash)
        except InvalidTag as exc:
            raise HandshakeError("could not decrypt timestamp") from exc
        state.mix_hash(encrypted_timestamp)

        self.peer_static_public = peer_static
        self._peer_ephemeral = peer_ephemeral
        return peer_index, timestamp

    def response(self, peer_index: int, preshared_key: bytes = _ZERO_PSK) -> Tuple[bytes, TransportKeys]:
        ephemeral = Keypair.generate()
        state = self._state

        state.mix_key_only(ephemeral.public)
        state.mix_hash(ephemeral.public)
        state.mix_key_only(x25519.shared_secret(ephemeral.private, self._peer_ephemeral))
        state.mix_key_only(x25519.shared_secret(ephemeral.private, self.peer_static_public))

        state.chaining_key, tau, key = _kdf(state.chaining_key, preshared_key, 3)
        state.mix_hash(tau)
        encrypted_nothing = encrypt(key, _ZERO_NONCE, b"", state.hash)
        state.mix_hash(encrypted_nothing)

        body = (
            struct.pack("<B3x II", MSG_RESPONSE, self.sender_index, peer_index)
            + ephemeral.public
            + encrypted_nothing
        )
        mac1 = _mac(_hash(LABEL_MAC1, self.peer_static_public), body)
        packet = body + mac1 + _BLANK_MAC2
        assert len(packet) == MESSAGE_RESPONSE_SIZE

        receive_key, send_key = _kdf(state.chaining_key, b"", 2)
        return packet, TransportKeys(
            send_key=send_key,
            receive_key=receive_key,
            sender_index=self.sender_index,
            receiver_index=peer_index,
        )
