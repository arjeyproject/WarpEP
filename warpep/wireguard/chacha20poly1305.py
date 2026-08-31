"""Pure-Python ChaCha20-Poly1305 AEAD (RFC 8439).

Only the pieces WireGuard needs are implemented: AEAD_CHACHA20_POLY1305 with a
96-bit nonce. Verified against the RFC 8439 test vectors.
"""

from __future__ import annotations

import struct
from typing import List

__all__ = ["KEY_SIZE", "NONCE_SIZE", "TAG_SIZE", "InvalidTag", "encrypt", "decrypt", "chacha20_block", "poly1305_mac"]

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

_MASK32 = 0xFFFFFFFF
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


class InvalidTag(Exception):
    """Raised when an AEAD ciphertext fails authentication."""


def _rotl32(value: int, count: int) -> int:
    value &= _MASK32
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("chacha20 key must be 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("chacha20 nonce must be 12 bytes")

    initial = list(_SIGMA)
    initial += list(struct.unpack("<8I", key))
    initial.append(counter & _MASK32)
    initial += list(struct.unpack("<3I", nonce))

    state = list(initial)
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    return struct.pack("<16I", *[(state[i] + initial[i]) & _MASK32 for i in range(16)])


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    for offset in range(0, len(data), 64):
        chunk = data[offset : offset + 64]
        stream = chacha20_block(key, counter + offset // 64, nonce)
        for i, byte in enumerate(chunk):
            out[offset + i] = byte ^ stream[i]
    return bytes(out)


_POLY_P = (1 << 130) - 5


def poly1305_mac(key: bytes, message: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = (acc + n) * r % _POLY_P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return b"" if remainder == 0 else b"\x00" * (16 - remainder)


def _tag(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    return poly1305_mac(poly_key, mac_data)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    ciphertext = _chacha20_xor(key, 1, nonce, plaintext)
    return ciphertext + _tag(key, nonce, ciphertext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if len(ciphertext) < TAG_SIZE:
        raise InvalidTag("ciphertext shorter than the authentication tag")
    body, tag = ciphertext[:-TAG_SIZE], ciphertext[-TAG_SIZE:]
    expected = _tag(key, nonce, body, aad)
    # Constant-time comparison: never leak where the mismatch happened.
    if not _constant_time_eq(tag, expected):
        raise InvalidTag("authentication tag mismatch")
    return _chacha20_xor(key, 1, nonce, body)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
