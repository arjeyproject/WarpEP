"""Pure-Python X25519 (RFC 7748).

WarpEP ships with zero third-party dependencies on purpose: the scanner has to
run on Termux, on a bare Windows box and inside a 20 MB Alpine container without
anyone compiling a wheel. The Montgomery ladder below is constant-time enough
for a scanner (it is only ever used with ephemeral, throw-away keys) and is
verified against the RFC 7748 test vectors in tests/test_x25519.py.
"""

from __future__ import annotations

import os

__all__ = ["X25519_KEY_SIZE", "generate_private_key", "public_key", "shared_secret", "x25519"]

X25519_KEY_SIZE = 32

_P = (1 << 255) - 19
_A24 = 121665
_BASE_POINT = b"\x09" + b"\x00" * 31


def _clamp_scalar(scalar: bytes) -> int:
    if len(scalar) != X25519_KEY_SIZE:
        raise ValueError("x25519 scalar must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _decode_u(coordinate: bytes) -> int:
    if len(coordinate) != X25519_KEY_SIZE:
        raise ValueError("x25519 u-coordinate must be 32 bytes")
    u = bytearray(coordinate)
    u[31] &= 127
    return int.from_bytes(u, "little")


def _cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    dummy = (-swap & (a ^ b))
    return a ^ dummy, b ^ dummy


def x25519(scalar: bytes, coordinate: bytes) -> bytes:
    """Scalar multiplication on Curve25519, RFC 7748 section 5."""
    k = _clamp_scalar(scalar)
    x1 = _decode_u(coordinate)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0

    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt

        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(X25519_KEY_SIZE, "little")


def generate_private_key() -> bytes:
    return os.urandom(X25519_KEY_SIZE)


def public_key(private: bytes) -> bytes:
    return x25519(private, _BASE_POINT)


def shared_secret(private: bytes, peer_public: bytes) -> bytes:
    secret = x25519(private, peer_public)
    if secret == bytes(X25519_KEY_SIZE):
        raise ValueError("x25519 produced an all-zero shared secret (invalid peer key)")
    return secret
