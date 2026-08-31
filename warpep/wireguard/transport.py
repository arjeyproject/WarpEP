"""WireGuard transport-data plane, used by WarpEP's deep verification mode.

Latency from a handshake proves an endpoint's WireGuard responder is alive. It
does not prove the endpoint will actually *carry your traffic*. ``warpep verify``
goes one step further: it completes the handshake, derives the transport keys and
pushes a real ICMP echo request through the tunnel to a resolver inside
Cloudflare's network. If the echo reply comes back decrypted and intact, the
endpoint is genuinely routing packets end to end.
"""

from __future__ import annotations

import struct
from typing import Optional, Tuple

from .chacha20poly1305 import InvalidTag, decrypt, encrypt
from .noise import MSG_DATA, TransportKeys

__all__ = ["seal", "open_packet", "icmp_echo_request", "parse_icmp_echo_reply", "KEEPALIVE"]

KEEPALIVE = b""


def _nonce(counter: int) -> bytes:
    return bytes(4) + struct.pack("<Q", counter)


def _pad(payload: bytes) -> bytes:
    if not payload:
        return payload
    remainder = len(payload) % 16
    return payload + (b"" if remainder == 0 else bytes(16 - remainder))


def seal(keys: TransportKeys, counter: int, payload: bytes) -> bytes:
    """Wrap an inner IP packet in a WireGuard transport-data message (type 4)."""
    ciphertext = encrypt(keys.send_key, _nonce(counter), _pad(payload))
    return struct.pack("<B3x IQ", MSG_DATA, keys.receiver_index, counter) + ciphertext


def open_packet(keys: TransportKeys, packet: bytes) -> Tuple[int, bytes]:
    """Unwrap a transport-data message, returning (counter, inner payload)."""
    if len(packet) < 32 or packet[0] != MSG_DATA:
        raise InvalidTag("not a WireGuard transport-data message")
    receiver, counter = struct.unpack("<IQ", packet[4:16])
    if receiver != keys.sender_index:
        raise InvalidTag("transport message addressed to another session")
    payload = decrypt(keys.receive_key, _nonce(counter), packet[16:])
    return counter, payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmp_echo_request(
    source: str,
    destination: str,
    identifier: int,
    sequence: int,
    payload: bytes = b"WarpEP by ArJey",
) -> bytes:
    """Hand-rolled IPv4 + ICMP echo request, because the tunnel carries raw IP."""
    icmp = struct.pack(">BBHHH", 8, 0, 0, identifier & 0xFFFF, sequence & 0xFFFF) + payload
    icmp = icmp[:2] + struct.pack(">H", _checksum(icmp)) + icmp[4:]

    total_length = 20 + len(icmp)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identifier & 0xFFFF,
        0,
        64,
        1,
        0,
        _ip_to_bytes(source),
        _ip_to_bytes(destination),
    )
    header = header[:10] + struct.pack(">H", _checksum(header)) + header[12:]
    return header + icmp


def parse_icmp_echo_reply(packet: bytes, identifier: int) -> Optional[int]:
    """Return the echo sequence number if this inner packet is our echo reply."""
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    if packet[9] != 1:  # not ICMP
        return None
    icmp = packet[header_length:]
    if len(icmp) < 8 or icmp[0] != 0:  # not an echo reply
        return None
    got_id, sequence = struct.unpack(">HH", icmp[4:8])
    if got_id != (identifier & 0xFFFF):
        return None
    return sequence


def _ip_to_bytes(address: str) -> bytes:
    import ipaddress

    return ipaddress.IPv4Address(address).packed
