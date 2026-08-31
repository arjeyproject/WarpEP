"""Anti-DPI shaping for probes: AmneziaWG junk packets and magic packets.

Why a scanner needs this at all
-------------------------------
On a censored network the thing that kills a WARP endpoint is rarely the endpoint.
It is a middlebox that recognises the very first packet of the flow. A WireGuard
handshake initiation is trivially fingerprintable: 148 bytes, UDP, first byte
0x01 followed by three zero bytes. Some DPI stacks drop it outright, some let the
handshake through and then throttle the session to death a few seconds later, and
some only block it on port 2408.

AmneziaWG's answer, which is currently the state of the art for getting WireGuard
past that class of filter, is two-part and both parts are implemented here:

* **junk packets** (``Jc`` random packets of ``Jmin``-``Jmax`` random bytes) sent
  ahead of the handshake, so the flow does not begin with a recognisable
  initiation and the packet-size histogram of the session stops matching
  WireGuard,
* **magic / init packets** (``I1``..``I5``), arbitrary attacker-chosen payloads
  sent first so the flow *opens* looking like something the censor allows. The
  default here is a DNS response for ``icloud.com``, which is what the current
  AmneziaWG presets use.

None of this changes the handshake itself. The initiation on the wire is still a
byte-exact, cryptographically valid WireGuard message, so a reply still proves the
endpoint is real. Obfuscation only changes what surrounds it.

A probe that only succeeds with obfuscation on is a genuinely useful signal in
its own right: it tells the user their network is filtering WireGuard by
signature, not by address, and that they need an AmneziaWG-capable client.
"""

from __future__ import annotations

import os
import re
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

__all__ = [
    "AWG_DEFAULT_I1",
    "JUNK_COUNT_MIN",
    "JUNK_COUNT_MAX",
    "ObfuscationError",
    "ObfuscationProfile",
    "parse_magic",
    "render_magic",
    "awg_profile",
    "off",
]

# The AmneziaWG preset the WARP community converged on: a DNS response for
# icloud.com. Two random bytes stand in for the transaction id so every probe
# looks like a different lookup.
AWG_DEFAULT_I1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001"
    "c00c000100010000105a00044d583737>"
)

JUNK_COUNT_MIN, JUNK_COUNT_MAX = 4, 6
JUNK_SIZE_MIN, JUNK_SIZE_MAX = 10, 50
JUNK_SPAN_MIN, JUNK_SPAN_MAX = 20, 100

JUNK_COUNT_LIMIT = 128
JUNK_SIZE_LIMIT = 1280

_TOKEN = re.compile(r"<\s*(b|r|c|t)\s*([^>]*)>", re.IGNORECASE)


class ObfuscationError(ValueError):
    """A magic-packet specification could not be understood."""


def parse_magic(spec: str) -> List[tuple]:
    """Compile an AmneziaWG magic-packet spec into render instructions.

    Supported tokens, matching amneziawg-go's own generator:

    ``<b 0xDEADBEEF>``  literal bytes
    ``<r 16>``          16 fresh random bytes
    ``<c 4>``           a 4-byte big-endian counter
    ``<t>``             the current unix time, 4 bytes big-endian
    """
    text = (spec or "").strip()
    if not text or text.lower() == "none":
        return []
    instructions: List[tuple] = []
    position = 0
    for match in _TOKEN.finditer(text):
        if match.start() != position:
            junk = text[position : match.start()].strip()
            if junk:
                raise ObfuscationError(f"unexpected text in magic packet spec: {junk!r}")
        kind = match.group(1).lower()
        argument = match.group(2).strip()
        if kind == "b":
            hexed = argument[2:] if argument.lower().startswith("0x") else argument
            hexed = hexed.replace("_", "").replace(" ", "")
            try:
                instructions.append(("b", bytes.fromhex(hexed)))
            except ValueError as exc:
                raise ObfuscationError(f"invalid hex in magic packet: {argument!r}") from exc
        elif kind == "t":
            instructions.append(("t", 4))
        else:
            try:
                count = int(argument)
            except ValueError as exc:
                raise ObfuscationError(f"<{kind}> needs a byte count, got {argument!r}") from exc
            if not 0 < count <= JUNK_SIZE_LIMIT:
                raise ObfuscationError(f"<{kind} {count}> is out of range 1..{JUNK_SIZE_LIMIT}")
            instructions.append((kind, count))
        position = match.end()
    if position != len(text.rstrip()):
        raise ObfuscationError(f"trailing junk in magic packet spec: {text[position:]!r}")
    if not instructions:
        raise ObfuscationError(f"magic packet spec produced no bytes: {spec!r}")
    return instructions


def render_magic(instructions: Sequence[tuple], counter: int = 0) -> bytes:
    out = bytearray()
    for kind, value in instructions:
        if kind == "b":
            out += value
        elif kind == "r":
            out += os.urandom(value)
        elif kind == "c":
            out += (counter % (1 << (8 * value))).to_bytes(value, "big")
        elif kind == "t":
            out += struct.pack(">I", int(time.time()) & 0xFFFFFFFF)
    return bytes(out)


@dataclass
class ObfuscationProfile:
    """How to dress up a probe before the handshake goes out."""

    enabled: bool = False
    junk_count: int = 0
    junk_min: int = JUNK_SIZE_MIN
    junk_max: int = JUNK_SIZE_MAX
    magic: List[tuple] = field(default_factory=list)
    magic_spec: str = ""
    _counter: int = 0

    def __post_init__(self) -> None:
        if self.junk_count and not 0 <= self.junk_count <= JUNK_COUNT_LIMIT:
            raise ObfuscationError(f"junk packet count must be 0..{JUNK_COUNT_LIMIT}")
        if self.junk_min > self.junk_max:
            raise ObfuscationError("junk minimum size cannot exceed the maximum")
        if not 0 < self.junk_max <= JUNK_SIZE_LIMIT:
            raise ObfuscationError(f"junk packet size must be 1..{JUNK_SIZE_LIMIT}")

    @property
    def active(self) -> bool:
        return self.enabled and bool(self.junk_count or self.magic)

    def preamble(self) -> List[bytes]:
        """The packets to put on the wire immediately before the initiation."""
        if not self.active:
            return []
        self._counter += 1
        packets: List[bytes] = []
        if self.magic:
            packets.append(render_magic(self.magic, self._counter))
        for _ in range(self.junk_count):
            size = self.junk_min if self.junk_min == self.junk_max else (
                self.junk_min + int.from_bytes(os.urandom(2), "big") % (self.junk_max - self.junk_min + 1)
            )
            packets.append(os.urandom(size))
        return packets

    def summary(self) -> str:
        if not self.active:
            return "plain WireGuard"
        bits = []
        if self.junk_count:
            bits.append(f"jc={self.junk_count} jmin={self.junk_min} jmax={self.junk_max}")
        if self.magic:
            bits.append("i1=magic")
        return "AmneziaWG (" + ", ".join(bits) + ")"

    def as_dict(self) -> dict:
        return {
            "enabled": self.active,
            "junk_count": self.junk_count,
            "junk_min": self.junk_min,
            "junk_max": self.junk_max,
            "magic_packet": bool(self.magic),
        }

    def wireguard_fields(self) -> List[str]:
        """The ``Jc``/``Jmin``/``Jmax``/``I1`` lines for an AmneziaWG .conf."""
        if not self.active:
            return []
        lines = [f"Jc = {self.junk_count}", f"Jmin = {self.junk_min}", f"Jmax = {self.junk_max}"]
        lines += ["S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"]
        if self.magic_spec:
            lines.append(f"I1 = {self.magic_spec}")
        return lines


def _rand_range(low: int, high: int) -> int:
    if high <= low:
        return low
    return low + int.from_bytes(os.urandom(2), "big") % (high - low + 1)


def awg_profile(
    junk_count: Optional[int] = None,
    junk_min: Optional[int] = None,
    junk_max: Optional[int] = None,
    magic: Optional[str] = None,
) -> ObfuscationProfile:
    """A randomised AmneziaWG profile, the way the reference generator does it."""
    count = _rand_range(JUNK_COUNT_MIN, JUNK_COUNT_MAX) if junk_count is None else junk_count
    low = _rand_range(JUNK_SIZE_MIN, JUNK_SIZE_MAX) if junk_min is None else junk_min
    high = low + _rand_range(JUNK_SPAN_MIN, JUNK_SPAN_MAX) if junk_max is None else junk_max
    spec = AWG_DEFAULT_I1 if magic is None else magic
    return ObfuscationProfile(
        enabled=True,
        junk_count=count,
        junk_min=low,
        junk_max=min(high, JUNK_SIZE_LIMIT),
        magic=parse_magic(spec),
        magic_spec="" if not spec or spec.lower() == "none" else spec,
    )


def off() -> ObfuscationProfile:
    return ObfuscationProfile(enabled=False)
