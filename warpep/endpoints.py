"""Cloudflare WARP endpoint address space.

These are Cloudflare's publicly documented anycast prefixes and UDP ports for the
WARP service. WarpEP never guesses at random internet hosts: the search space is
exactly the address space Cloudflare publishes for WARP and for MASQUE.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

__all__ = [
    "Endpoint",
    "IPV4_PREFIXES",
    "IPV6_PREFIXES",
    "PRIMARY_PORTS",
    "EXTENDED_PORTS",
    "ALL_PORTS",
    "expand_prefixes",
    "parse_prefixes",
    "parse_ports",
    "sample_addresses",
    "build_endpoints",
    "spread",
]

# Cloudflare WARP IPv4 anycast prefixes.
IPV4_PREFIXES: Tuple[str, ...] = (
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
)

# Cloudflare WARP IPv6 anycast prefixes.
IPV6_PREFIXES: Tuple[str, ...] = (
    "2606:4700:d0::/64",
    "2606:4700:d1::/64",
)

IPV6_SUFFIX_TEMPLATES: Tuple[str, ...] = (
    "a29f:{host:x}",
    "bc72:{host:x}",
)

# The ports the official WARP client falls back through, fastest-first.
PRIMARY_PORTS: Tuple[int, ...] = (2408, 500, 1701, 4500, 8886, 8854, 894, 943)

EXTENDED_PORTS: Tuple[int, ...] = (
    854, 859, 864, 878, 880, 890, 891, 903, 908, 928, 934, 939, 942, 945, 946,
    955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
    2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103,
    7152, 7156, 7281, 7559, 8319, 8742,
)

ALL_PORTS: Tuple[int, ...] = PRIMARY_PORTS + EXTENDED_PORTS


@dataclass(frozen=True, order=True)
class Endpoint:
    """One candidate WARP endpoint: an anycast address plus a UDP port."""

    address: str
    port: int

    @property
    def is_ipv6(self) -> bool:
        return ":" in self.address

    @property
    def prefix24(self) -> str:
        """The /24 (or /64-ish block) this endpoint belongs to, for grouping."""
        if self.is_ipv6:
            return ":".join(self.address.split(":")[:4]) + "::/64"
        return self.address.rsplit(".", 1)[0] + ".0/24"

    def __str__(self) -> str:
        return f"[{self.address}]:{self.port}" if self.is_ipv6 else f"{self.address}:{self.port}"

    @classmethod
    def parse(cls, text: str) -> "Endpoint":
        text = text.strip()
        if text.startswith("["):
            host, _, port = text.rpartition("]:")
            return cls(host[1:], int(port))
        host, _, port = text.rpartition(":")
        if not host:
            raise ValueError(f"invalid endpoint: {text!r}")
        return cls(host, int(port or 2408))


def parse_prefixes(values: Optional[Iterable[str]], ipv6: bool) -> List[str]:
    if values:
        prefixes = []
        for value in values:
            for item in str(value).split(","):
                item = item.strip()
                if item:
                    ipaddress.ip_network(item, strict=False)
                    prefixes.append(item)
        return prefixes
    return list(IPV6_PREFIXES if ipv6 else IPV4_PREFIXES)


def parse_ports(values: Optional[Iterable[str]]) -> List[int]:
    if not values:
        return list(PRIMARY_PORTS)
    ports: List[int] = []
    for value in values:
        for item in str(value).split(","):
            item = item.strip()
            if not item:
                continue
            if item in {"all", "extended"}:
                ports.extend(ALL_PORTS)
                continue
            if item == "primary":
                ports.extend(PRIMARY_PORTS)
                continue
            if "-" in item:
                low, _, high = item.partition("-")
                low_i, high_i = int(low), int(high)
                if not 0 < low_i <= high_i <= 65535:
                    raise ValueError(f"invalid port range: {item}")
                ports.extend(range(low_i, high_i + 1))
                continue
            port = int(item)
            if not 0 < port <= 65535:
                raise ValueError(f"invalid port: {item}")
            ports.append(port)
    seen = set()
    unique = []
    for port in ports:
        if port not in seen:
            seen.add(port)
            unique.append(port)
    return unique


def _ipv6_hosts(prefix: str) -> Iterator[str]:
    network = ipaddress.IPv6Network(prefix, strict=False)
    base = network.network_address
    for template in IPV6_SUFFIX_TEMPLATES:
        for host in range(1, 256):
            suffix = template.format(host=host)
            yield str(ipaddress.IPv6Address(f"{base.compressed.rstrip(':')}::{suffix}".replace(":::", "::")))


def expand_prefixes(prefixes: Sequence[str]) -> List[str]:
    """Every candidate address inside the given prefixes."""
    addresses: List[str] = []
    for prefix in prefixes:
        network = ipaddress.ip_network(prefix, strict=False)
        if network.version == 6:
            addresses.extend(_ipv6_hosts(prefix))
            continue
        if network.num_addresses > 65536:
            raise ValueError(f"prefix {prefix} is too large to enumerate")
        if network.num_addresses == 1:
            addresses.append(str(network.network_address))
            continue
        addresses.extend(str(host) for host in network.hosts())
    seen = set()
    unique = []
    for address in addresses:
        if address not in seen:
            seen.add(address)
            unique.append(address)
    return unique


def sample_addresses(addresses: Sequence[str], count: int, rng: Optional[random.Random] = None) -> List[str]:
    if count <= 0 or count >= len(addresses):
        return list(addresses)
    return (rng or random).sample(list(addresses), count)


def spread(addresses: Sequence[str], count: int, rng: Optional[random.Random] = None) -> List[str]:
    """Sample evenly across prefixes instead of uniformly across the whole space.

    A plain random sample of a /24-heavy space clusters: with seven prefixes and
    48 slots you can easily draw 20 addresses from one block and 2 from another,
    which is exactly how a scan ends up reporting that "nothing works" when only
    one block is being blackholed. Round-robin over the blocks fixes that.
    """
    if count <= 0 or count >= len(addresses):
        return list(addresses)
    buckets: dict = {}
    for address in addresses:
        key = address.rsplit(".", 1)[0] if "." in address else ":".join(address.split(":")[:4])
        buckets.setdefault(key, []).append(address)
    picker = rng or random
    for pool in buckets.values():
        picker.shuffle(pool)
    ordered: List[str] = []
    keys = sorted(buckets)
    index = 0
    while len(ordered) < count:
        progressed = False
        for key in keys:
            pool = buckets[key]
            if index < len(pool):
                ordered.append(pool[index])
                progressed = True
                if len(ordered) >= count:
                    break
        if not progressed:
            break
        index += 1
    return ordered


def build_endpoints(addresses: Sequence[str], ports: Sequence[int]) -> List[Endpoint]:
    return [Endpoint(address, port) for address in addresses for port in ports]
