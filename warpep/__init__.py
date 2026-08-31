"""WarpEP by ArJey - a real Cloudflare WARP endpoint scanner with a user panel.

Zero third-party dependencies: pure-Python X25519, ChaCha20-Poly1305 and the
WireGuard Noise handshake, so it runs on Termux, Windows, macOS, any Linux and
inside a tiny container without compiling anything.

    from warpep import Scanner, ScanConfig, Endpoint, resolve_identity

    scanner = Scanner(identity=resolve_identity(), config=ScanConfig(probes=3))
    report = scanner.hunt([Endpoint("162.159.192.1", 2408)])
    print(report.best)
"""

from .endpoints import ALL_PORTS, Endpoint, PRIMARY_PORTS, build_endpoints, expand_prefixes, spread
from .engine import EndpointResult, ScanConfig, ScanReport, Scanner, TunnelCheck, verify_endpoint
from .identity import WARP_RESPONDER_PUBLIC_KEY_B64, ScanIdentity, resolve as resolve_identity
from .obfuscation import ObfuscationProfile, awg_profile
from .version import __version__

__all__ = [
    "ALL_PORTS",
    "Endpoint",
    "EndpointResult",
    "ObfuscationProfile",
    "PRIMARY_PORTS",
    "ScanConfig",
    "ScanIdentity",
    "ScanReport",
    "Scanner",
    "TunnelCheck",
    "WARP_RESPONDER_PUBLIC_KEY_B64",
    "__version__",
    "awg_profile",
    "build_endpoints",
    "expand_prefixes",
    "resolve_identity",
    "spread",
    "verify_endpoint",
]
