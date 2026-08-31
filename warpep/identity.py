"""WARP scan identities: the single thing that decides real results from dead ones.

Read this before touching the scanner.

Cloudflare's WARP responder is a WireGuard responder with a peer list. When an
initiation arrives it checks ``mac1`` (anybody can compute that from the public
responder key), then decrypts ``encrypted_static`` to learn *which client* is
calling, and looks that public key up. If the key is not an enrolled WARP device
the packet is dropped in silence. No response, no ICMP error, nothing.

That is exactly what a throwaway ``Keypair.generate()`` produces: a scan where
every single endpoint on earth looks dead, because Cloudflare never answers an
unknown peer. WarpEP 1.x had that bug. Everything in this module exists so it
cannot come back:

* ``resolve()`` never hands the scanner an unregistered key by accident.
* a bundled, publicly published enrolled identity means a fresh install scans
  correctly with zero network calls and zero setup, even where
  ``api.cloudflareclient.com`` is blocked,
* ``ScanIdentity.registered`` is surfaced in the UI and the JSON export, so a
  scan can always be audited for whether its results could be trusted.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .wireguard.noise import Keypair

__all__ = [
    "WARP_RESPONDER_PUBLIC_KEY_B64",
    "BUNDLED_IDENTITIES",
    "IdentityError",
    "ScanIdentity",
    "decode_public_key",
    "warp_responder_public_key",
    "bundled_identity",
    "resolve",
]

# Cloudflare's WARP WireGuard responder public key. Every WARP client on the
# planet (official app, wgcf, warp-plus, usque, warpscout) handshakes against
# this exact key, and it has not changed since WARP shipped.
WARP_RESPONDER_PUBLIC_KEY_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

# Enrolled WARP device keys that are already public in other open-source WARP
# tools, shipped so a fresh install can scan before it can register. These are
# only ever used to *probe*: a probe needs an enrolled key, but it carries no
# traffic and is tied to no account of yours. `warpep register` replaces them
# with your own device the moment the API is reachable.
BUNDLED_IDENTITIES: Tuple[Tuple[str, str], ...] = (
    # Published in vernette/warpscout (warp.go) as its default scan identity.
    ("community-1", "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg="),
)


class IdentityError(Exception):
    """No identity that Cloudflare will actually answer could be assembled."""


def decode_public_key(value: str) -> bytes:
    text = value.strip()
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:  # noqa: BLE001
        raise IdentityError(f"invalid base64 public key: {value!r}") from exc
    if len(raw) != 32:
        raise IdentityError("a WireGuard public key must decode to 32 bytes")
    return raw


def warp_responder_public_key() -> bytes:
    return decode_public_key(WARP_RESPONDER_PUBLIC_KEY_B64)


@dataclass(frozen=True)
class ScanIdentity:
    """The keypair a scan probes with, plus an honest label for where it came from."""

    keypair: Keypair
    responder_public: bytes
    source: str
    registered: bool
    label: str = ""
    client_ip: str = "172.16.0.2"
    client_ip_v6: str = ""

    @property
    def public_b64(self) -> str:
        return self.keypair.public_b64

    @property
    def trustworthy(self) -> bool:
        """Will Cloudflare answer probes signed by this identity at all?"""
        return self.registered

    def describe(self) -> str:
        if self.source == "account":
            return f"your own WARP registration ({self.client_ip})"
        if self.source == "bundled":
            return f"bundled enrolled identity [{self.label}]"
        if self.source == "custom":
            return "identity supplied on the command line"
        return "throwaway key (Cloudflare will NOT answer: results are meaningless)"

    def warning(self) -> Optional[str]:
        if self.registered:
            return None
        return (
            "this scan is using an UNREGISTERED key. Cloudflare silently drops "
            "handshakes from unknown peers, so every endpoint will look dead. "
            "Run 'warpep register' or drop the --unregistered flag."
        )


def bundled_identity(index: int = 0) -> ScanIdentity:
    """An enrolled identity that ships with WarpEP. Works with no network at all."""
    if not BUNDLED_IDENTITIES:  # pragma: no cover - defensive
        raise IdentityError("this build ships no bundled identity")
    label, private = BUNDLED_IDENTITIES[index % len(BUNDLED_IDENTITIES)]
    return ScanIdentity(
        keypair=Keypair.from_base64(private),
        responder_public=warp_responder_public_key(),
        source="bundled",
        registered=True,
        label=label,
    )


def _from_account(account, responder_public: bytes) -> Optional[ScanIdentity]:
    try:
        keypair = account.keypair
    except Exception:  # noqa: BLE001 - a corrupt cache must never be fatal
        return None
    peer = responder_public
    if getattr(account, "peer_public_key", ""):
        try:
            peer = decode_public_key(account.peer_public_key)
        except IdentityError:
            peer = responder_public
    return ScanIdentity(
        keypair=keypair,
        responder_public=peer,
        source="account",
        registered=True,
        label=account.public_key[:12] if getattr(account, "public_key", "") else "",
        client_ip=getattr(account, "address_v4", "") or "172.16.0.2",
        client_ip_v6=getattr(account, "address_v6", "") or "",
    )


def resolve(
    private_key: Optional[str] = None,
    peer_key: Optional[str] = None,
    allow_unregistered: bool = False,
    use_account: bool = True,
    use_bundled: bool = True,
) -> ScanIdentity:
    """Pick the best identity available, in the order that actually works.

    1. ``--key``: an explicit WARP private key the user pasted in.
    2. the cached registration from ``warpep register`` - your own device, and
       the only identity whose tunnel is routable for you.
    3. a bundled enrolled identity - instant, offline, plenty for probing.
    4. a throwaway key, and only when the caller explicitly asked for one.

    Registration is never attempted here: it is a network call, and a scan must
    stay usable when the WARP API itself is blocked.
    """
    responder = decode_public_key(peer_key) if peer_key else warp_responder_public_key()

    if private_key:
        try:
            keypair = Keypair.from_base64(private_key)
        except Exception as exc:  # noqa: BLE001
            raise IdentityError(f"invalid WARP private key: {exc}") from exc
        return ScanIdentity(
            keypair=keypair,
            responder_public=responder,
            source="custom",
            registered=True,
            label=keypair.public_b64[:12],
        )

    if use_account:
        from . import account as account_mod

        cached = account_mod.load_account()
        if cached is not None:
            identity = _from_account(cached, responder)
            if identity is not None:
                return identity

    if use_bundled:
        identity = bundled_identity()
        if peer_key:
            identity = ScanIdentity(
                keypair=identity.keypair,
                responder_public=responder,
                source=identity.source,
                registered=identity.registered,
                label=identity.label,
            )
        return identity

    if not allow_unregistered:
        raise IdentityError(
            "no enrolled WARP identity available. Run 'warpep register', pass "
            "--key, or accept meaningless results with --unregistered."
        )

    keypair = Keypair.generate()
    return ScanIdentity(
        keypair=keypair,
        responder_public=responder,
        source="throwaway",
        registered=False,
        label=keypair.public_b64[:12],
    )
