"""Real Cloudflare WARP registration.

A handshake probe works with any keypair, but a tunnel that actually *carries*
traffic needs a registered WARP peer. This module talks to the same public
registration API the official client uses, with the standard library only, and
caches the result under the user's config directory so you register once.

Nothing here is scraped or reverse-engineered beyond what wgcf, warp-plus and
every other WARP tool already document publicly.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .version import user_agent
from .wireguard.noise import Keypair

__all__ = ["WarpAccount", "AccountError", "register", "load_account", "save_account", "ensure_account", "config_dir"]

API_BASE = "https://api.cloudflareclient.com/v0a2158"
CLIENT_VERSION = "a-6.30-3596"
API_UA = "okhttp/3.12.1"


class AccountError(Exception):
    """Registration or refresh failed."""


def config_dir() -> Path:
    override = os.environ.get("WARPEP_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming"
        return Path(base) / "WarpEP"
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "warpep"


@dataclass
class WarpAccount:
    private_key: str
    public_key: str
    peer_public_key: str
    address_v4: str
    address_v6: str
    account_id: str = ""
    token: str = ""
    license: str = ""
    endpoint: str = "engage.cloudflareclient.com:2408"
    created_at: float = field(default_factory=time.time)

    @property
    def keypair(self) -> Keypair:
        import base64

        return Keypair.from_private(base64.b64decode(self.private_key))

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "WarpAccount":
        known = {k: v for k, v in payload.items() if k in cls.__dataclass_fields__}
        return cls(**known)


def _post(path: str, payload: Dict[str, Any], token: str = "", method: str = "POST", timeout: float = 15.0) -> Dict[str, Any]:
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        data=json.dumps(payload).encode(),
        method=method,
        headers={
            "Content-Type": "application/json; charset=UTF-8",
            "CF-Client-Version": CLIENT_VERSION,
            "User-Agent": API_UA,
            "X-Warpep-Client": user_agent(),
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise AccountError(f"WARP API returned HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise AccountError(f"could not reach the WARP API: {exc.reason}") from exc
    except (ValueError, TimeoutError) as exc:
        raise AccountError(f"unexpected WARP API response: {exc}") from exc


def register(keypair: Optional[Keypair] = None, timeout: float = 15.0) -> WarpAccount:
    """Create a fresh WARP registration and return the usable account."""
    keypair = keypair or Keypair.generate()
    body = {
        "key": keypair.public_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "PC",
        "serial_number": "",
        "locale": "en_US",
    }
    data = _post("/reg", body, timeout=timeout)
    try:
        config = data["config"]
        peer = config["peers"][0]
        interface = config["interface"]["addresses"]
        account = WarpAccount(
            private_key=keypair.private_b64,
            public_key=keypair.public_b64,
            peer_public_key=peer["public_key"],
            address_v4=interface.get("v4", "172.16.0.2"),
            address_v6=interface.get("v6", ""),
            account_id=data.get("id", ""),
            token=data.get("token", ""),
            license=data.get("account", {}).get("license", ""),
            endpoint=peer.get("endpoint", {}).get("host", "engage.cloudflareclient.com:2408"),
        )
    except (KeyError, IndexError, TypeError) as exc:
        raise AccountError("WARP API response did not contain a usable peer config") from exc

    if account.account_id and account.token:
        try:
            _post(f"/reg/{account.account_id}", {"warp_enabled": True}, token=account.token, method="PATCH", timeout=timeout)
        except AccountError:
            # WARP stays usable without the toggle; never fail registration on it.
            pass
    return account


def account_path() -> Path:
    return config_dir() / "account.json"


def save_account(account: WarpAccount) -> Path:
    path = account_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(account.as_dict(), indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def load_account() -> Optional[WarpAccount]:
    path = account_path()
    if not path.is_file():
        return None
    try:
        return WarpAccount.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, TypeError):
        return None


def ensure_account(refresh: bool = False, timeout: float = 15.0) -> WarpAccount:
    """Load the cached registration, or make one. Raises AccountError offline."""
    if not refresh:
        cached = load_account()
        if cached:
            return cached
    account = register(timeout=timeout)
    save_account(account)
    return account
