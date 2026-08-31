"""``warpep`` with no arguments: the interactive panel.

The panel exists because the people who need a WARP endpoint the most are not
going to memorise ``--sample``, ``--ports all`` and ``--verify 3``. Type
``warpep`` on Termux, Windows, macOS or any Linux and you land in a numbered
menu that does the right thing by default: detect the operator, scan for real,
verify the winners, and hand over something you can paste into your client.

Every option here is a thin wrapper over the same engine the CLI drives, so the
panel can never drift into showing something the flags would not.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from . import account as account_mod
from . import exporters, masque, operator as operator_mod, selftest
from .endpoints import ALL_PORTS, Endpoint, PRIMARY_PORTS, build_endpoints, expand_prefixes, parse_ports, parse_prefixes, spread
from .engine import ScanConfig, ScanReport, Scanner, verify_endpoint
from .identity import IdentityError, ScanIdentity, resolve as resolve_identity
from .obfuscation import ObfuscationProfile, awg_profile, off as no_obfuscation
from .output import Console, Progress
from .version import BRAND, REPO, __version__

__all__ = ["Panel", "Settings", "MENU", "run"]


@dataclass
class Settings:
    """Everything the panel lets you change, with sane starting points."""

    sample: int = 128
    ports: str = "primary"
    ipv6: bool = False
    probes: int = 4
    timeout: float = 1.2
    rate: int = 700
    verify: int = 3
    obfuscation: str = "auto"  # auto | on | off
    top: int = 10

    def rows(self) -> List[Tuple[str, str]]:
        return [
            ("addresses sampled", "every address" if self.sample == 0 else str(self.sample)),
            ("ports", self.ports),
            ("address family", "IPv6" if self.ipv6 else "IPv4"),
            ("probes per endpoint", str(self.probes)),
            ("reply timeout", f"{self.timeout:g}s"),
            ("probe rate", f"{self.rate}/s"),
            ("tunnel verifications", str(self.verify)),
            ("obfuscation", self.obfuscation),
            ("rows shown", str(self.top)),
        ]

    def build_obfuscation(self, phase: str = "sweep") -> ObfuscationProfile:
        if self.obfuscation == "on":
            return awg_profile()
        return no_obfuscation()

    @property
    def obfuscate_confirm(self) -> bool:
        return self.obfuscation in {"auto", "on"}


MENU: Tuple[Tuple[str, str, str], ...] = (
    ("1", "endpoint scan fast", "~20 s, port 2408, tuned for mobile data. Start here."),
    ("2", "endpoint scan deep", "every published prefix and every WARP port. Slow, thorough."),
    ("3", "endpoint scan IPv6", "for networks where IPv4 WARP is filtered but v6 is not."),
    ("4", "best endpoints for my operator", "re-verify what already worked on this network."),
    ("5", "MASQUE scan (TCP / QUIC)", "use when WireGuard UDP is dead: MASQUE rides HTTPS."),
    ("6", "verify one endpoint", "push real ICMP through a tunnel to a single ip:port."),
    ("7", "export config", "WireGuard, AmneziaWG, sing-box, warp:// or plain ip:port."),
    ("8", "network doctor", "what is actually broken here, in plain words."),
    ("9", "WARP account", "register or refresh your own device with Cloudflare."),
    ("10", "settings", "sample size, ports, probes, obfuscation, IPv6."),
    ("11", "self test", "prove the crypto and the scan loop on this machine."),
    ("0", "quit", ""),
)


class Panel:
    def __init__(self, console: Optional[Console] = None, settings: Optional[Settings] = None):
        self.console = console or Console()
        self.settings = settings or Settings()
        self.identity: Optional[ScanIdentity] = None
        self.network: Optional[operator_mod.NetworkProfile] = None
        self.report: Optional[ScanReport] = None
        self.masque_results: List[masque.MasqueResult] = []
        self._network_checked = False

    # -- shared helpers ----------------------------------------------------

    def ensure_identity(self) -> ScanIdentity:
        if self.identity is None:
            try:
                self.identity = resolve_identity()
            except IdentityError as exc:
                self.console.error(str(exc))
                raise
        return self.identity

    def ensure_network(self, force: bool = False) -> Optional[operator_mod.NetworkProfile]:
        if force or not self._network_checked:
            self._network_checked = True
            self.console.info("asking Cloudflare's edge which network you are on")
            self.network = operator_mod.detect()
        return self.network

    def _scanner(self, config: ScanConfig, progress: Progress) -> Scanner:
        return Scanner(identity=self.ensure_identity(), config=config, progress=progress.hook)

    def _config(self, **overrides) -> ScanConfig:
        settings = self.settings
        base = dict(
            probes=settings.probes,
            timeout=settings.timeout,
            rate=settings.rate,
            ipv6=settings.ipv6,
            obfuscation=settings.build_obfuscation(),
            confirm_probes=settings.probes,
            verify_top=settings.verify,
        )
        base.update(overrides)
        return ScanConfig(**base)

    def _targets(self, ports: Sequence[int], sample: int, ipv6: bool) -> List[Endpoint]:
        prefixes = parse_prefixes(None, ipv6)
        addresses = expand_prefixes(prefixes)
        chosen = spread(addresses, sample) if sample else addresses
        self.console.info(
            f"address space: {len(addresses)} published addresses, probing {len(chosen)} "
            f"across {len(prefixes)} prefixes on {len(ports)} port(s)"
        )
        return build_endpoints(chosen, list(ports))

    def _run_scan(
        self,
        ports: Sequence[int],
        sample: int,
        ipv6: bool,
        label: str,
        targets: Optional[Sequence[Endpoint]] = None,
    ) -> Optional[ScanReport]:
        console = self.console
        try:
            identity = self.ensure_identity()
        except IdentityError:
            return None
        console.rule(label, "bright_cyan")
        console.identity_card(identity)
        profile = self.ensure_network()
        console.network_card(profile)

        progress = Progress(console)
        scanner = self._scanner(self._config(ipv6=ipv6), progress)

        console.info("preflight: probing control endpoints that are known to answer")
        ok, detail = scanner.preflight()
        progress.clear()
        (console.ok if ok else console.warn)(detail)
        if not ok:
            console.warn("scanning anyway, but read 'network doctor' if this comes back empty")

        picked = list(targets) if targets else self._targets(ports, sample, ipv6)
        report = scanner.hunt(picked, obfuscate_confirm=self.settings.obfuscate_confirm)
        progress.clear()
        report.control_ok, report.control_detail = ok, detail
        report.network = profile.as_dict() if profile else None

        console.write()
        console.table(report.results, limit=self.settings.top)
        console.verdict(report)
        self.report = report
        self._remember(report)
        return report

    def _remember(self, report: ScanReport) -> None:
        if not self.network or not report.responsive:
            return
        entries = exporters.memory_entries(report.results)
        path = operator_mod.remember(self.network, entries)
        if path:
            self.console.info(
                f"remembered {len(entries)} working endpoint(s) for "
                f"{self.network.operator} - option 4 starts from these next time"
            )

    # -- menu actions ------------------------------------------------------

    def action_fast(self) -> None:
        self._run_scan(ports=[2408], sample=64, ipv6=False, label="FAST ENDPOINT SCAN")

    def action_deep(self) -> None:
        console = self.console
        console.warn("a deep scan probes every published address on every WARP port: this takes a while")
        if not self._confirm("run the deep scan"):
            return
        self._run_scan(ports=list(PRIMARY_PORTS), sample=0, ipv6=False, label="DEEP ENDPOINT SCAN")

    def action_ipv6(self) -> None:
        self._run_scan(ports=[2408, 500, 4500], sample=0, ipv6=True, label="IPv6 ENDPOINT SCAN")

    def action_operator(self) -> None:
        console = self.console
        profile = self.ensure_network(force=True)
        console.network_card(profile)
        if profile is None or not profile.known and not profile.ip:
            console.warn("could not identify your network, falling back to a fast scan")
            return self.action_fast()
        seeds = operator_mod.seed_endpoints(profile, limit=32)
        if not seeds:
            console.warn(
                f"nothing remembered for {profile.operator} yet. Running a fast scan first, "
                "then this option gets much faster."
            )
            return self.action_fast()
        console.ok(f"{len(seeds)} endpoint(s) remembered for {profile.operator}, re-verifying them now")
        targets = [Endpoint.parse(item) for item in seeds]
        self._run_scan(ports=[], sample=0, ipv6=self.settings.ipv6, label="MY OPERATOR", targets=targets)

    def action_masque(self) -> None:
        console = self.console
        console.rule("MASQUE SCAN", "bright_cyan")
        console.info(
            "MASQUE is Cloudflare's newest WARP transport: CONNECT-IP over HTTP/3, with an "
            "HTTP/2-over-TCP fallback that looks like ordinary HTTPS on the wire."
        )
        choice = console.ask("transport - 1) HTTP/2 over TCP  2) HTTP/3 over QUIC  3) both", "1")
        transports = {"1": ["masque-h2"], "2": ["masque-h3"], "3": ["masque-h2", "masque-h3"]}.get(choice, ["masque-h2"])
        progress = Progress(console)
        collected: List[masque.MasqueResult] = []
        for transport in transports:
            targets = masque.default_targets(transport, ipv6=self.settings.ipv6)
            if transport == "masque-h2" and self.settings.sample:
                targets = targets[: max(64, self.settings.sample * 4)]
            console.info(f"probing {len(targets)} {transport} endpoint(s)")
            results = masque.scan(
                targets,
                transport=transport,
                timeout=max(2.0, self.settings.timeout * 2),
                attempts=2,
                progress=progress.hook,
            )
            progress.clear()
            collected.extend(results)
            console.masque_table(results, limit=self.settings.top)
        self.masque_results = collected
        alive = [r for r in collected if r.alive]
        if alive:
            best = alive[0]
            console.ok(
                f"best MASQUE endpoint: {best.endpoint} ({best.transport}, {best.avg:.0f} ms). "
                "Use it with usque or any MASQUE-capable WARP client."
            )
        else:
            console.warn("no MASQUE endpoint answered: this network blocks it too, or TLS is intercepted")

    def action_verify(self) -> None:
        console = self.console
        raw = console.ask("endpoint to verify (ip:port)", "162.159.192.1:2408")
        try:
            endpoint = Endpoint.parse(raw)
        except ValueError as exc:
            console.error(str(exc))
            return
        try:
            identity = self.ensure_identity()
        except IdentityError:
            return
        console.info(f"handshake, transport keys, then real ICMP through {endpoint}")
        check = verify_endpoint(
            identity.keypair,
            endpoint,
            responder_public=identity.responder_public,
            client_ip=identity.client_ip,
            echoes=3,
            timeout=max(2.5, self.settings.timeout * 2),
            obfuscation=self.settings.build_obfuscation(),
        )
        console.tunnel(check)

    def action_export(self) -> None:
        console = self.console
        if self.report is None or not self.report.responsive:
            console.warn("nothing to export yet: run a scan first (option 1)")
            return
        best = self.report.best
        assert best is not None
        console.info(f"exporting for {best.endpoint} (health {best.health}, {best.badge})")
        console.write()
        for key, label in (
            ("1", "WireGuard .conf"),
            ("2", "AmneziaWG .conf (junk packets, beats DPI)"),
            ("3", "sing-box / Hiddify outbound JSON"),
            ("4", "warp:// links for Hiddify / NekoBox"),
            ("5", "plain ip:port list"),
            ("6", "full JSON report"),
        ):
            console.write(f"    {console.paint(key, 'bright_cyan', 'bold')}. {label}")
        console.write()
        choice = console.ask("format", "1")
        account = self._account_for_export()
        content, suggested = self._render_export(choice, best, account)
        if content is None:
            console.warn("unknown format")
            return
        target = console.ask("write to file (blank prints it here)", suggested)
        if target:
            path = Path(target).expanduser()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            except OSError as exc:
                console.error(f"could not write {path}: {exc}")
                return
            console.ok(f"wrote {path}")
        else:
            console.write()
            console.say(content)

    def _render_export(self, choice: str, best, account) -> Tuple[Optional[str], str]:
        report = self.report
        assert report is not None
        profile = awg_profile() if self.settings.obfuscation != "off" else no_obfuscation()
        note = "tunnel VERIFIED by WarpEP" if best.verified else f"health {best.health}/100, not tunnel-verified"
        if choice == "1":
            return (
                exporters.wireguard_conf(
                    best.endpoint,
                    private_key=account.private_key,
                    address_v4=account.address_v4,
                    address_v6=account.address_v6,
                    peer_public_key=account.peer_public_key,
                    note=note,
                ),
                "warp.conf",
            )
        if choice == "2":
            return (
                exporters.wireguard_conf(
                    best.endpoint,
                    private_key=account.private_key,
                    address_v4=account.address_v4,
                    address_v6=account.address_v6,
                    peer_public_key=account.peer_public_key,
                    obfuscation=profile,
                    note=note,
                ),
                "warp-awg.conf",
            )
        if choice == "3":
            return (
                exporters.singbox_outbound(
                    best.endpoint,
                    private_key=account.private_key,
                    address_v4=account.address_v4,
                    address_v6=account.address_v6,
                    peer_public_key=account.peer_public_key,
                ),
                "warp-singbox.json",
            )
        if choice == "4":
            return exporters.warp_uri_list(report.results, limit=self.settings.top), "warp-links.txt"
        if choice == "5":
            return exporters.warp_links(report.results, limit=self.settings.top), "endpoints.txt"
        if choice == "6":
            return exporters.results_json(report.results, report=report), "warpep-report.json"
        return None, ""

    def _account_for_export(self):
        cached = account_mod.load_account()
        if cached:
            return cached
        self.console.warn(
            "no WARP registration cached: the config will use a local key, which is fine for "
            "testing but will not route traffic. Option 9 registers a real device."
        )
        identity = self.ensure_identity()
        from .identity import WARP_RESPONDER_PUBLIC_KEY_B64

        return account_mod.WarpAccount(
            private_key=identity.keypair.private_b64,
            public_key=identity.keypair.public_b64,
            peer_public_key=WARP_RESPONDER_PUBLIC_KEY_B64,
            address_v4=identity.client_ip,
            address_v6=identity.client_ip_v6,
        )

    def action_doctor(self) -> None:
        from .doctor import run as run_doctor

        run_doctor(self.console, self)

    def action_account(self) -> None:
        console = self.console
        cached = account_mod.load_account()
        if cached:
            console.panel(
                "CACHED WARP REGISTRATION",
                [
                    ("client address", cached.address_v4 + (f" / {cached.address_v6}" if cached.address_v6 else "")),
                    ("public key", cached.public_key),
                    ("peer key", cached.peer_public_key),
                    ("license", cached.license or "-"),
                ],
            )
            if not self._confirm("register a brand new device (replaces the cached one)"):
                return
        console.info("contacting the Cloudflare WARP registration API")
        try:
            account = account_mod.ensure_account(refresh=True)
        except account_mod.AccountError as exc:
            console.error(str(exc))
            console.warn(
                "the WARP API itself looks blocked here. Scanning still works: WarpEP falls "
                "back to its bundled enrolled identity, which is enough to probe."
            )
            return
        path = account_mod.save_account(account)
        self.identity = None  # pick the new registration up on the next scan
        console.ok(f"registered {account.address_v4} and cached it at {path}")

    def action_settings(self) -> None:
        console = self.console
        while True:
            console.rule("SETTINGS", "bright_cyan")
            rows = self.settings.rows()
            for index, (label, value) in enumerate(rows, start=1):
                console.write(
                    f"    {console.paint(str(index), 'bright_cyan', 'bold')}. "
                    f"{label:<22} {console.paint(value, 'bold')}"
                )
            console.write(f"    {console.paint('0', 'bright_cyan', 'bold')}. back")
            console.write()
            choice = console.ask("change which", "0")
            if choice in {"0", ""}:
                return
            self._edit_setting(choice)

    def _edit_setting(self, choice: str) -> None:
        console, settings = self.console, self.settings
        try:
            if choice == "1":
                settings.sample = max(0, int(console.ask("addresses to sample (0 = all)", str(settings.sample))))
            elif choice == "2":
                value = console.ask("ports (list, range, 'primary' or 'all')", settings.ports)
                parse_ports([value])
                settings.ports = value
            elif choice == "3":
                settings.ipv6 = console.ask("address family - 4 or 6", "6" if settings.ipv6 else "4") == "6"
            elif choice == "4":
                settings.probes = max(1, int(console.ask("probes per endpoint", str(settings.probes))))
            elif choice == "5":
                settings.timeout = max(0.2, float(console.ask("reply timeout in seconds", str(settings.timeout))))
            elif choice == "6":
                settings.rate = max(20, int(console.ask("probes per second", str(settings.rate))))
            elif choice == "7":
                settings.verify = max(0, int(console.ask("how many winners to tunnel-verify", str(settings.verify))))
            elif choice == "8":
                value = console.ask("obfuscation - auto, on or off", settings.obfuscation).lower()
                if value not in {"auto", "on", "off"}:
                    raise ValueError("obfuscation must be auto, on or off")
                settings.obfuscation = value
            elif choice == "9":
                settings.top = max(1, int(console.ask("rows to show", str(settings.top))))
            else:
                console.warn("no such setting")
        except ValueError as exc:
            console.error(str(exc))

    def action_selftest(self) -> None:
        selftest.run(self.console)

    # -- loop --------------------------------------------------------------

    def _confirm(self, question: str) -> bool:
        return self.console.ask(f"{question}? [y/N]", "n").lower().startswith("y")

    def _header(self) -> None:
        console = self.console
        console.banner()
        hints = []
        if self.identity is not None:
            hints.append(("identity", self.identity.describe()))
        if self.network is not None and self.network.known:
            hints.append(("network", self.network.label()))
        if self.report is not None:
            best = self.report.best
            hints.append(("last winner", f"{best.endpoint}  health {best.health}" if best else "nothing found"))
        if hints:
            console.panel("SESSION", hints, "grey")

    def run(self) -> int:
        console = self.console
        actions: dict = {
            "1": self.action_fast,
            "2": self.action_deep,
            "3": self.action_ipv6,
            "4": self.action_operator,
            "5": self.action_masque,
            "6": self.action_verify,
            "7": self.action_export,
            "8": self.action_doctor,
            "9": self.action_account,
            "10": self.action_settings,
            "11": self.action_selftest,
        }
        self._header()
        while True:
            console.menu("WARPEP PANEL", MENU)
            try:
                choice = console.ask("choose", "1")
            except KeyboardInterrupt:
                console.write()
                return 130
            if choice in {"0", "q", "quit", "exit"}:
                console.write()
                console.ok("bye. May your endpoints stay green.")
                return 0
            action = actions.get(choice)
            if action is None:
                console.warn(f"no option {choice!r}")
                continue
            try:
                action()
            except KeyboardInterrupt:
                console.write()
                console.warn("interrupted, back to the menu")
            except IdentityError as exc:
                console.error(str(exc))
            except OSError as exc:
                console.error(f"network error: {exc}")
            console.write()


def run(console: Optional[Console] = None) -> int:
    console = console or Console()
    if not sys.stdin.isatty():
        console.error("the panel needs an interactive terminal; use 'warpep scan' in scripts")
        return 2
    return Panel(console).run()
