"""WarpEP command line interface.

    warpep                     open the interactive panel (or scan when piped)
    warpep panel               the panel, explicitly
    warpep scan --fast         quick scan, good enough for a phone on 4G
    warpep scan --deep         sweep every published prefix, all ports
    warpep masque              probe MASQUE, for when WireGuard UDP is blocked
    warpep verify IP:PORT      prove an endpoint actually carries traffic
    warpep config -o warp.conf generate a config for the best endpoint
    warpep doctor              find out what is really broken on this network
    warpep register            create a real WARP registration (cached locally)
    warpep operators           what has worked on the networks you have used
    warpep selftest            verify the crypto and scan loop on this machine
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import account as account_mod
from . import doctor as doctor_mod
from . import exporters, masque, operator as operator_mod, selftest
from .endpoints import (
    ALL_PORTS,
    Endpoint,
    PRIMARY_PORTS,
    build_endpoints,
    expand_prefixes,
    parse_ports,
    parse_prefixes,
    spread,
)
from .engine import (
    EndpointResult,
    ScanConfig,
    ScanReport,
    Scanner,
    verify_endpoint,
)
from .identity import (
    WARP_RESPONDER_PUBLIC_KEY_B64,
    IdentityError,
    ScanIdentity,
    decode_public_key,
    resolve as resolve_identity,
)
from .obfuscation import ObfuscationError, ObfuscationProfile, awg_profile, off as no_obfuscation
from .output import Console, Progress
from .version import BRAND, REPO, TAGLINE, __version__

EXIT_OK = 0
EXIT_NOTHING_FOUND = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

COMMANDS = (
    "panel", "scan", "masque", "verify", "config", "register",
    "operators", "doctor", "selftest", "version",
)
_GLOBAL_FLAGS = {"--no-color", "-q", "--quiet"}


# -- parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="warpep",
        description=f"{BRAND} - {TAGLINE}",
        epilog=f"docs and updates: {REPO}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="store_true", help="print the version and exit")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print the final result")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("panel", help="open the interactive panel")

    scan = sub.add_parser("scan", help="scan and rank WARP endpoints")
    _add_scan_flags(scan)

    masque_cmd = sub.add_parser("masque", help="probe Cloudflare's MASQUE transport")
    masque_cmd.add_argument(
        "--transport",
        choices=["masque-h2", "masque-h3", "both"],
        default="masque-h2",
        help="h2 = CONNECT-IP over TCP/TLS (survives UDP blocking), h3 = over QUIC",
    )
    masque_cmd.add_argument("-6", "--ipv6", action="store_true", help="probe the IPv6 MASQUE pools")
    masque_cmd.add_argument("-p", "--ports", action="append", help="ports to probe (default: the published MASQUE set)")
    masque_cmd.add_argument("--sni", default=masque.MASQUE_SNI, help="SNI to present (default: the WARP client's)")
    masque_cmd.add_argument("--timeout", type=float, default=4.0, help="per-attempt timeout in seconds")
    masque_cmd.add_argument("--attempts", type=int, default=2, help="attempts per endpoint (default 2)")
    masque_cmd.add_argument("--workers", type=int, default=64, help="concurrent probes (default 64)")
    masque_cmd.add_argument("-n", "--sample", type=int, default=256, help="addresses to probe, 0 = all")
    masque_cmd.add_argument("-t", "--top", type=int, default=10, help="rows to show")
    masque_cmd.add_argument("--json", help="write full results as JSON")
    masque_cmd.add_argument("-o", "--out", help="write the winners as ip:port lines")

    verify = sub.add_parser("verify", help="push real traffic through an endpoint")
    verify.add_argument("endpoint", help="endpoint to verify, e.g. 162.159.192.1:2408")
    verify.add_argument("--echoes", type=int, default=3, help="ICMP echoes to send through the tunnel (default 3)")
    verify.add_argument("--timeout", type=float, default=2.5, help="per-step timeout in seconds")
    verify.add_argument("--peer-key", default=WARP_RESPONDER_PUBLIC_KEY_B64, help="responder public key")
    verify.add_argument("--key", help="WARP private key to probe with (base64)")
    verify.add_argument("--target", default="162.159.192.1", help="IP to ping inside the tunnel")
    verify.add_argument("--awg", action="store_true", help="wrap the handshake in AmneziaWG obfuscation")

    config = sub.add_parser("config", help="generate a client config for the best endpoint")
    config.add_argument("endpoint", nargs="?", help="endpoint to use; omit to scan for the best one")
    config.add_argument(
        "--format",
        choices=list(exporters.FORMATS),
        default="wireguard",
        help="output format (default wireguard; amneziawg adds the junk parameters)",
    )
    config.add_argument("-o", "--out", help="write to a file instead of stdout")
    config.add_argument("--mtu", type=int, default=1280, help="interface MTU (default 1280)")
    config.add_argument("--no-register", action="store_true", help="do not contact the WARP API, use a local key")
    _add_scan_flags(config, minimal=True)

    register = sub.add_parser("register", help="create or refresh a real WARP registration")
    register.add_argument("--refresh", action="store_true", help="force a new registration")
    register.add_argument("--timeout", type=float, default=15.0, help="API timeout in seconds")

    operators = sub.add_parser("operators", help="what has worked on the networks you have used")
    operators.add_argument("--forget", action="store_true", help="delete the memory for the current network")
    operators.add_argument("--json", action="store_true", help="print the memory as JSON")

    sub.add_parser("doctor", help="diagnose this network in plain words")
    sub.add_parser("selftest", help="verify crypto vectors and the scan loop locally")
    sub.add_parser("version", help="print version information")
    return parser


def _add_scan_flags(parser: argparse.ArgumentParser, minimal: bool = False) -> None:
    parser.add_argument("-6", "--ipv6", action="store_true", help="scan the IPv6 WARP prefixes")
    parser.add_argument("-n", "--sample", type=int, default=None, help="how many addresses to sample (0 = every address)")
    parser.add_argument("-c", "--probes", type=int, default=None, help="handshakes per endpoint (default 4)")
    parser.add_argument("-p", "--ports", action="append", help="ports: list, range, 'primary' or 'all'")
    parser.add_argument("--prefix", action="append", help="override the prefixes to scan (CIDR)")
    parser.add_argument("--target", action="append", help="scan only these endpoints (repeatable)")
    parser.add_argument("--timeout", type=float, default=None, help="reply timeout in seconds (default 1.2)")
    parser.add_argument("--rate", type=int, default=700, help="probes per second (default 700)")
    parser.add_argument("--max-inflight", type=int, default=384, help="outstanding probes (default 384)")
    parser.add_argument("--budget", type=float, default=0.0, help="give up after this many seconds (0 = no limit)")
    parser.add_argument("--source-ip", help="bind probes to a specific local address")
    parser.add_argument("--peer-key", default=WARP_RESPONDER_PUBLIC_KEY_B64, help="responder public key")
    parser.add_argument("--key", help="WARP private key to probe with (base64); must be an enrolled device")
    parser.add_argument("--unregistered", action="store_true",
                        help="allow a throwaway key; Cloudflare will ignore it and every endpoint will look dead")
    parser.add_argument("--seed", type=int, help="seed the address sampler for reproducible scans")
    parser.add_argument("--fast", action="store_true", help="preset: fewer addresses, port 2408 only")
    parser.add_argument("--deep", action="store_true", help="preset: every address, more probes, all ports")
    parser.add_argument("--skip-port-scan", action="store_true", help="trust the given ports, skip discovery")
    parser.add_argument("--no-preflight", action="store_true", help="skip the control-endpoint sanity check")
    parser.add_argument("--awg", action="store_true", help="force AmneziaWG obfuscation on every probe")
    parser.add_argument("--no-awg", action="store_true", help="never obfuscate, not even when confirming survivors")
    parser.add_argument("--awg-jc", type=int, help="AmneziaWG junk packet count")
    parser.add_argument("--awg-jmin", type=int, help="AmneziaWG minimum junk packet size")
    parser.add_argument("--awg-jmax", type=int, help="AmneziaWG maximum junk packet size")
    parser.add_argument("--i1", help="AmneziaWG magic packet spec, or 'none'")
    parser.add_argument("--no-operator", action="store_true", help="skip ISP detection and per-operator memory")
    if minimal:
        return
    parser.add_argument("-t", "--top", type=int, default=10, help="how many results to show (default 10)")
    parser.add_argument("--verify", nargs="?", type=int, const=3, default=None,
                        help="tunnel-verify the best N endpoints (default 3, 0 to disable)")
    parser.add_argument("--json", help="write the full report as JSON")
    parser.add_argument("--csv", help="write full results as CSV")
    parser.add_argument("-o", "--out", help="write the healthy endpoints as plain ip:port lines")
    parser.add_argument("--links", help="write warp:// links for Hiddify / NekoBox")
    parser.add_argument("--conf", help="write a WireGuard config for the best endpoint")
    parser.add_argument("--awg-conf", help="write an AmneziaWG config for the best endpoint")
    parser.add_argument("--singbox", help="write a sing-box / Hiddify outbound for the best endpoint")


# -- shared plumbing --------------------------------------------------------


def _apply_presets(args: argparse.Namespace) -> None:
    if getattr(args, "fast", False) and getattr(args, "deep", False):
        raise ValueError("--fast and --deep are mutually exclusive")
    if getattr(args, "fast", False):
        args.sample = 64 if args.sample is None else args.sample
        args.probes = 3 if args.probes is None else args.probes
        args.timeout = 1.0 if args.timeout is None else args.timeout
        args.ports = args.ports or ["2408"]
        args.skip_port_scan = True
    elif getattr(args, "deep", False):
        args.sample = 0 if args.sample is None else args.sample
        args.probes = 5 if args.probes is None else args.probes
        args.timeout = 1.5 if args.timeout is None else args.timeout
        args.ports = args.ports or ["all"]
    args.sample = 128 if args.sample is None else args.sample
    args.probes = 4 if args.probes is None else args.probes
    args.timeout = 1.2 if args.timeout is None else args.timeout


def _obfuscation(args: argparse.Namespace) -> ObfuscationProfile:
    if getattr(args, "no_awg", False):
        return no_obfuscation()
    wants = getattr(args, "awg", False) or any(
        getattr(args, name, None) is not None for name in ("awg_jc", "awg_jmin", "awg_jmax", "i1")
    )
    if not wants:
        return no_obfuscation()
    return awg_profile(
        junk_count=getattr(args, "awg_jc", None),
        junk_min=getattr(args, "awg_jmin", None),
        junk_max=getattr(args, "awg_jmax", None),
        magic=getattr(args, "i1", None),
    )


def _identity(args: argparse.Namespace, console: Console) -> ScanIdentity:
    identity = resolve_identity(
        private_key=getattr(args, "key", None),
        peer_key=getattr(args, "peer_key", None) if getattr(args, "peer_key", "") != WARP_RESPONDER_PUBLIC_KEY_B64 else None,
        allow_unregistered=getattr(args, "unregistered", False),
        use_bundled=not getattr(args, "unregistered", False),
    )
    console.identity_card(identity)
    return identity


def _network(args: argparse.Namespace, console: Console) -> Optional[operator_mod.NetworkProfile]:
    if getattr(args, "no_operator", False):
        return None
    profile = operator_mod.detect()
    console.network_card(profile)
    return profile


def _scan_config(args: argparse.Namespace, obfuscation: ObfuscationProfile) -> ScanConfig:
    verify = getattr(args, "verify", None)
    return ScanConfig(
        probes=args.probes,
        timeout=args.timeout,
        rate=args.rate,
        max_inflight=args.max_inflight,
        source_ip=args.source_ip,
        ipv6=args.ipv6,
        obfuscation=obfuscation,
        confirm_probes=args.probes,
        verify_top=3 if verify is None else verify,
        budget=getattr(args, "budget", 0.0) or 0.0,
    )


def _collect_targets(
    console: Console,
    args: argparse.Namespace,
    scanner: Scanner,
    profile: Optional[operator_mod.NetworkProfile],
) -> List[Endpoint]:
    if args.target:
        targets = []
        for value in args.target:
            for item in str(value).split(","):
                if item.strip():
                    targets.append(Endpoint.parse(item))
        return targets

    prefixes = parse_prefixes(args.prefix, args.ipv6)
    ports = parse_ports(args.ports)
    addresses = expand_prefixes(prefixes)
    rng = random.Random(args.seed) if args.seed is not None else random
    sampled = spread(addresses, args.sample, rng)

    console.info(
        f"address space: {len(addresses)} addresses in {len(prefixes)} "
        f"{'IPv6' if args.ipv6 else 'IPv4'} prefix(es), probing {len(sampled)}"
    )

    if not args.skip_port_scan and len(ports) > 1:
        found = scanner.discover_ports(sampled, ports, sample=12)
        if not found and set(ports) != set(ALL_PORTS):
            console.warn("no primary port answered, sweeping every published WARP port")
            found = scanner.discover_ports(sampled, list(ALL_PORTS), sample=12)
        if found:
            ports = found[:3]
            console.ok(f"reachable ports on this network: {', '.join(str(p) for p in ports)}")
        else:
            console.warn("port discovery found nothing; scanning the primary ports anyway")
            ports = list(PRIMARY_PORTS[:2])

    targets = build_endpoints(sampled, ports)

    # Anything this network is already known to like goes in the pot too. It
    # costs a handful of extra probes and it is where the winners usually come
    # from on a network that has been scanned before.
    if profile is not None:
        remembered = [Endpoint.parse(item) for item in operator_mod.seed_endpoints(profile, limit=24)]
        extra = [e for e in remembered if e not in set(targets) and e.is_ipv6 == args.ipv6]
        if extra:
            console.info(f"adding {len(extra)} endpoint(s) remembered for {profile.operator}")
            targets = extra + targets
    return targets


# -- commands ---------------------------------------------------------------


def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    _apply_presets(args)
    obfuscation = _obfuscation(args)
    identity = _identity(args, console)
    profile = _network(args, console)

    progress = Progress(console)
    scanner = Scanner(
        identity=identity,
        config=_scan_config(args, obfuscation),
        progress=progress.hook,
    )

    control_ok, control_detail = True, "skipped"
    if not args.no_preflight:
        control_ok, control_detail = scanner.preflight()
        progress.clear()
        (console.ok if control_ok else console.warn)(control_detail)

    targets = _collect_targets(console, args, scanner, profile)
    if not targets:
        console.error("no targets to scan")
        return EXIT_USAGE
    console.info(
        f"probing {len(targets)} endpoints with real WireGuard handshakes "
        f"({obfuscation.summary()})"
    )

    report = scanner.hunt(targets, obfuscate_confirm=not args.no_awg)
    progress.clear()
    report.control_ok, report.control_detail = control_ok, control_detail
    report.network = profile.as_dict() if profile else None

    console.write()
    console.table(report.results, limit=args.top)
    console.verdict(report)

    if profile is not None and report.responsive:
        operator_mod.remember(profile, exporters.memory_entries(report.results))

    _write_exports(args, console, report)

    if not report.responsive:
        console.warn("run 'warpep doctor' - it will tell you which of the identity, "
                     "network, family, port or transport is at fault")
        return EXIT_NOTHING_FOUND
    return EXIT_OK


def _write_exports(args: argparse.Namespace, console: Console, report: ScanReport) -> None:
    results = report.results
    meta = {
        "probes_per_endpoint": args.probes,
        "timeout_seconds": args.timeout,
        "ipv6": bool(args.ipv6),
        "endpoints_scanned": len(results),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if getattr(args, "json", None):
        _write(args.json, exporters.results_json(results, meta, report=report), console)
    if getattr(args, "csv", None):
        _write(args.csv, exporters.results_csv(results), console)
    if getattr(args, "out", None):
        _write(args.out, exporters.warp_links(results, limit=max(1, args.top)), console)
    if getattr(args, "links", None):
        _write(args.links, exporters.warp_uri_list(results, limit=max(1, args.top)), console)

    best = report.best
    wants_conf = any(getattr(args, name, None) for name in ("conf", "awg_conf", "singbox"))
    if not (best and wants_conf):
        return
    account = _account_for_export(console, no_register=False)
    note = "tunnel VERIFIED by WarpEP" if best.verified else f"health {best.health}/100, not tunnel-verified"
    shared = dict(
        private_key=account.private_key,
        address_v4=account.address_v4,
        address_v6=account.address_v6,
        peer_public_key=account.peer_public_key,
    )
    if getattr(args, "conf", None):
        _write(args.conf, exporters.wireguard_conf(best.endpoint, note=note, **shared), console)
    if getattr(args, "awg_conf", None):
        profile = report_obfuscation_profile(args)
        _write(
            args.awg_conf,
            exporters.wireguard_conf(best.endpoint, obfuscation=profile, note=note, **shared),
            console,
        )
    if getattr(args, "singbox", None):
        _write(args.singbox, exporters.singbox_outbound(best.endpoint, **shared), console)


def report_obfuscation_profile(args: argparse.Namespace) -> ObfuscationProfile:
    profile = _obfuscation(args)
    return profile if profile.active else awg_profile()


def _write(path: str, content: str, console: Console) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    console.ok(f"wrote {target}")


def _account_for_export(console: Console, no_register: bool) -> account_mod.WarpAccount:
    cached = account_mod.load_account()
    if cached:
        return cached
    if not no_register:
        try:
            account = account_mod.register()
            account_mod.save_account(account)
            console.ok("registered a real WARP account (cached locally)")
            return account
        except account_mod.AccountError as exc:
            console.warn(f"WARP registration unavailable ({exc}); emitting a local key instead")
    identity = resolve_identity()
    return account_mod.WarpAccount(
        private_key=identity.keypair.private_b64,
        public_key=identity.keypair.public_b64,
        peer_public_key=WARP_RESPONDER_PUBLIC_KEY_B64,
        address_v4=identity.client_ip,
        address_v6=identity.client_ip_v6,
    )


def cmd_masque(args: argparse.Namespace, console: Console) -> int:
    transports = ["masque-h2", "masque-h3"] if args.transport == "both" else [args.transport]
    ports = parse_ports(args.ports) if args.ports else list(masque.MASQUE_PORTS)
    progress = Progress(console)
    collected: List[masque.MasqueResult] = []
    for transport in transports:
        targets = masque.default_targets(transport, ipv6=args.ipv6, ports=ports)
        if args.sample and len(targets) > args.sample:
            targets = targets[: args.sample]
        console.info(f"probing {len(targets)} {transport} endpoint(s) with SNI {args.sni}")
        results = masque.scan(
            targets,
            transport=transport,
            timeout=args.timeout,
            attempts=args.attempts,
            workers=args.workers,
            sni=args.sni,
            progress=progress.hook,
        )
        progress.clear()
        console.write()
        console.masque_table(results, limit=args.top)
        collected.extend(results)

    alive = [r for r in collected if r.alive]
    if args.json:
        import json

        _write(
            args.json,
            json.dumps({"tool": BRAND, "version": __version__, "results": [r.as_dict() for r in collected]}, indent=2) + "\n",
            console,
        )
    if args.out:
        _write(args.out, "\n".join(str(r.endpoint) for r in alive[: args.top]) + ("\n" if alive else ""), console)
    if not alive:
        console.warn("no MASQUE endpoint answered on this network")
        return EXIT_NOTHING_FOUND
    best = alive[0]
    console.ok(
        f"best MASQUE endpoint: {console.paint(str(best.endpoint), 'bold')} "
        f"({best.transport}, {best.avg:.0f} ms). Feed it to usque or another MASQUE client."
    )
    return EXIT_OK


def cmd_verify(args: argparse.Namespace, console: Console) -> int:
    endpoint = Endpoint.parse(args.endpoint)
    identity = resolve_identity(private_key=args.key)
    console.identity_card(identity)
    if identity.source != "account":
        console.warn(
            "no WARP registration cached: the handshake will succeed but the inner IP is not "
            "yours, so a tunnel failure here may be the address, not the endpoint. "
            "Run 'warpep register' for a decisive answer."
        )
    console.info(f"verifying {endpoint}: handshake, transport keys, then real ICMP through the tunnel")
    check = verify_endpoint(
        identity.keypair,
        endpoint,
        responder_public=decode_public_key(args.peer_key),
        client_ip=identity.client_ip,
        target_ip=args.target,
        echoes=args.echoes,
        timeout=args.timeout,
        obfuscation=awg_profile() if args.awg else no_obfuscation(),
    )
    console.tunnel(check)
    return EXIT_OK if check.ok else EXIT_NOTHING_FOUND


def cmd_config(args: argparse.Namespace, console: Console) -> int:
    best: Optional[EndpointResult] = None
    if args.endpoint:
        endpoint = Endpoint.parse(args.endpoint)
    else:
        _apply_presets(args)
        console.info("no endpoint given: scanning for the fastest healthy one first")
        obfuscation = _obfuscation(args)
        identity = _identity(args, console)
        profile = _network(args, console)
        progress = Progress(console)
        scanner = Scanner(identity=identity, config=_scan_config(args, obfuscation), progress=progress.hook)
        report = scanner.hunt(
            _collect_targets(console, args, scanner, profile),
            obfuscate_confirm=not args.no_awg,
        )
        progress.clear()
        best = report.best
        if best is None:
            console.error("no endpoint answered, cannot build a config")
            return EXIT_NOTHING_FOUND
        endpoint = best.endpoint
        console.ok(f"using {endpoint} (health {best.health}/100, {best.badge})")

    account = _account_for_export(console, no_register=args.no_register)
    note = "" if best is None else (
        "tunnel VERIFIED by WarpEP" if best.verified else f"health {best.health}/100, not tunnel-verified"
    )
    shared = dict(
        private_key=account.private_key,
        address_v4=account.address_v4,
        address_v6=account.address_v6,
        peer_public_key=account.peer_public_key,
        mtu=args.mtu,
    )
    if args.format == "wireguard":
        content = exporters.wireguard_conf(endpoint, note=note, **shared)
    elif args.format == "amneziawg":
        content = exporters.wireguard_conf(endpoint, obfuscation=report_obfuscation_profile(args), note=note, **shared)
    elif args.format == "singbox":
        shared.pop("mtu")
        content = exporters.singbox_outbound(endpoint, mtu=args.mtu, **shared)
    elif args.format == "warp":
        content = f"warp://{endpoint}/?ifp=5-10#WarpEP\n"
    else:
        content = f"{endpoint}\n"

    if args.out:
        _write(args.out, content, console)
    else:
        console.say(content.rstrip("\n"))
    return EXIT_OK


def cmd_register(args: argparse.Namespace, console: Console) -> int:
    try:
        account = account_mod.ensure_account(refresh=args.refresh, timeout=args.timeout)
    except account_mod.AccountError as exc:
        console.error(str(exc))
        console.warn(
            "the WARP API looks blocked from here. Scanning still works: WarpEP falls back to "
            "its bundled enrolled identity, which is enough to probe endpoints."
        )
        return EXIT_NOTHING_FOUND
    path = account_mod.save_account(account)
    console.panel(
        "WARP REGISTRATION READY",
        [
            ("client address", account.address_v4 + (f" / {account.address_v6}" if account.address_v6 else "")),
            ("public key", account.public_key),
            ("peer key", account.peer_public_key),
            ("license", account.license or "-"),
            ("saved to", str(path)),
        ],
        "bright_green",
    )
    return EXIT_OK


def cmd_operators(args: argparse.Namespace, console: Console) -> int:
    profile = operator_mod.detect()
    console.network_card(profile)
    if args.forget:
        if operator_mod.forget(profile):
            console.ok(f"forgot everything learned about {profile.operator}")
        else:
            console.warn("nothing remembered for this network")
        return EXIT_OK

    networks = operator_mod.all_networks()
    if args.json:
        import json

        console.say(json.dumps(networks, indent=2, ensure_ascii=False))
        return EXIT_OK
    if not networks:
        console.warn("no network memory yet: run a scan and WarpEP starts learning")
        return EXIT_NOTHING_FOUND
    for entry in networks:
        network = entry.get("network", {})
        endpoints = entry.get("endpoints", [])
        title = f"{network.get('operator', 'unknown')}  AS{network.get('asn', 0)}"
        rows = []
        for item in endpoints[:8]:
            badge = "VERIFIED" if item.get("verified") else f"health {item.get('health', '?')}"
            avg = item.get("avg_ms")
            rows.append((item.get("endpoint", "?"), f"{avg if avg is not None else '-'} ms   {badge}"))
        if not rows:
            rows = [("(empty)", "")]
        console.panel(title, rows, "bright_cyan")
    console.info("these are re-probed automatically at the start of every scan on that network")
    return EXIT_OK


def cmd_version(console: Console) -> int:
    console.say(f"{BRAND} {__version__}")
    console.say(f"python {sys.version.split()[0]} on {sys.platform}")
    console.say("zero dependencies, real WireGuard handshakes, real MASQUE probes")
    console.say(REPO)
    return EXIT_OK


# -- entry point ------------------------------------------------------------


def _normalise_argv(argv: Sequence[str]) -> "tuple[List[str], bool, bool]":
    """Let global flags appear anywhere, and pick a sensible default command.

    ``warpep`` on a terminal opens the panel, because that is what a human wants.
    ``warpep | tee log`` scans, because that is what a script wants.
    """
    argv = list(argv)
    no_color = "--no-color" in argv
    quiet = any(flag in argv for flag in ("-q", "--quiet"))
    argv = [item for item in argv if item not in _GLOBAL_FLAGS]
    asks_for_help = any(item in {"-h", "--help", "-V", "--version"} for item in argv)
    if not asks_for_help and (not argv or argv[0] not in COMMANDS):
        interactive = not argv and sys.stdin.isatty() and sys.stdout.isatty()
        argv = (["panel"] if interactive else ["scan"]) + argv
    return argv, no_color, quiet


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    argv, no_color, quiet = _normalise_argv(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    console = Console(color=False if no_color else None, quiet=quiet)

    if args.version or args.command == "version":
        return cmd_version(console)

    try:
        if args.command == "panel":
            from .panel import run as run_panel

            return run_panel(console)
        if args.command == "selftest":
            console.banner()
            return selftest.run(console)
        if args.command == "doctor":
            console.banner()
            return doctor_mod.run(console)
        if args.command == "operators":
            console.banner()
            return cmd_operators(args, console)
        if args.command == "masque":
            console.banner()
            return cmd_masque(args, console)
        if args.command == "verify":
            console.banner()
            return cmd_verify(args, console)
        if args.command == "config":
            return cmd_config(args, console)
        if args.command == "register":
            console.banner()
            return cmd_register(args, console)
        console.banner()
        return cmd_scan(args, console)
    except KeyboardInterrupt:
        console.write()
        console.warn("interrupted")
        return EXIT_INTERRUPTED
    except (IdentityError, ObfuscationError) as exc:
        console.error(str(exc))
        return EXIT_USAGE
    except ValueError as exc:
        console.error(str(exc))
        return EXIT_USAGE
    except OSError as exc:
        console.error(f"network error: {exc}")
        return EXIT_NOTHING_FOUND


if __name__ == "__main__":
    sys.exit(main())
