"""WarpEP command line interface.

    warpep                    scan and rank Cloudflare WARP endpoints
    warpep scan --fast        quick scan, good enough for a phone on 4G
    warpep scan --deep        sweep every published prefix, all ports
    warpep verify IP:PORT     prove an endpoint actually carries traffic
    warpep config             generate a WireGuard config for the best endpoint
    warpep register           create a real WARP registration (cached locally)
    warpep selftest           verify the crypto and scan loop on this machine
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import account as account_mod
from . import exporters, selftest
from .endpoints import (
    ALL_PORTS,
    Endpoint,
    PRIMARY_PORTS,
    build_endpoints,
    expand_prefixes,
    parse_ports,
    parse_prefixes,
    sample_addresses,
)
from .engine import (
    EndpointResult,
    ScanConfig,
    Scanner,
    WARP_PUBLIC_KEY_B64,
    verify_endpoint,
    warp_public_key,
)
from .output import Console, Progress
from .version import BRAND, REPO, TAGLINE, __version__
from .wireguard.noise import Keypair

EXIT_OK = 0
EXIT_NOTHING_FOUND = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


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

    scan = sub.add_parser("scan", help="scan and rank WARP endpoints")
    _add_scan_flags(scan)

    verify = sub.add_parser("verify", help="push real traffic through an endpoint")
    verify.add_argument("endpoint", help="endpoint to verify, e.g. 162.159.192.1:2408")
    verify.add_argument("--echoes", type=int, default=3, help="ICMP echoes to send through the tunnel (default 3)")
    verify.add_argument("--timeout", type=float, default=2.5, help="per-step timeout in seconds")
    verify.add_argument("--peer-key", default=WARP_PUBLIC_KEY_B64, help="responder public key (default: Cloudflare WARP)")
    verify.add_argument("--target", default="162.159.192.1", help="IP to ping inside the tunnel")

    config = sub.add_parser("config", help="generate a client config for the best endpoint")
    config.add_argument("endpoint", nargs="?", help="endpoint to use; omit to scan for the best one")
    config.add_argument(
        "--format",
        choices=["wireguard", "singbox", "endpoint"],
        default="wireguard",
        help="output format (default wireguard)",
    )
    config.add_argument("-o", "--out", help="write to a file instead of stdout")
    config.add_argument("--mtu", type=int, default=1280, help="interface MTU (default 1280)")
    config.add_argument("--no-register", action="store_true", help="do not contact the WARP API, use a local key")
    _add_scan_flags(config, minimal=True)

    register = sub.add_parser("register", help="create or refresh a real WARP registration")
    register.add_argument("--refresh", action="store_true", help="force a new registration")
    register.add_argument("--timeout", type=float, default=15.0, help="API timeout in seconds")

    sub.add_parser("selftest", help="verify crypto vectors and the scan loop locally")
    sub.add_parser("version", help="print version information")
    return parser


def _add_scan_flags(parser: argparse.ArgumentParser, minimal: bool = False) -> None:
    parser.add_argument("-6", "--ipv6", action="store_true", help="scan the IPv6 WARP prefixes")
    parser.add_argument("-n", "--sample", type=int, default=None, help="how many addresses to sample (0 = every address)")
    parser.add_argument("-c", "--probes", type=int, default=None, help="handshakes per endpoint (default 3)")
    parser.add_argument("-p", "--ports", action="append", help="ports: list, range, 'primary' or 'all'")
    parser.add_argument("--prefix", action="append", help="override the prefixes to scan (CIDR)")
    parser.add_argument("--target", action="append", help="scan only these endpoints (repeatable)")
    parser.add_argument("--timeout", type=float, default=None, help="reply timeout in seconds (default 1.2)")
    parser.add_argument("--rate", type=int, default=1500, help="probes per second (default 1500)")
    parser.add_argument("--max-inflight", type=int, default=512, help="outstanding probes (default 512)")
    parser.add_argument("--source-ip", help="bind probes to a specific local address")
    parser.add_argument("--peer-key", default=WARP_PUBLIC_KEY_B64, help="responder public key (default: Cloudflare WARP)")
    parser.add_argument("--seed", type=int, help="seed the address sampler for reproducible scans")
    parser.add_argument("--fast", action="store_true", help="preset: fewer addresses, port 2408 only")
    parser.add_argument("--deep", action="store_true", help="preset: every address, more probes, all ports")
    parser.add_argument("--skip-port-scan", action="store_true", help="trust the given ports, skip discovery")
    if minimal:
        return
    parser.add_argument("-t", "--top", type=int, default=10, help="how many results to show (default 10)")
    parser.add_argument("--verify", nargs="?", type=int, const=1, default=0, help="deep-verify the best N endpoints")
    parser.add_argument("--json", help="write full results as JSON")
    parser.add_argument("--csv", help="write full results as CSV")
    parser.add_argument("-o", "--out", help="write the winning endpoints as plain ip:port lines")
    parser.add_argument("--conf", help="write a WireGuard config for the best endpoint")
    parser.add_argument("--singbox", help="write a sing-box / Hiddify outbound for the best endpoint")


def _decode_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"invalid base64 public key: {value!r}") from exc
    if len(raw) != 32:
        raise ValueError("public key must decode to 32 bytes")
    return raw


def _static_key(console: Console, allow_cached: bool = True) -> Keypair:
    """Scan with the cached WARP identity when we have one, else a fresh key."""
    if allow_cached:
        cached = account_mod.load_account()
        if cached:
            try:
                return cached.keypair
            except Exception:  # noqa: BLE001
                console.warn("cached WARP account is unreadable, using a throwaway key")
    return Keypair.generate()


def _apply_presets(args: argparse.Namespace) -> None:
    if getattr(args, "fast", False) and getattr(args, "deep", False):
        raise ValueError("--fast and --deep are mutually exclusive")
    if getattr(args, "fast", False):
        args.sample = 48 if args.sample is None else args.sample
        args.probes = 2 if args.probes is None else args.probes
        args.timeout = 1.0 if args.timeout is None else args.timeout
        args.ports = args.ports or ["2408"]
        args.skip_port_scan = True
    elif getattr(args, "deep", False):
        args.sample = 0 if args.sample is None else args.sample
        args.probes = 5 if args.probes is None else args.probes
        args.timeout = 1.5 if args.timeout is None else args.timeout
        args.ports = args.ports or ["all"]
    args.sample = 128 if args.sample is None else args.sample
    args.probes = 3 if args.probes is None else args.probes
    args.timeout = 1.2 if args.timeout is None else args.timeout


def _collect_targets(console: Console, args: argparse.Namespace, scanner: Scanner) -> List[Endpoint]:
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
    sampled = sample_addresses(addresses, args.sample, rng)

    console.info(
        f"address space: {len(addresses)} addresses in {len(prefixes)} "
        f"{'IPv6' if args.ipv6 else 'IPv4'} prefix(es), probing {len(sampled)}"
    )

    if not args.skip_port_scan and len(ports) > 1:
        discovery_ports = ports
        found = scanner.discover_ports(sampled, discovery_ports, sample=6)
        if not found and set(discovery_ports) != set(ALL_PORTS):
            console.warn("no primary port answered, sweeping every published WARP port")
            found = scanner.discover_ports(sampled, list(ALL_PORTS), sample=6)
        if found:
            ports = found[:3]
            console.ok(f"reachable ports on this network: {', '.join(str(p) for p in ports)}")
        else:
            console.warn("port discovery found nothing; scanning the primary ports anyway")
            ports = list(PRIMARY_PORTS[:2])

    return build_endpoints(sampled, ports)


def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    _apply_presets(args)
    config = ScanConfig(
        probes=args.probes,
        timeout=args.timeout,
        rate=args.rate,
        max_inflight=args.max_inflight,
        source_ip=args.source_ip,
        ipv6=args.ipv6,
    )
    progress = Progress(console)
    scanner = Scanner(
        static=_static_key(console),
        responder_public=_decode_key(args.peer_key),
        config=config,
        progress=progress.hook,
    )

    targets = _collect_targets(console, args, scanner)
    if not targets:
        console.error("no targets to scan")
        return EXIT_USAGE
    console.info(f"probing {len(targets)} endpoints with {args.probes} real WireGuard handshakes each")

    started = time.perf_counter()
    results = scanner.scan(targets)
    progress.clear()
    elapsed = time.perf_counter() - started

    alive = [r for r in results if r.alive]
    responsive = [r for r in results if r.rtts]
    console.write()
    console.table(results, limit=args.top)
    console.write()
    console.info(
        f"{len(alive)} of {len(targets)} endpoints answered in {elapsed:.1f}s "
        f"({sum(r.sent for r in results)} handshakes sent)"
    )

    if not responsive:
        console.warn("nothing usable found: try --deep, another network, or -6 for IPv6")
        _write_exports(args, console, results, None)
        return EXIT_NOTHING_FOUND

    best = responsive[0]
    console.ok(
        f"best endpoint: {console.paint(str(best.endpoint), 'bold')} "
        f"({best.avg:.1f} ms avg, {best.loss:.0f}% loss, {best.jitter:.1f} ms jitter)"
    )

    if getattr(args, "verify", 0):
        console.write()
        console.info("deep verification: pushing real traffic through the winners")
        static = _static_key(console)
        for result in responsive[: args.verify]:
            check = verify_endpoint(
                static,
                result.endpoint,
                responder_public=_decode_key(args.peer_key),
                client_ip=_client_ip(),
                echoes=2,
                timeout=max(2.0, args.timeout * 2),
            )
            console.tunnel(check)

    _write_exports(args, console, results, best)
    return EXIT_OK


def _client_ip() -> str:
    cached = account_mod.load_account()
    return cached.address_v4 if cached and cached.address_v4 else "172.16.0.2"


def _write_exports(
    args: argparse.Namespace,
    console: Console,
    results: Sequence[EndpointResult],
    best: Optional[EndpointResult],
) -> None:
    meta = {
        "probes_per_endpoint": args.probes,
        "timeout_seconds": args.timeout,
        "ipv6": bool(args.ipv6),
        "endpoints_scanned": len(results),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if getattr(args, "json", None):
        _write(args.json, exporters.results_json(results, meta), console)
    if getattr(args, "csv", None):
        _write(args.csv, exporters.results_csv(results), console)
    if getattr(args, "out", None):
        _write(args.out, exporters.warp_links(results, limit=max(1, args.top)), console)
    if best and (getattr(args, "conf", None) or getattr(args, "singbox", None)):
        account = _account_for_export(console, no_register=False)
        if getattr(args, "conf", None):
            _write(
                args.conf,
                exporters.wireguard_conf(
                    best.endpoint,
                    private_key=account.private_key,
                    address_v4=account.address_v4,
                    address_v6=account.address_v6,
                    peer_public_key=account.peer_public_key,
                ),
                console,
            )
        if getattr(args, "singbox", None):
            _write(
                args.singbox,
                exporters.singbox_outbound(
                    best.endpoint,
                    private_key=account.private_key,
                    address_v4=account.address_v4,
                    address_v6=account.address_v6,
                    peer_public_key=account.peer_public_key,
                ),
                console,
            )


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
    keypair = Keypair.generate()
    return account_mod.WarpAccount(
        private_key=keypair.private_b64,
        public_key=keypair.public_b64,
        peer_public_key=WARP_PUBLIC_KEY_B64,
        address_v4="172.16.0.2",
        address_v6="",
    )


def cmd_verify(args: argparse.Namespace, console: Console) -> int:
    endpoint = Endpoint.parse(args.endpoint)
    console.info(f"verifying {endpoint}: handshake, transport keys, then real ICMP through the tunnel")
    account = account_mod.load_account()
    static = account.keypair if account else Keypair.generate()
    if not account:
        console.warn("no WARP registration cached: run 'warpep register' for a routable tunnel check")
    check = verify_endpoint(
        static,
        endpoint,
        responder_public=_decode_key(args.peer_key),
        client_ip=account.address_v4 if account else "172.16.0.2",
        target_ip=args.target,
        echoes=args.echoes,
        timeout=args.timeout,
    )
    console.tunnel(check)
    return EXIT_OK if check.ok or check.handshake_ms is not None else EXIT_NOTHING_FOUND


def cmd_config(args: argparse.Namespace, console: Console) -> int:
    if args.endpoint:
        endpoint = Endpoint.parse(args.endpoint)
    else:
        _apply_presets(args)
        console.info("no endpoint given: scanning for the fastest one first")
        progress = Progress(console)
        scanner = Scanner(
            static=_static_key(console),
            responder_public=_decode_key(args.peer_key),
            config=ScanConfig(
                probes=args.probes,
                timeout=args.timeout,
                rate=args.rate,
                max_inflight=args.max_inflight,
                source_ip=args.source_ip,
                ipv6=args.ipv6,
            ),
            progress=progress.hook,
        )
        results = scanner.scan(_collect_targets(console, args, scanner))
        progress.clear()
        responsive = [r for r in results if r.rtts]
        if not responsive:
            console.error("no endpoint answered, cannot build a config")
            return EXIT_NOTHING_FOUND
        endpoint = responsive[0].endpoint
        console.ok(f"using {endpoint} ({responsive[0].avg:.1f} ms)")

    account = _account_for_export(console, no_register=args.no_register)
    if args.format == "wireguard":
        content = exporters.wireguard_conf(
            endpoint,
            private_key=account.private_key,
            address_v4=account.address_v4,
            address_v6=account.address_v6,
            peer_public_key=account.peer_public_key,
            mtu=args.mtu,
        )
    elif args.format == "singbox":
        content = exporters.singbox_outbound(
            endpoint,
            private_key=account.private_key,
            address_v4=account.address_v4,
            address_v6=account.address_v6,
            peer_public_key=account.peer_public_key,
            mtu=args.mtu,
        )
    else:
        content = f"{endpoint}\n"

    if args.out:
        _write(args.out, content, console)
    else:
        console.stream.write(content)
    return EXIT_OK


def cmd_register(args: argparse.Namespace, console: Console) -> int:
    try:
        account = account_mod.ensure_account(refresh=args.refresh, timeout=args.timeout)
    except account_mod.AccountError as exc:
        console.error(str(exc))
        return EXIT_NOTHING_FOUND
    path = account_mod.save_account(account)
    console.ok("WARP registration ready")
    console.write(f"  client address : {account.address_v4}" + (f" / {account.address_v6}" if account.address_v6 else ""))
    console.write(f"  public key     : {account.public_key}")
    console.write(f"  peer key       : {account.peer_public_key}")
    console.write(f"  license        : {account.license or '-'}")
    console.write(f"  saved to       : {path}")
    return EXIT_OK


def cmd_version(console: Console) -> int:
    console.write(f"{BRAND} {__version__}")
    console.write(f"python {sys.version.split()[0]} on {sys.platform}")
    console.write(f"zero dependencies, real WireGuard handshakes")
    console.write(REPO)
    return EXIT_OK


COMMANDS = ("scan", "verify", "config", "register", "selftest", "version")
_GLOBAL_FLAGS = {"--no-color", "-q", "--quiet"}


def _normalise_argv(argv: Sequence[str]) -> "tuple[List[str], bool, bool]":
    """Let global flags appear anywhere and make `scan` the default command.

    ``warpep -q scan``, ``warpep scan -q`` and ``warpep --fast -q`` all work.
    """
    argv = list(argv)
    no_color = "--no-color" in argv
    quiet = any(flag in argv for flag in ("-q", "--quiet"))
    argv = [item for item in argv if item not in _GLOBAL_FLAGS]
    asks_for_help = any(item in {"-h", "--help", "-V", "--version"} for item in argv)
    if not asks_for_help and (not argv or argv[0] not in COMMANDS):
        argv = ["scan"] + argv
    return argv, no_color, quiet


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    argv, no_color, quiet = _normalise_argv(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    console = Console(color=False if no_color else None, quiet=quiet)

    if args.version or args.command == "version":
        return cmd_version(console)

    try:
        if args.command == "selftest":
            console.banner()
            return selftest.run(console)
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
    except ValueError as exc:
        console.error(str(exc))
        return EXIT_USAGE
    except OSError as exc:
        console.error(f"network error: {exc}")
        return EXIT_NOTHING_FOUND


if __name__ == "__main__":
    sys.exit(main())
