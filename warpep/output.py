"""Terminal presentation: banner, live progress, panels, the ranking table.

Works in Windows CMD, PowerShell, GNOME Terminal, Termux and a CI log. ANSI is
enabled explicitly on Windows, colour is dropped when the output is piped or when
NO_COLOR is set, and every box, bar and sparkline degrades to pure ASCII when the
console encoding cannot handle the glyphs (hello, legacy CMD code pages).

The table is deliberately opinionated: HEALTH and STATUS come before latency,
because a 30 ms endpoint that drops your traffic is worse than a 120 ms one that
carries it, and the old "sort by ping" table is exactly how users end up copying
dead endpoints into their client.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
import time
from typing import Iterable, List, Optional, Sequence, TextIO, Tuple

from .engine import EndpointResult, ScanReport, TunnelCheck
from .version import BRAND, REPO, TAGLINE, __version__

__all__ = ["Console", "Progress", "visible_len"]

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def visible_len(text: str) -> int:
    """Length of a string as the terminal draws it, ignoring colour escapes."""
    return len(_ANSI_RE.sub("", text))


_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "italic": "\033[3m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "grey": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
    "on_green": "\033[42;30m",
    "on_yellow": "\033[43;30m",
    "on_red": "\033[41;97m",
    "on_cyan": "\033[46;30m",
    "on_grey": "\033[100;97m",
}

_BANNER = r"""
 ██╗    ██╗  █████╗  ██████╗  ██████╗  ███████╗ ██████╗
 ██║    ██║ ██╔══██╗ ██╔══██╗ ██╔══██╗ ██╔════╝ ██╔══██╗
 ██║ █╗ ██║ ███████║ ██████╔╝ ██████╔╝ █████╗   ██████╔╝
 ██║███╗██║ ██╔══██║ ██╔══██╗ ██╔═══╝  ██╔══╝   ██╔═══╝
 ╚███╔███╔╝ ██║  ██║ ██║  ██║ ██║      ███████╗ ██║
  ╚══╝╚══╝  ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝      ╚══════╝ ╚═╝
"""

_BANNER_ASCII = r"""
 __        __                 _____ ____
 \ \      / /_ _ _ __ _ __   | ____|  _ \
  \ \ /\ / / _` | '__| '_ \  |  _| | |_) |
   \ V  V / (_| | |  | |_) | | |___|  __/
    \_/\_/ \__,_|_|  | .__/  |_____|_|
                     |_|
"""

_SPARKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
_SPARKS_ASCII = "._-=+*#@"

_BOX = {
    "h": "\u2500", "v": "\u2502", "tl": "\u256d", "tr": "\u256e", "bl": "\u2570", "br": "\u256f",
    "lj": "\u251c", "rj": "\u2524", "cj": "\u253c", "tt": "\u252c", "bt": "\u2534",
}
_BOX_ASCII = {
    "h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "lj": "+", "rj": "+", "cj": "+", "tt": "+", "bt": "+",
}


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class Console:
    def __init__(
        self,
        stream: Optional[TextIO] = None,
        color: Optional[bool] = None,
        quiet: bool = False,
        error_stream: Optional[TextIO] = None,
    ):
        self.stream = stream or sys.stdout
        # Errors go to stderr for real runs, but follow an injected stream so a
        # test or an embedder can capture everything in one place.
        self.error_stream = error_stream or (sys.stderr if self.stream is sys.stdout else self.stream)
        self.quiet = quiet
        if color is None:
            color = self._detect_color()
        self.color = bool(color)
        self.unicode = self._detect_unicode()
        self.box = _BOX if self.unicode else _BOX_ASCII

    # -- capability detection ---------------------------------------------

    def _detect_color(self) -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
            return True
        if not hasattr(self.stream, "isatty") or not self.stream.isatty():
            return False
        if os.environ.get("TERM") == "dumb":
            return False
        return _enable_windows_ansi()

    def _detect_unicode(self) -> bool:
        if os.environ.get("WARPEP_ASCII"):
            return False
        encoding = (getattr(self.stream, "encoding", None) or "").lower()
        return "utf" in encoding

    @property
    def width(self) -> int:
        return max(52, min(110, shutil.get_terminal_size((80, 24)).columns))

    # -- primitives --------------------------------------------------------

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        prefix = "".join(_ANSI.get(style, "") for style in styles)
        if not prefix:
            return text
        return f"{prefix}{text}{_ANSI['reset']}"

    def write(self, text: str = "") -> None:
        if self.quiet:
            return
        self.stream.write(text + "\n")
        self.stream.flush()

    def say(self, text: str = "") -> None:
        """Like write, but survives --quiet: used for answers the user asked for."""
        self.stream.write(text + "\n")
        self.stream.flush()

    def error(self, text: str) -> None:
        self.error_stream.write(self.paint(f"  x  {text}", "bright_red") + "\n")
        self.error_stream.flush()

    def warn(self, text: str) -> None:
        self.write(self.paint("  !  ", "bright_yellow", "bold") + text)

    def info(self, text: str) -> None:
        self.write(self.paint("  >  ", "bright_cyan") + text)

    def ok(self, text: str) -> None:
        self.write(self.paint("  +  ", "bright_green", "bold") + text)

    def step(self, index: int, total: int, text: str) -> None:
        self.write(self.paint(f"  [{index}/{total}] ", "bright_magenta", "bold") + text)

    def banner(self) -> None:
        if self.quiet:
            return
        art = (_BANNER if self.unicode else _BANNER_ASCII).strip("\n")
        shades = ("bright_cyan", "bright_cyan", "cyan", "cyan", "blue", "blue")
        for index, line in enumerate(art.splitlines()):
            self.write(self.paint(line, shades[min(index, len(shades) - 1)], "bold"))
        self.write(
            f"  {self.paint(BRAND, 'bold')} {self.paint('v' + __version__, 'bright_green')}"
            f"  {self.paint(TAGLINE, 'dim')}"
        )
        self.write(f"  {self.paint(REPO, 'grey')}")
        self.write()

    def rule(self, title: str = "", style: str = "grey") -> None:
        width = self.width
        h = self.box["h"]
        if not title:
            self.write(self.paint(h * width, style))
            return
        label = f" {title} "
        left = 2
        right = max(0, width - left - len(label))
        self.write(self.paint(h * left, style) + self.paint(label, "bold") + self.paint(h * right, style))

    def panel(self, title: str, rows: Sequence[Tuple[str, str]], style: str = "bright_cyan") -> None:
        """A titled key/value card. Long values wrap instead of blowing the border."""
        if self.quiet or not rows:
            return
        label_width = max(len(label) for label, _ in rows)
        max_inner = self.width - 2
        room = max(20, max_inner - label_width - 6)
        lines: List[Tuple[str, str]] = []
        for label, value in rows:
            prefix = f"{label:<{label_width}}   "
            if visible_len(value) <= room or _ANSI_RE.search(value):
                lines.append((prefix, value))
                continue
            chunks = textwrap.wrap(value, room) or [value]
            lines.append((prefix, chunks[0]))
            lines.extend((" " * len(prefix), chunk) for chunk in chunks[1:])

        inner = min(max(len(prefix) + visible_len(value) for prefix, value in lines) + 2, max_inner)
        inner = max(inner, len(title) + 4)
        b = self.box
        self.write(
            self.paint(b["tl"] + b["h"], style)
            + self.paint(f" {title} ", "bold")
            + self.paint(b["h"] * max(1, inner - len(title) - 3) + b["tr"], style)
        )
        for prefix, value in lines:
            used = len(prefix) + visible_len(value) + 1
            self.write(
                self.paint(b["v"], style) + " " + prefix + value
                + " " * max(0, inner - used) + self.paint(b["v"], style)
            )
        self.write(self.paint(b["bl"] + b["h"] * inner + b["br"], style))

    # -- little graphics ---------------------------------------------------

    def sparkline(self, values: Sequence[float], width: int = 8) -> str:
        if not values:
            return "-"
        glyphs = _SPARKS if self.unicode else _SPARKS_ASCII
        sample = list(values)[-width:]
        low, high = min(sample), max(sample)
        span = (high - low) or 1.0
        return "".join(glyphs[min(len(glyphs) - 1, int((v - low) / span * (len(glyphs) - 1)))] for v in sample)

    def health_bar(self, health: int, width: int = 10) -> str:
        full, empty = ("\u2588", "\u2591") if self.unicode else ("#", ".")
        filled = int(round(width * max(0, min(100, health)) / 100))
        style = self._health_style(health)
        return self.paint(full * filled, style) + self.paint(empty * (width - filled), "grey")

    @staticmethod
    def _health_style(health: int) -> str:
        if health >= 85:
            return "bright_green"
        if health >= 70:
            return "green"
        if health >= 50:
            return "bright_yellow"
        if health > 0:
            return "bright_red"
        return "grey"

    def badge(self, text: str) -> str:
        style = {
            "VERIFIED": "on_green",
            "ALIVE": "on_cyan",
            "RATE LIMITED": "on_yellow",
            "NO TRAFFIC": "on_red",
            "DEAD": "on_grey",
            "REACHABLE": "on_cyan",
        }.get(text, "on_grey")
        return self.paint(f" {text} ", style)

    # -- tables ------------------------------------------------------------

    def table(self, results: Sequence[EndpointResult], limit: int = 10) -> None:
        if self.quiet:
            return
        rows = [r for r in results if r.responsive] or list(results)
        rows = rows[:limit]
        if not rows:
            self.warn("no endpoint answered")
            return

        headers = ["#", "ENDPOINT", "HEALTH", "PING ms", "JITTER", "LOSS", "TREND", "STATUS"]
        widths = [3, 24, 15, 8, 7, 5, 8, 12]
        b = self.box

        def line(left: str, mid: str, right: str) -> str:
            return left + mid.join(b["h"] * (w + 2) for w in widths) + right

        def cells(values: Sequence[str], raw: Sequence[int], styles: Sequence[str] = ()) -> str:
            out = []
            for index, (cell, width) in enumerate(zip(values, widths)):
                visible = raw[index]
                pad = " " * max(0, width - visible)
                body = (cell + pad) if index in (1, 2, 6, 7) else (pad + cell)
                if styles:
                    body = self.paint(body, *styles)
                out.append(" " + body + " ")
            return b["v"] + b["v"].join(out) + b["v"]

        self.write(self.paint(line(b["tl"], b["tt"], b["tr"]), "grey"))
        self.write(cells(headers, [len(h) for h in headers], ("bold",)))
        self.write(self.paint(line(b["lj"], b["cj"], b["rj"]), "grey"))

        for index, result in enumerate(rows, start=1):
            bar = self.health_bar(result.health, 10)
            spark = self.sparkline(result.rtts)
            badge = self.badge(result.badge)
            values = [
                str(index),
                str(result.endpoint),
                f"{bar} {result.health:>3}",
                self._ms(result.avg),
                self._ms(result.jitter),
                f"{result.loss:.0f}%",
                spark,
                badge,
            ]
            visible = [
                len(str(index)),
                len(str(result.endpoint)),
                14,
                len(self._ms(result.avg)),
                len(self._ms(result.jitter)),
                len(f"{result.loss:.0f}%"),
                len(spark),
                len(result.badge) + 2,
            ]
            self.write(cells(values, visible))
        self.write(self.paint(line(b["bl"], b["bt"], b["br"]), "grey"))
        self.write(
            self.paint("     health = loss, latency and jitter combined, then the tunnel test. "
                       "VERIFIED means real traffic went through.", "grey")
        )

    def masque_table(self, results: Sequence, limit: int = 10) -> None:
        if self.quiet:
            return
        rows = [r for r in results if r.alive][:limit]
        if not rows:
            self.warn("no MASQUE endpoint answered")
            return
        headers = ["#", "ENDPOINT", "TRANSPORT", "RTT", "LOSS", "DETAIL"]
        widths = [3, 24, 11, 9, 6, 18]
        b = self.box

        def line(left, mid, right):
            return left + mid.join(b["h"] * (w + 2) for w in widths) + right

        def row(values, styles=()):
            out = []
            for index, (cell, width) in enumerate(zip(values, widths)):
                text = str(cell)[:width]
                pad = " " * (width - len(text))
                body = text + pad if index in (1, 2, 5) else pad + text
                out.append(" " + (self.paint(body, *styles) if styles else body) + " ")
            return b["v"] + b["v"].join(out) + b["v"]

        self.write(self.paint(line(b["tl"], b["tt"], b["tr"]), "grey"))
        self.write(row(headers, ("bold",)))
        self.write(self.paint(line(b["lj"], b["cj"], b["rj"]), "grey"))
        for index, result in enumerate(rows, start=1):
            detail = result.alpn or ""
            if result.tls_version:
                detail = f"{result.tls_version} {detail}".strip()
            self.write(
                row(
                    [index, str(result.endpoint), result.transport, self._ms(result.avg),
                     f"{result.loss:.0f}%", detail or "quic-vn"],
                    ("bright_green" if result.loss == 0 else "bright_yellow",),
                )
            )
        self.write(self.paint(line(b["bl"], b["bt"], b["br"]), "grey"))
        self.write(self.paint("     MASQUE rows are reachability, not a tunnel: TLS/ALPN for h2, "
                              "QUIC version negotiation for h3.", "grey"))

    # -- summaries ---------------------------------------------------------

    def network_card(self, profile) -> None:
        if profile is None or self.quiet:
            return
        rows = []
        name = profile.operator
        if profile.local_name and profile.local_name != name:
            name = f"{name}  ({profile.local_name})"
        rows.append(("operator", self.paint(name, "bold")))
        if profile.asn:
            rows.append(("network", f"AS{profile.asn}  {profile.organisation}"))
        where = "  ".join(x for x in (profile.city, profile.country.upper() if profile.country else "") if x)
        if where:
            rows.append(("location", where))
        if profile.colo:
            rows.append(("cloudflare edge", profile.colo))
        if profile.ip:
            rows.append(("your address", profile.ip))
        if profile.behind_warp:
            rows.append(("warning", self.paint("you are already behind WARP: results will be skewed", "bright_yellow")))
        if profile.error:
            rows.append(("detection", self.paint(profile.error, "bright_yellow")))
        self.panel("YOUR NETWORK", rows, "bright_magenta")

    def identity_card(self, identity) -> None:
        if identity is None or self.quiet:
            return
        rows = [
            ("probe identity", identity.describe()),
            ("public key", identity.public_b64),
            ("enrolled", self.paint("yes", "bright_green") if identity.registered
             else self.paint("NO", "bright_red", "bold")),
        ]
        self.panel("SCAN IDENTITY", rows, "bright_cyan" if identity.registered else "bright_red")
        if not identity.registered:
            self.warn(identity.warning() or "")

    def verdict(self, report: ScanReport) -> None:
        """The one thing the user came for, said plainly."""
        if self.quiet:
            return
        healthy = report.healthy
        self.write()
        if not report.responsive:
            self.error("no endpoint completed a WireGuard handshake")
            for note in report.notes:
                self.warn(note)
            return
        best = report.best
        assert best is not None
        rows = [
            ("endpoint", self.paint(str(best.endpoint), "bold", "bright_green")),
            ("health", f"{self.health_bar(best.health, 14)} {best.health}/100  ({best.grade})"),
            ("latency", f"{best.avg or 0:.1f} ms avg, {best.best or 0:.1f} ms best, {best.jitter or 0:.1f} ms jitter"),
            ("loss", f"{best.loss:.0f}%  over {best.sent} real handshakes"),
            ("tunnel", self._tunnel_line(best.tunnel)),
            ("obfuscation", report.obfuscation),
        ]
        self.panel("USE THIS ENDPOINT", rows, "bright_green" if best.verified else "bright_yellow")
        self.info(
            f"{self.paint(str(len(healthy)), 'bold')} healthy of {len(report.responsive)} answering, "
            f"{report.targets} probed in {report.elapsed:.1f}s "
            f"({report.handshakes} real handshakes)"
        )
        for note in report.notes:
            self.warn(note)

    def _tunnel_line(self, check: Optional[TunnelCheck]) -> str:
        if check is None:
            return self.paint("not verified (run with --verify)", "grey")
        if check.ok:
            return self.paint(
                f"VERIFIED - {len(check.tunnel_rtts)} ICMP echoes returned, "
                f"{check.avg_tunnel_ms:.1f} ms through the tunnel",
                "bright_green",
            )
        if check.handshake_ms is not None:
            return self.paint(f"handshake only, no traffic ({check.error or 'silent'})", "bright_red")
        return self.paint(f"failed: {check.error or 'no response'}", "bright_red")

    def tunnel(self, check: TunnelCheck) -> None:
        label = str(check.endpoint)
        if check.ok:
            self.ok(
                f"{label} carries real traffic: handshake {check.handshake_ms:.1f} ms, "
                f"tunnel echo {check.avg_tunnel_ms:.1f} ms ({len(check.tunnel_rtts)} replies)"
            )
        elif check.handshake_ms is not None:
            self.warn(
                f"{label} handshakes in {check.handshake_ms:.1f} ms but returned no tunnel traffic"
                + (f" ({check.error})" if check.error else "")
            )
        else:
            self.warn(f"{label} failed verification: {check.error or 'no response'}")

    # -- interactive helpers ----------------------------------------------

    def menu(self, title: str, items: Sequence[Tuple[str, str, str]]) -> None:
        """items = (key, title, subtitle)."""
        self.rule(title, "bright_cyan")
        self.write()
        for key, label, subtitle in items:
            bullet = self.paint(f"  {key:>2}. ", "bright_cyan", "bold")
            self.write(bullet + self.paint(label, "bold"))
            if subtitle:
                self.write("      " + self.paint(subtitle, "grey"))
        self.write()

    def ask(self, prompt: str, default: str = "") -> str:
        suffix = self.paint(f" [{default}]", "grey") if default else ""
        self.stream.write(self.paint("  ? ", "bright_magenta", "bold") + prompt + suffix + ": ")
        self.stream.flush()
        try:
            answer = input().strip()
        except EOFError:
            return default
        return answer or default

    @staticmethod
    def _ms(value: Optional[float]) -> str:
        return "-" if value is None else f"{value:.1f}"


class Progress:
    """Single-line progress bar, safe to pipe (it simply goes quiet)."""

    _LABELS = {
        "preflight": "preflight",
        "ports": "finding open ports",
        "sweep": "sweeping endpoints",
        "confirm": "confirming survivors",
        "scan": "scanning endpoints",
        "verify": "verifying tunnels",
        "masque-h2": "probing MASQUE/TCP",
        "masque-h3": "probing MASQUE/QUIC",
    }

    def __init__(self, console: Console, enabled: Optional[bool] = None):
        self.console = console
        stream = console.stream
        if enabled is None:
            enabled = not console.quiet and hasattr(stream, "isatty") and stream.isatty()
        self.enabled = bool(enabled)
        self._last_draw = 0.0
        self._started = time.perf_counter()
        self._phase = ""
        self._width = 0

    def hook(self, phase: str, done: int, total: int) -> None:
        if not self.enabled or total <= 0:
            return
        now = time.perf_counter()
        finished = done >= total
        if not finished and now - self._last_draw < 0.08:
            return
        self._last_draw = now
        if phase != self._phase:
            self._phase = phase
            self._started = now

        columns = shutil.get_terminal_size((80, 24)).columns
        fraction = min(1.0, done / total)
        label = self._LABELS.get(phase, phase)
        elapsed = now - self._started
        suffix = f"{done}/{total} {int(fraction * 100):>3}% {elapsed:5.1f}s"
        bar_width = max(10, min(34, columns - len(label) - len(suffix) - 10))
        filled = int(bar_width * fraction)
        full, empty = ("\u2501", "\u2500") if self.console.unicode else ("=", "-")
        head = ("\u25b8" if self.console.unicode else ">") if 0 < filled < bar_width else ""
        body = full * max(0, filled - len(head)) + head + empty * (bar_width - filled)
        text = f"  {label} {self.console.paint(body, 'bright_cyan')} {suffix}"
        plain = f"  {label} {body} {suffix}"
        pad = max(0, self._width - len(plain))
        self._width = len(plain)
        self.console.stream.write("\r" + text + " " * pad)
        self.console.stream.flush()
        if finished:
            self.clear()

    def clear(self) -> None:
        if not self.enabled:
            return
        self.console.stream.write("\r" + " " * (self._width + 2) + "\r")
        self.console.stream.flush()
        self._width = 0
