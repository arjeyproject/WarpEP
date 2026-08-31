"""Terminal presentation: banner, live progress, ranking table.

Works in Windows CMD, PowerShell, GNOME Terminal, Termux and a CI log. ANSI is
enabled explicitly on Windows, colour is dropped when the output is piped or when
NO_COLOR is set, and the table degrades to pure ASCII when the console encoding
cannot handle box drawing (hello, legacy CMD code pages).
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from typing import List, Optional, Sequence, TextIO

from .engine import EndpointResult, TunnelCheck
from .version import BRAND, REPO, TAGLINE, __version__

__all__ = ["Console", "Progress"]

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_cyan": "\033[96m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_red": "\033[91m",
}

_BANNER = r""" __        __                 _____ ____
 \ \      / /_ _ _ __ _ __   | ____|  _ \
  \ \ /\ / / _` | '__| '_ \  |  _| | |_) |
   \ V  V / (_| | |  | |_) | | |___|  __/
    \_/\_/ \__,_|_|  | .__/  |_____|_|
                     |_|
"""


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
    def __init__(self, stream: Optional[TextIO] = None, color: Optional[bool] = None, quiet: bool = False):
        self.stream = stream or sys.stdout
        self.quiet = quiet
        if color is None:
            color = self._detect_color()
        self.color = bool(color)
        self.unicode = self._detect_unicode()

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
        encoding = (getattr(self.stream, "encoding", None) or "").lower()
        return "utf" in encoding

    # -- primitives --------------------------------------------------------

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        prefix = "".join(_ANSI.get(style, "") for style in styles)
        return f"{prefix}{text}{_ANSI['reset']}"

    def write(self, text: str = "") -> None:
        if self.quiet:
            return
        self.stream.write(text + "\n")
        self.stream.flush()

    def error(self, text: str) -> None:
        sys.stderr.write(self.paint(f"error: {text}", "bright_red") + "\n")

    def warn(self, text: str) -> None:
        self.write(self.paint(f"! {text}", "bright_yellow"))

    def info(self, text: str) -> None:
        self.write(self.paint("* ", "cyan") + text)

    def ok(self, text: str) -> None:
        self.write(self.paint("+ ", "bright_green") + text)

    def banner(self) -> None:
        if self.quiet:
            return
        self.write(self.paint(_BANNER.rstrip("\n"), "bright_cyan", "bold"))
        self.write(f"  {self.paint(BRAND, 'bold')}  v{__version__}  {self.paint('-', 'dim')}  {TAGLINE}")
        self.write(f"  {self.paint(REPO, 'dim')}")
        self.write()

    # -- tables ------------------------------------------------------------

    def table(self, results: Sequence[EndpointResult], limit: int = 10) -> None:
        if self.quiet:
            return
        alive = [r for r in results if r.rtts]
        rows = (alive or list(results))[:limit]
        if not rows:
            self.warn("no endpoint answered")
            return

        headers = ["#", "ENDPOINT", "BEST", "AVG", "WORST", "JITTER", "LOSS"]
        widths = [3, 26, 9, 9, 9, 8, 6]
        h, v, tl, tr, bl, br, lj, rj, cj, tt, bt = (
            ("-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+")
            if not self.unicode
            else (
                "\u2500", "\u2502", "\u250c", "\u2510", "\u2514", "\u2518",
                "\u251c", "\u2524", "\u253c", "\u252c", "\u2534",
            )
        )

        def line(left: str, mid: str, right: str) -> str:
            return left + mid.join(h * (w + 2) for w in widths) + right

        def row(cells: Sequence[str], styles: Sequence[str] = ()) -> str:
            out = []
            for index, (cell, width) in enumerate(zip(cells, widths)):
                text = str(cell)[:width]
                pad = " " * (width - len(text))
                body = text + pad if index == 1 else pad + text
                out.append(" " + (self.paint(body, *styles) if styles else body) + " ")
            return v + v.join(out) + v

        self.write(self.paint(line(tl, tt, tr), "dim"))
        self.write(row(headers, ("bold",)))
        self.write(self.paint(line(lj, cj, rj), "dim"))
        for index, result in enumerate(rows, start=1):
            style = self._grade(result)
            self.write(
                row(
                    [
                        str(index),
                        str(result.endpoint),
                        self._ms(result.best),
                        self._ms(result.avg),
                        self._ms(result.worst),
                        self._ms(result.jitter),
                        f"{result.loss:.0f}%",
                    ],
                    (style,),
                )
            )
        self.write(self.paint(line(bl, bt, br), "dim"))

    def _grade(self, result: EndpointResult) -> str:
        if not result.rtts:
            return "dim"
        avg = result.avg or 0
        if result.loss == 0 and avg < 100:
            return "bright_green"
        if result.loss <= 34 and avg < 250:
            return "bright_yellow"
        return "bright_red"

    @staticmethod
    def _ms(value: Optional[float]) -> str:
        return "-" if value is None else f"{value:.1f} ms"

    def tunnel(self, check: TunnelCheck) -> None:
        label = str(check.endpoint)
        if check.ok:
            self.ok(
                f"{label} carries real traffic: handshake {check.handshake_ms:.1f} ms, "
                f"tunnel echo {check.avg_tunnel_ms:.1f} ms ({len(check.tunnel_rtts)} replies)"
            )
        elif check.handshake_ms is not None:
            self.warn(f"{label} handshakes in {check.handshake_ms:.1f} ms but returned no tunnel traffic"
                      + (f" ({check.error})" if check.error else ""))
        else:
            self.warn(f"{label} failed verification: {check.error or 'no response'}")


class Progress:
    """Single-line progress bar, safe to pipe (it simply goes quiet)."""

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
        label = {"ports": "probing ports", "scan": "scanning endpoints", "verify": "verifying"}.get(phase, phase)
        elapsed = now - self._started
        suffix = f"{done}/{total} {int(fraction * 100):>3}% {elapsed:5.1f}s"
        bar_width = max(10, min(40, columns - len(label) - len(suffix) - 8))
        filled = int(bar_width * fraction)
        glyph_full, glyph_empty = ("#", ".") if not self.console.unicode else ("\u2588", "\u2591")
        bar = glyph_full * filled + glyph_empty * (bar_width - filled)
        text = f"  {label} [{self.console.paint(bar, 'bright_cyan')}] {suffix}"
        pad = max(0, self._width - len(text))
        self._width = len(text)
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
