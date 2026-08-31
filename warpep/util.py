"""Small helpers that keep the tool responsive on a hostile network.

``socket`` timeouts do not cover name resolution: ``getaddrinfo`` is a blocking
libc call and on a network with a black-holed resolver it can sit there for half
a minute, which is exactly the network WarpEP is designed for. Every DNS-touching
call therefore goes through :func:`run_bounded`, so a wedged resolver costs the
declared timeout and not the user's patience.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional, TypeVar

__all__ = ["run_bounded"]

T = TypeVar("T")


def run_bounded(func: Callable[[], T], timeout: float, default: Optional[T] = None) -> Optional[T]:
    """Run ``func`` on a daemon thread and give up after ``timeout`` seconds.

    The thread is abandoned rather than killed - Python cannot interrupt a
    blocking syscall - but it is a daemon, so it never keeps the process alive.
    """
    box: dict = {}

    def target() -> None:
        try:
            box["value"] = func()
        except BaseException as exc:  # noqa: BLE001 - the caller decides what a failure means
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive() or "error" in box:
        return default
    return box.get("value", default)
