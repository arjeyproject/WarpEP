"""Project metadata for WarpEP by ArJey."""

__all__ = ["__version__", "NAME", "BRAND", "AUTHOR", "REPO", "TAGLINE", "user_agent"]

__version__ = "2.0.0"
NAME = "WarpEP"
BRAND = "WarpEP by ArJey"
AUTHOR = "ArJey"
REPO = "https://github.com/arjeyproject/WarpEP"
TAGLINE = "Real Cloudflare WARP endpoint scanner, with a panel"


def user_agent() -> str:
    return f"{NAME}/{__version__} (+{REPO})"
