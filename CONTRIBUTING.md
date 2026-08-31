# Contributing to WarpEP

Thanks for helping. Two rules keep this project what it is:

1. **Zero third-party dependencies.** The standard library only. It is the reason
   WarpEP installs in seconds on Termux and in a bare container.
2. **No fake results.** A probe counts as successful only when the protocol says so.
   No "if we got any UDP bytes back, call it alive" shortcuts.

## Getting set up

```bash
git clone https://github.com/arjeyproject/WarpEP && cd WarpEP
make test        # full offline suite
make selftest    # crypto vectors + scan loop
```

The suite runs a real WireGuard responder on loopback, so it needs no internet and
catches protocol regressions immediately.

## Before opening a pull request

- `make test` passes on your platform.
- `python -m warpep selftest` passes.
- New behaviour has a test. Protocol changes need a loopback test.
- Python 3.8 compatible (`from __future__ import annotations` where needed).
- Keep the CLI stable: adding flags is fine, renaming them is not.

## Good first contributions

- More published WARP ports or prefixes, with a source for the change.
- Extra export formats (Clash, WireGuard for Windows profiles, Xray outbound).
- Better platform detection in `install.sh` / `install.ps1`.
- Translations of the docs beyond English and Persian.

## Reporting bugs

Open an [issue](https://github.com/arjeyproject/WarpEP/issues) with:

- `warpep --version` output and your OS,
- the exact command you ran,
- the output of `warpep selftest`,
- what you expected versus what happened.

Never paste a private key or the contents of `account.json`.
