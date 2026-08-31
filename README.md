<div align="center">

```
 __        __                 _____ ____
 \ \      / /_ _ _ __ _ __   | ____|  _ \
  \ \ /\ / / _` | '__| '_ \  |  _| | |_) |
   \ V  V / (_| | |  | |_) | | |___|  __/
    \_/\_/ \__,_|_|  | .__/  |_____|_|
                     |_|
```

# WarpEP · by ArJey

**A real Cloudflare WARP endpoint scanner.** Not a ping tool, not a port poker:
every probe is a cryptographically valid WireGuard handshake, and every result is
verified before you ever see it.

[![CI](https://github.com/arjeyproject/WarpEP/actions/workflows/ci.yml/badge.svg)](https://github.com/arjeyproject/WarpEP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776ab.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-informational.svg)](#installation)

**English** · [فارسی](README.fa.md)

</div>

---

## Table of contents

- [Why WarpEP](#why-warpep)
- [Features](#features)
- [Installation](#installation)
  - [Android · Termux](#android--termux)
  - [Windows · CMD or PowerShell](#windows--cmd-or-powershell)
  - [Linux · Ubuntu and friends](#linux--ubuntu-and-friends)
  - [macOS](#macos)
  - [Run without installing](#run-without-installing)
  - [pip, pipx, Docker](#pip-pipx-docker)
- [One-line install + one-line scan](#one-line-install--one-line-scan-cheat-sheet)
- [Usage](#usage)
- [Command reference](#command-reference)
- [Reading the output](#reading-the-output)
- [Using the results](#using-the-results)
- [How the scan engine really works](#how-the-scan-engine-really-works)
- [Tuning](#tuning)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Development](#development)
- [License and credits](#license-and-credits)

---

## Why WarpEP

Cloudflare WARP is reachable on hundreds of anycast IP and port combinations. Which
of them is fast **for you** depends on your ISP, your city, your carrier and the time
of day. Most "endpoint scanners" answer that question badly:

| Approach | What it actually measures | Problem |
| --- | --- | --- |
| ICMP ping | whether Cloudflare's edge answers ping | the WARP responder can be dead while ping is perfect |
| Blind UDP send | nothing at all | UDP has no handshake; silence looks like success |
| Replaying a captured packet | one stale handshake | replay protection and MAC checks make results unreliable |
| **WarpEP** | **a full WireGuard handshake, cryptographically verified** | **none: if it answers, it is a working WARP responder** |

WarpEP speaks the actual protocol. It builds a real
`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake initiation against Cloudflare's
published WARP responder key, and it only counts a reply when:

1. the response is exactly 92 bytes with message type `2`,
2. the receiver index matches the sender index of *that* probe,
3. `MAC1` verifies against **our** static public key,
4. the mixed chaining key successfully decrypts the response's AEAD payload.

A captive portal, a middlebox, a random UDP echo or a spoofed packet fails all of
that. And `warpep verify` goes one step further: it derives the transport keys and
pushes a **real ICMP echo through the tunnel**, proving the endpoint actually carries
traffic instead of merely answering handshakes.

## Features

- **Real handshakes, real numbers** — best / average / worst RTT, jitter (mdev) and
  packet loss per endpoint, measured over multiple independent probes.
- **Zero dependencies** — X25519, ChaCha20-Poly1305, BLAKE2s HKDF and the whole
  WireGuard handshake live in this repo. No pip wheels, no compiler, no root. That
  is why Termux installs in seconds.
- **Everywhere** — Windows (CMD, PowerShell, Terminal), Ubuntu/Debian/Fedora/Arch/
  Alpine, macOS (Intel and Apple silicon), Android via Termux, WSL, Docker, CI.
- **Two-phase scanning** — first learn which WARP ports your network allows, then
  spend all your time on those.
- **Deep verification** — `warpep verify` completes the handshake and sends real
  encrypted ICMP traffic through the tunnel.
- **Real WARP registration** — `warpep register` creates an actual WARP peer through
  Cloudflare's public client API and caches it, so generated configs work as-is.
- **Exports that paste anywhere** — WireGuard `.conf`, sing-box / Hiddify outbound
  JSON, plain `ip:port` lines, JSON and CSV.
- **IPv4 and IPv6** — the whole published address space, or your own `--prefix`.
- **Fast and polite** — one non-blocking socket, token-bucket rate limiting, a full
  sweep in seconds without flooding anyone.
- **Provable** — `warpep selftest` re-runs the RFC 7748 / RFC 8439 vectors, a full
  handshake and a complete scan loop on *your* machine.

## Installation

Every platform gets a **single line**. Pick yours.

### Android · Termux

Install [Termux](https://termux.dev) (the F-Droid build is recommended), then:

```bash
pkg update -y && pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

Install **and** scan in one line:

```bash
pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run --fast
```

Afterwards, any time:

```bash
warpep scan --fast
```

> No root needed, and no separate Python step: the installer handles Python for you.
> Full walkthrough: [docs/INSTALL_TERMUX.md](docs/INSTALL_TERMUX.md).

### Windows · CMD or PowerShell

Open **CMD** (or PowerShell) and paste one line:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

Install **and** scan in one line:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:WARPEP_RUN=1; irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex"
```

Open a **new** CMD window afterwards so the PATH refreshes, then:

```bat
warpep
warpep scan --fast
```

> Python missing? The installer pulls it in with `winget` automatically.
> Step-by-step guide: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md).

### Linux · Ubuntu and friends

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

Install **and** scan in one line:

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
```

Then:

```bash
warpep scan
```

Tested on Ubuntu, Debian, Mint, Fedora, RHEL, Arch, Manjaro, openSUSE, Alpine and
WSL. If `~/.local/bin` is not on your `PATH`, the installer prints the exact line to
add. Details: [docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md).

### macOS

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

Install **and** scan in one line:

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --run
```

Details: [docs/INSTALL_MACOS.md](docs/INSTALL_MACOS.md).

### Run without installing

Scan once, install nothing, leave no trace (any OS with Python 3.8+):

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --no-install --fast
```

Or grab the single-file bundle from the latest release:

```bash
curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz
python3 warpep.pyz scan --fast
```

```bat
:: Windows CMD
curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz
python warpep.pyz scan --fast
```

Standalone binaries with no Python at all are attached to every
[release](https://github.com/arjeyproject/WarpEP/releases) for Windows, Linux and macOS.

### pip, pipx, Docker

```bash
pipx install git+https://github.com/arjeyproject/WarpEP        # recommended
pip install --user git+https://github.com/arjeyproject/WarpEP  # plain pip
```

```bash
git clone https://github.com/arjeyproject/WarpEP && cd WarpEP
docker build -t warpep .
docker run --rm -it warpep scan --fast
```

Uninstall any time:

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash -s -- --uninstall
```

```powershell
irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 -OutFile i.ps1; ./i.ps1 -Uninstall
```

## One-line install + one-line scan (cheat sheet)

| Platform | One-line install | One-line scan |
| --- | --- | --- |
| **Android (Termux)** | `pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh \| bash` | `warpep scan --fast` |
| **Windows (CMD)** | `powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 \| iex"` | `warpep scan --fast` |
| **Linux (Ubuntu)** | `curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh \| bash` | `warpep scan` |
| **macOS** | `curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh \| bash` | `warpep scan` |
| **Anything with Python** | `curl -fsSLO https://github.com/arjeyproject/WarpEP/releases/latest/download/warpep.pyz` | `python3 warpep.pyz scan --fast` |

## Usage

```bash
warpep                       # scan, rank, and show the best endpoints
warpep scan --fast           # quick scan (great on mobile data)
warpep scan --deep           # every published prefix, every port, 5 probes each
warpep scan -6               # scan the IPv6 WARP prefixes
warpep scan -n 512 -c 5      # 512 sampled addresses, 5 handshakes each
warpep scan --top 20         # show 20 rows instead of 10
warpep verify 162.159.192.1:2408
warpep config -o warp.conf   # WireGuard config for the fastest endpoint
warpep register              # create a real WARP registration
warpep selftest              # prove the crypto and scan loop on this machine
```

Typical output:

```
* address space: 1778 addresses in 7 IPv4 prefix(es), probing 128
+ reachable ports on this network: 2408, 500, 1701
* probing 384 endpoints with 3 real WireGuard handshakes each

┌─────┬────────────────────────────┬───────────┬───────────┬───────────┬──────────┬────────┐
│   # │ ENDPOINT                   │      BEST │       AVG │     WORST │   JITTER │   LOSS │
├─────┼────────────────────────────┼───────────┼───────────┼───────────┼──────────┼────────┤
│   1 │ 162.159.192.79:2408        │   28.4 ms │   31.2 ms │   35.9 ms │   3.1 ms │     0% │
│   2 │ 188.114.97.140:500         │   33.7 ms │   34.8 ms │   36.2 ms │   1.4 ms │     0% │
│   3 │ 162.159.193.10:1701        │   41.2 ms │   47.9 ms │   58.1 ms │   8.6 ms │     0% │
└─────┴────────────────────────────┴───────────┴───────────┴───────────┴──────────┴────────┘

* 37 of 384 endpoints answered in 6.4s (1152 handshakes sent)
+ best endpoint: 162.159.192.79:2408 (31.2 ms avg, 0% loss, 3.1 ms jitter)
```

## Command reference

### `warpep scan`

| Flag | Meaning | Default |
| --- | --- | --- |
| `-6, --ipv6` | scan the IPv6 WARP prefixes | IPv4 |
| `-n, --sample N` | how many addresses to sample (`0` = every address) | `128` |
| `-c, --probes N` | handshakes per endpoint | `3` |
| `-p, --ports LIST` | `2408`, `500-520`, `primary`, `all` (repeatable) | auto-discovered |
| `--prefix CIDR` | scan your own prefixes instead of the published ones | WARP prefixes |
| `--target IP:PORT` | scan only these endpoints (repeatable, comma-separated) | – |
| `--timeout SEC` | reply timeout per probe | `1.2` |
| `--rate N` | probes per second (token bucket) | `1500` |
| `--max-inflight N` | outstanding probes at once | `512` |
| `--source-ip ADDR` | bind probes to a local address / interface IP | auto |
| `--seed N` | reproducible address sampling | random |
| `--fast` | preset: 48 addresses, port 2408, 2 probes | off |
| `--deep` | preset: every address, all ports, 5 probes | off |
| `--skip-port-scan` | trust `--ports`, skip discovery | off |
| `-t, --top N` | rows to display | `10` |
| `--verify [N]` | deep-verify the best N endpoints through the tunnel | off |
| `--json FILE` | full results as JSON | – |
| `--csv FILE` | full results as CSV | – |
| `-o, --out FILE` | winning endpoints as plain `ip:port` lines | – |
| `--conf FILE` | WireGuard config for the winner | – |
| `--singbox FILE` | sing-box / Hiddify outbound for the winner | – |
| `--peer-key B64` | responder public key (point it at your own WireGuard server) | Cloudflare WARP |

### `warpep verify IP:PORT`

| Flag | Meaning | Default |
| --- | --- | --- |
| `--echoes N` | ICMP echoes to push through the tunnel | `3` |
| `--target IP` | address to ping inside the tunnel | `162.159.192.1` |
| `--timeout SEC` | per-step timeout | `2.5` |

### `warpep config [IP:PORT]`

| Flag | Meaning | Default |
| --- | --- | --- |
| `--format` | `wireguard`, `singbox`, `endpoint` | `wireguard` |
| `-o, --out FILE` | write to a file instead of stdout | stdout |
| `--mtu N` | interface MTU | `1280` |
| `--no-register` | never contact the WARP API, use a local key | off |

Omit the endpoint and WarpEP scans first, then writes a config for the winner.

### Global flags

`--no-color`, `-q/--quiet`, `-V/--version`, `-h/--help`. They work before *or* after
the subcommand, so `warpep -q scan` and `warpep scan -q` are both fine.

Exit codes: `0` success · `1` nothing found / network failure · `2` usage error ·
`130` interrupted.

## Reading the output

| Column | Meaning |
| --- | --- |
| `BEST` | fastest verified handshake round trip |
| `AVG` | mean of all successful handshakes (the number that matters) |
| `WORST` | slowest successful handshake |
| `JITTER` | mean deviation between consecutive probes, like `ping`'s mdev |
| `LOSS` | share of probes that never came back |

Rows are ranked by `avg + jitter/2 + loss×10`: **loss first, then latency, then
stability**. Green means clean and fast, yellow means usable, red means desperate.
Endpoints that answer only with a *cookie reply* count as alive (the responder is
there but rate limiting) and appear in JSON as `cookie_replies`.

## Using the results

**Any WARP client (v2rayNG, Hiddify, NekoBox, WARP+ apps).** Paste the endpoint:

```bash
warpep scan -o best-endpoints.txt   # one ip:port per line, best first
```

**WireGuard / wg-quick.** Real registration, real config:

```bash
warpep register
warpep config -o warp.conf
sudo wg-quick up ./warp.conf
```

**sing-box / Hiddify outbound.**

```bash
warpep config --format singbox -o warp-outbound.json
```

**Automation.** Machine-readable results for cron jobs and dashboards:

```bash
warpep scan --fast --json results.json --csv results.csv -q
```

## How the scan engine really works

1. **Address space.** Cloudflare's published WARP prefixes: `162.159.192.0/24`,
   `162.159.193.0/24`, `162.159.195.0/24`, `188.114.96.0/24`, `188.114.97.0/24`,
   `188.114.98.0/24`, `188.114.99.0/24`, plus `2606:4700:d0::/64` and
   `2606:4700:d1::/64` for IPv6. Ports are the ones the official client falls back
   through, `2408` first, 53 in total.
2. **Phase 1 — port reachability.** A handful of addresses are probed across the
   candidate ports to learn what your network actually permits. If no primary port
   answers, WarpEP sweeps every published port before giving up.
3. **Phase 2 — latency and loss.** Every endpoint receives `--probes` independent
   handshake initiations, each with its own sender index and TAI64N timestamp.
   Replies are matched back by index, verified cryptographically, and timed with
   `time.perf_counter` around the send.
4. **Ranking.** Loss first, then average RTT, then jitter.
5. **Optional deep verify.** Transport keys are derived from the completed
   handshake, an ICMP echo request is built by hand, encrypted as a WireGuard type-4
   data message, and the reply is decrypted and matched by echo sequence.

Implementation map:

| File | Job |
| --- | --- |
| `warpep/wireguard/x25519.py` | Curve25519, RFC 7748, pure Python |
| `warpep/wireguard/chacha20poly1305.py` | AEAD, RFC 8439, pure Python |
| `warpep/wireguard/noise.py` | the WireGuard handshake, initiator and responder |
| `warpep/wireguard/transport.py` | data-plane packets, IPv4/ICMP builder |
| `warpep/endpoints.py` | published prefixes, ports, sampling |
| `warpep/engine.py` | the scan loop, rate limiting, scoring, tunnel check |
| `warpep/account.py` | real WARP registration via Cloudflare's client API |
| `warpep/exporters.py` | WireGuard / sing-box / JSON / CSV output |
| `warpep/output.py` | banner, live progress, ranking table |
| `warpep/selftest.py` | RFC vectors + full scan loop, on your machine |

Everything is covered by an offline test suite that runs a **genuine WireGuard
responder on loopback**, so `make test` needs no internet at all.

## Tuning

| Situation | Do this |
| --- | --- |
| Mobile data, slow network | `warpep scan --fast` |
| Serious hunt for the best endpoint | `warpep scan --deep -c 5 --top 20` |
| ISP blocking port 2408 | `warpep scan -p all` |
| Your ISP is rate limiting you | lower `--rate 300` and `--max-inflight 64` |
| Multiple uplinks | `warpep scan --source-ip 192.168.1.50` |
| IPv6-only or dual stack | `warpep scan -6` |
| Reproducible benchmarking | `warpep scan --seed 42 -n 256` |
| Deep confidence in the winner | `warpep scan --verify 3` |

## Troubleshooting

**`warpep: command not found` (Linux/macOS/Termux)** — `~/.local/bin` is not on your
PATH. Add `export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc` or `~/.zshrc` and
reopen the shell. Or run it directly: `python3 -m warpep scan`.

**`warpep` not recognised in CMD** — open a *new* CMD window after installing so the
PATH refreshes. Still nothing? Run `%LOCALAPPDATA%\WarpEP\bin\warpep.cmd`.

**PowerShell blocks the script** — use the exact one-liner above; it already includes
`-ExecutionPolicy Bypass`.

**Everything shows 100% loss** — your network is blocking UDP to Cloudflare. Try
`warpep scan -p all`, then a different network. Cellular data and Wi-Fi often differ.

**Nothing found on IPv6** — your ISP probably has no IPv6 route. Drop the `-6`.

**Termux says `pkg: command not found`** — you are in the Android shell, not Termux.
Open the Termux app itself.

**Results differ between runs** — anycast latency genuinely fluctuates. Use `-c 5`
for steadier averages and `--seed` for a comparable address sample.

**Is my Python OK?** Run `warpep selftest`. If the crypto vectors pass, the numbers
are trustworthy.

## FAQ

**Does this need root or VPN permission?** No. Plain unprivileged UDP sockets.

**Does it change my network settings?** No. WarpEP measures and reports; you decide
what to do with the winner.

**Why Python and not Go?** Because a single dependency-free Python package installs
in seconds on Termux, Windows CMD, an Alpine container and a CI runner, with no
compiler and no cross-build matrix. All the protocol work is here in the repo, and
the hot loop is one non-blocking socket, so a full sweep still finishes in seconds.

**Does registration cost anything or need an account?** No. `warpep register` uses
Cloudflare's public client API, the same one every WARP tool uses, and caches the
result in `~/.config/warpep/account.json` (`%APPDATA%\WarpEP` on Windows).

**Can I point it at my own WireGuard server?** Yes: `--peer-key <base64 pubkey>` with
`--target host:port`. Handy for measuring your own tunnels.

**Is scanning Cloudflare's endpoints allowed?** WarpEP only speaks the WARP protocol
to Cloudflare's published WARP service addresses, at a polite rate, exactly as a
client picking an endpoint would. Keep `--rate` sane and be a good citizen.

## Development

```bash
git clone https://github.com/arjeyproject/WarpEP && cd WarpEP
make test        # offline test suite, real handshakes over loopback
make selftest    # RFC vectors + scan loop
make scan        # fast scan
make bundle      # build warpep.pyz
```

The test suite spins up a real WireGuard responder on `127.0.0.1`, so protocol
regressions fail loudly and nothing depends on the internet. Contributions welcome:
see [CONTRIBUTING.md](CONTRIBUTING.md).

## License and credits

MIT © ArJey — see [LICENSE](LICENSE).

Built and branded as **WarpEP by ArJey**. The WireGuard protocol is the work of
Jason A. Donenfeld; "WireGuard" and "Cloudflare WARP" are trademarks of their
respective owners and this project is not affiliated with either. Inspired by the
excellent [warpscout](https://github.com/vernette/warpscout) and the wider WARP
tooling community; all code here was written from scratch for this repository.

<div align="center">

**WarpEP by ArJey** · [Report an issue](https://github.com/arjeyproject/WarpEP/issues) · [فارسی](README.fa.md)

</div>
