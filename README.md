# WarpEP by ArJey

**A real Cloudflare WARP endpoint scanner, with a panel.** Every result comes from an
actual WireGuard handshake against Cloudflare's WARP responder, and the ones labelled
`VERIFIED` have carried real ICMP traffic through a real tunnel before you ever see them.

Zero dependencies. Pure Python. Runs on **Termux, Windows, macOS, Linux, WSL** and in a
container, without compiling anything.

[فارسی](README.fa.md)

---

## Install

Termux / Linux / macOS / WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.sh | bash
```

Windows (PowerShell):

```powershell
iwr -useb https://raw.githubusercontent.com/arjeyproject/WarpEP/main/install.ps1 | iex
```

Then type:

```bash
warpep
```

---

## The panel

`warpep` with no arguments opens the panel. Same menu on every operating system.

```
--  WARPEP PANEL  ----------------------------------------------

   1. endpoint scan fast
      ~20 s, port 2408, tuned for mobile data. Start here.
   2. endpoint scan deep
      every published prefix and every WARP port. Slow, thorough.
   3. endpoint scan IPv6
      for networks where IPv4 WARP is filtered but v6 is not.
   4. best endpoints for my operator
      re-verify what already worked on this network.
   5. MASQUE scan (TCP / QUIC)
      use when WireGuard UDP is dead: MASQUE rides HTTPS.
   6. verify one endpoint
      push real ICMP through a tunnel to a single ip:port.
   7. export config
      WireGuard, AmneziaWG, sing-box, warp:// or plain ip:port.
   8. network doctor
      what is actually broken here, in plain words.
   9. WARP account
  10. settings
  11. self test
   0. quit
```

Pick `1`. Twenty seconds later you get a table and one clear answer.

```
+-----+--------------------------+-----------------+----------+---------+-------+--------------+
|   # | ENDPOINT                 | HEALTH          |  PING ms |  JITTER |  LOSS | STATUS       |
+-----+--------------------------+-----------------+----------+---------+-------+--------------+
|   1 | 162.159.192.19:2408      | ########## 100  |     40.4 |     3.5 |    0% |  VERIFIED    |
|   2 | 188.114.98.224:894       | #######...  70  |    126.0 |    20.3 |   20% |  ALIVE       |
|   3 | 188.114.97.7:2408        | ##........  17  |    420.0 |     0.0 |   80% |  NO TRAFFIC  |
+-----+--------------------------+-----------------+----------+---------+-------+--------------+

+- USE THIS ENDPOINT -----------------------------------------------------------+
| endpoint      162.159.192.19:2408                                            |
| health        ############## 100/100  (excellent)                            |
| latency       40.4 ms avg, 38.0 ms best, 3.5 ms jitter                       |
| loss          0%  over 5 real handshakes                                     |
| tunnel        VERIFIED - 2 ICMP echoes returned, 50.5 ms through the tunnel   |
| obfuscation   AmneziaWG (jc=5 jmin=22 jmax=88, i1=magic)                     |
+------------------------------------------------------------------------------+
```

### What the badges mean

This is the important part, and it is why WarpEP 2.0 exists.

| Badge | Meaning | Should you use it? |
|---|---|---|
| `VERIFIED` | Handshake completed **and** real ICMP went through the tunnel and came back decrypted. | **Yes.** This endpoint works. |
| `ALIVE` | A cryptographically valid WireGuard handshake completed. Not tunnel-tested. | Probably. Verify it first. |
| `RATE LIMITED` | Cloudflare answered with a cookie challenge. Alive, but throttling you. | Slow down: `--rate 200`. |
| `NO TRAFFIC` | Handshakes fine, then swallows your packets. **The classic trap.** | **No.** This is the "fast but dead" endpoint. |
| `DEAD` | Nothing came back at all. | No. |

Other tools sort by ping and hand you row 1. On a ping-sorted table a 30 ms endpoint
that drops your traffic always beats a 120 ms one that carries it. WarpEP sorts by
**health**, demotes `NO TRAFFIC` on purpose, and only exports endpoints it will stand
behind.

---

## Command line

```bash
warpep                            # panel on a terminal, scan when piped
warpep scan --fast                # ~20 s, port 2408, great on mobile data
warpep scan --deep                # every published address, every WARP port
warpep scan -6                    # IPv6, when IPv4 WARP is filtered
warpep scan --awg                 # force AmneziaWG obfuscation on every probe
warpep scan --verify 5            # tunnel-test the best five
warpep masque                     # MASQUE over TCP/443, for dead-UDP networks
warpep masque --transport both    # ...and over QUIC
warpep verify 162.159.192.1:2408  # prove one endpoint carries traffic
warpep config -o warp.conf        # WireGuard config for the winner
warpep config --format amneziawg -o warp-awg.conf
warpep doctor                     # what is actually broken on this network
warpep register                   # your own WARP device (cached locally)
warpep operators                  # what has worked on each network you use
warpep selftest                   # 14 checks: crypto vectors and the scan loop
```

Exports: `--json`, `--csv`, `-o` (plain `ip:port`), `--links` (`warp://` for Hiddify /
NekoBox), `--conf`, `--awg-conf`, `--singbox`.

---

## Why WarpEP finds working endpoints when other scanners show a wall of dead ones

**1. It probes with an enrolled identity.** Cloudflare's WARP responder decrypts
`encrypted_static` to find out which client is calling, and **silently drops**
handshakes from keys that are not enrolled WARP devices. No reply, no ICMP error,
nothing. Any scanner that probes with a freshly generated keypair can only ever report
one thing: every endpoint on earth is dead. WarpEP 1.x had exactly that bug - it is what
you were seeing. 2.0 resolves an enrolled identity before any probe leaves the machine,
ships one so a fresh install works with no network calls at all, and prints
`enrolled: NO` in red if you ever force otherwise.

**2. Preflight before blame.** Control endpoints that are known to answer are probed
first. If they are silent, the fault is your identity, your network or your UDP ports,
and WarpEP says so instead of printing 4000 dead rows.

**3. A funnel, not a flat sweep.** One cheap probe finds who is home. Survivors get
several more, so latency and jitter come from a real sample. Finalists get a full
tunnel: handshake, transport keys, ICMP out, decrypted on the way back.

**4. Real anti-censorship on the probes.** AmneziaWG junk packets (`Jc/Jmin/Jmax`) and a
magic init packet (`I1`, a DNS response for `icloud.com`) so the flow does not open with
a recognisable 148-byte WireGuard initiation. The handshake itself stays byte-exact, so
a reply still proves the endpoint is real. If only the obfuscated probes survive, your
network is fingerprinting WireGuard and you need an AmneziaWG client - WarpEP will
export that config for you.

**5. MASQUE, measured for real.** Cloudflare's newest WARP transport is CONNECT-IP over
HTTP/3, with an HTTP/2-over-TCP fallback that looks like ordinary HTTPS on the wire.
WarpEP probes HTTP/3 with a QUIC version-negotiation packet - the reply must echo our
connection IDs, so a middlebox cannot fake it - and the fallback with a real TCP + TLS +
ALPN `h2` handshake. When UDP is completely dead, this is your route.

**6. It knows your ISP.** Filtering is per operator, not per country: an endpoint that is
perfect on Irancell can be a black hole on TCI. WarpEP asks Cloudflare's own edge which
ASN you are on, then keeps a **private, local** record of what actually answered on
*that* network and re-probes those first next time. Nothing leaves your machine.

---

## When nothing works

Run `warpep doctor`. It measures the identity, UDP, DNS, the WARP API, WireGuard over v4
and v6, which ports get out, MASQUE over TCP and over QUIC, then tells you which one to
fix:

```
 WHAT TO DO
 1.   UDP WireGuard is dead on this network, but MASQUE over TCP/443 answers.
      Run 'warpep masque' and use the result with a MASQUE client such as usque.
```

Quick fixes:

- every endpoint `DEAD` and header says `enrolled: NO` -> `warpep register`
- control endpoints silent, MASQUE answers -> `warpep masque`
- default ports blocked -> `warpep scan --ports all`
- IPv4 filtered -> `warpep scan -6`
- everything `RATE LIMITED` -> `warpep scan --rate 200 -c 2`
- broken box characters -> `WARPEP_ASCII=1 warpep`

Files live in `~/.config/warpep` (`%APPDATA%\WarpEP` on Windows), override with
`WARPEP_HOME`. Nothing is uploaded anywhere.

---

## Credit

Inspired by [vernette/warpscout](https://github.com/vernette/warpscout), whose research
into the WARP address space, the MASQUE pools and AmneziaWG shaping made this possible.
WarpEP is an independent pure-Python implementation with its own panel.

MIT licensed. Use it to reach the open internet.
