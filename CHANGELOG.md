# Changelog

## 2.0.0

### The bug that made every endpoint look dead

1.x fell back to `Keypair.generate()` whenever no WARP registration was cached.

Cloudflare's WARP responder checks `mac1` (which anyone can compute from the public
responder key), then decrypts `encrypted_static` to learn **which client** is calling,
and looks that public key up in its peer list. A key that is not an enrolled WARP
device is dropped in silence: no response, no ICMP error, nothing.

So a scan with a throwaway key could only ever produce one result: every endpoint on
earth is dead. That is exactly what users were seeing.

**Fixed.** `warpep.identity` resolves an enrolled identity before any probe goes out,
in the order that actually works: `--key`, your cached registration, a bundled publicly
published enrolled identity, and only then a throwaway key behind an explicit
`--unregistered`. Registration is never attempted implicitly, so scanning still works
where `api.cloudflareclient.com` is blocked. The identity and its enrolled state appear
in the UI and in the JSON export, so any scan can be audited after the fact.

### Added

- **Interactive panel** (`warpep`, or `warpep panel`): numbered menu, identical on
  Termux, Windows, macOS and Linux.
- **Tunnel verification in the main flow.** The finalists of every scan get a real
  tunnel: handshake, transport keys, ICMP echo out and decrypted back. Only those are
  labelled `VERIFIED`.
- **`NO TRAFFIC` detection.** An endpoint that handshakes and then swallows traffic is
  marked and has its health halved, so it can no longer win a table.
- **Health scoring** (0-100) from loss, latency, jitter and the tunnel test, and it is
  what sorts the results instead of raw ping.
- **AmneziaWG obfuscation**: junk packets `Jc/Jmin/Jmax` and magic init packet `I1` with
  the icloud DNS preset. `--awg`, `--awg-jc`, `--awg-jmin`, `--awg-jmax`, `--i1`.
- **MASQUE probing** (`warpep masque`): QUIC version negotiation for HTTP/3 and
  TCP+TLS+ALPN h2 for the fallback that survives UDP blocking.
- **Network doctor** (`warpep doctor`): eleven real measurements and a prescription.
- **Operator awareness** (`warpep operators`): ASN detection from Cloudflare's edge plus
  a private, local, per-operator memory of endpoints that really answered.
- **Preflight** against known-good control endpoints before every scan.
- New exports: `warp://` links for Hiddify / NekoBox, AmneziaWG configs, and a JSON
  report including the identity, the network and the full audit trail.

### Changed

- Sampling is prefix-balanced, so a sample can no longer cluster in one blackholed /24
  and declare the whole space dead.
- Adaptive rate back-off when Cloudflare replies with cookie challenges.
- Send-buffer pressure is retried instead of being charged as endpoint packet loss.
- Every DNS-touching call is time-bounded: `getaddrinfo` is not covered by socket
  timeouts and a black-holed resolver used to stall the tool.
- New visual layer: boxed panels, health bars, latency sparklines, status badges, and
  full ASCII fallback for legacy consoles (`WARPEP_ASCII=1`).
- selftest grew from 7 to 14 checks.

## 1.0.0

Initial release: pure-Python WireGuard handshake scanner, WARP registration, WireGuard
and sing-box exports.
