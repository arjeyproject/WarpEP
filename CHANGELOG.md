# Changelog

All notable changes to WarpEP by ArJey are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-08-31

First public release.

### Added

- **Real WARP scan engine.** Cryptographically valid WireGuard
  (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) handshake probes against Cloudflare's
  published WARP responder key, with four-step verification of every reply
  (source address, session index, MAC1, AEAD decryption).
- **Zero-dependency crypto.** Pure-Python X25519 (RFC 7748), ChaCha20-Poly1305
  (RFC 8439) and BLAKE2s-based HKDF, all verified against official test vectors.
- **Metrics per endpoint.** Best / average / worst RTT, jitter (mdev), packet loss
  and cookie-reply detection, ranked by loss, then latency, then stability.
- **Two-phase scanning.** Port reachability discovery followed by a paced,
  single-socket latency sweep with a token-bucket rate limiter.
- **Deep tunnel verification.** `warpep verify` derives transport keys and pushes a
  real ICMP echo through the tunnel, proving the endpoint routes traffic.
- **Real WARP registration.** `warpep register` creates and caches an actual WARP
  peer through Cloudflare's public client API.
- **Exports.** WireGuard `.conf`, sing-box / Hiddify outbound JSON, plain `ip:port`
  lines, JSON and CSV.
- **IPv4 and IPv6** support across all published prefixes, plus custom `--prefix`
  and `--target` scanning and `--peer-key` for your own WireGuard servers.
- **CLI.** `scan`, `verify`, `config`, `register`, `selftest`, `version`, with
  `--fast` / `--deep` presets, live progress bar and a coloured ranking table that
  degrades gracefully on legacy consoles.
- **Installers.** One-line `install.sh` (Linux, macOS, WSL, Termux, with air-gapped
  `WARPEP_TARBALL` support) and `install.ps1` (Windows, winget-assisted Python),
  both with `--run` and `--uninstall`.
- **Distribution.** `warpep.pyz` single-file bundle, PyInstaller binaries for
  Windows/Linux/macOS, Docker image, pip/pipx install.
- **Docs.** Full English and Persian guides plus per-platform tutorials for Termux,
  Windows CMD, Ubuntu and macOS, and a protocol deep dive.
- **CI.** Tests on Windows, Linux and macOS across Python 3.8 to 3.13, offline test
  suite with a genuine WireGuard responder on loopback, and a tagged release
  pipeline.
