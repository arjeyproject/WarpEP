# Security policy

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/arjeyproject/WarpEP/security/advisories/new)
or a regular issue for non-sensitive reports. Please include a reproduction and the
output of `warpep selftest`.

## What WarpEP does with keys

- Ephemeral and static Curve25519 keys are generated with `os.urandom`.
- A WARP registration (only created when you run `warpep register`, or when you ask
  for a config) is cached at `~/.config/warpep/account.json`
  (`%APPDATA%\WarpEP\account.json` on Windows) with `0600` permissions where the
  platform supports it.
- Nothing is ever uploaded anywhere except the WARP registration request itself,
  which goes to Cloudflare's public client API.
- Generated `.conf` and `.json` files contain a private key. Treat them like passwords.

## Cryptography notes

The X25519 and ChaCha20-Poly1305 implementations in `warpep/wireguard/` are pure
Python and verified against the RFC 7748 and RFC 8439 test vectors. They are written
for a scanner that uses throwaway keys: they are not hardened against local
side-channel attackers, and they are not a general-purpose crypto library. Do not
reuse them to protect long-lived secrets on a shared machine.

## Scope and etiquette

WarpEP speaks the WARP protocol to Cloudflare's published WARP service addresses at
a rate-limited pace, exactly as a client selecting an endpoint would. Do not use it
to flood third-party hosts; `--rate` exists for a reason.
