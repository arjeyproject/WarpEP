# How the WarpEP engine works

A deep dive into what happens between typing `warpep scan` and seeing a ranked
table. Everything described here is implemented in this repository, with no
third-party code.

## 1. The handshake WarpEP sends

WireGuard uses the Noise pattern `IKpsk2` with Curve25519, ChaCha20-Poly1305 and
BLAKE2s. WarpEP builds message type 1 exactly as the protocol specifies:

```
offset  size  field
0       1     type = 1
1       3     reserved (zero)
4       4     sender index (unique per probe)
8       32    unencrypted ephemeral public key
40      48    AEAD(our static public key)
88      28    AEAD(TAI64N timestamp)
116     16    MAC1 = BLAKE2s-128(HASH("mac1----" || Spub_r), msg[0:116])
132     16    MAC2 = zero (no cookie held)
--------------
total   148 bytes
```

Key derivation follows the whitepaper step by step:

```
Ci  = HASH(CONSTRUCTION)
Hi  = HASH(Ci  || IDENTIFIER)
Hi  = HASH(Hi  || Spub_r)
Ci  = KDF1(Ci, Epub_i)
Hi  = HASH(Hi  || Epub_i)
Ci, k = KDF2(Ci, DH(Epriv_i, Spub_r))
msg.static    = AEAD(k, 0, Spub_i, Hi)
Hi  = HASH(Hi || msg.static)
Ci, k = KDF2(Ci, DH(Spriv_i, Spub_r))
msg.timestamp = AEAD(k, 0, TAI64N(), Hi)
Hi  = HASH(Hi || msg.timestamp)
```

`CONSTRUCTION` is `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, `IDENTIFIER` is
`WireGuard v1 zx2c4 Jason@zx2c4.com`, and `Spub_r` is Cloudflare's published WARP
responder key `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=`.

## 2. What counts as a valid reply

A response (message type 2, exactly 92 bytes) is accepted only after four
independent checks:

1. **Source address** matches the endpoint we probed (kills spoofing and NAT confusion).
2. **Receiver index** equals the sender index of that specific probe (kills
   cross-talk between probes).
3. **MAC1** verifies as `BLAKE2s-128(HASH("mac1----" || Spub_i), msg[0:60])`. Only a
   peer that read our static public key out of the initiation can compute this.
4. **AEAD decryption** of the response's empty payload succeeds after mixing
   `DH(Epriv_i, Epub_r)` and `DH(Spriv_i, Epub_r)` into the chaining key. This is
   full cryptographic proof that the responder holds the WARP private key.

Message type 3 (cookie reply) is recognised separately: the endpoint is alive but
rate limiting, which is reported as `cookie_replies` rather than as latency.

## 3. Why the scan is fast

- **One socket.** All probes share a single non-blocking UDP socket per address
  family; replies are demultiplexed by sender index. No thread pools, no fd storms.
- **Ephemeral pool.** Curve25519 in pure Python costs a few milliseconds. The
  scanner precomputes a pool of ephemeral keypairs (with `DH(Epriv, Spub_r)` cached)
  and reuses them across *different* endpoints, so each probe costs only two BLAKE2s
  hashes and two small AEAD seals. Every endpoint still receives a unique, valid,
  fresh handshake.
- **Token bucket.** `--rate` paces sends so a sweep never looks like a flood.
- **Two phases.** Port reachability is learned from a small sample first, so the
  expensive phase only touches ports your network actually allows.

## 4. Timing methodology

`time.perf_counter()` is read immediately before `sendto` and immediately after the
matching reply is parsed, so the RTT contains the network path plus a few
microseconds of parsing, not scheduler noise. Per endpoint WarpEP reports:

- `best` = min RTT
- `avg` = arithmetic mean of successful probes
- `worst` = max RTT
- `jitter` = mean of `|rtt[i+1] - rtt[i]|`, the same idea as `ping`'s mdev
- `loss` = `(sent - received) / sent`

Ranking score is `avg + jitter/2 + loss * 10`, so a lossy 10 ms endpoint always
ranks below a clean 120 ms endpoint. Unresponsive endpoints score infinity.

## 5. Deep tunnel verification

`warpep verify` (and `warpep scan --verify N`) goes past the handshake:

1. Complete the handshake and derive `(Tsend, Trecv) = KDF2(C, ε)`.
2. Build an IPv4 + ICMP echo request by hand from the WARP-assigned client address
   to a Cloudflare address inside the tunnel.
3. Pad to a 16-byte boundary, seal with `Tsend` and a 12-byte nonce
   (`4 zero bytes || counter LE64`), wrap in a type-4 data message.
4. Read the reply, decrypt with `Trecv`, parse the inner IPv4/ICMP header and match
   the echo identifier and sequence.

If that echo comes back, the endpoint is not just answering handshakes: it is
routing your packets. A routable check needs a registered peer, which is what
`warpep register` provides through Cloudflare's public client API.

## 6. Proving it locally

`warpep selftest` runs, on your machine:

- RFC 7748 X25519 vectors and a random key agreement,
- RFC 8439 ChaCha20 block, Poly1305 and AEAD vectors,
- a complete handshake against an in-process responder, checking that both sides
  derive matching transport keys,
- a full scan loop over loopback where the live endpoint must rank first and a dead
  port must show 100% loss.

The test suite in `tests/` extends this with hostile-endpoint cases: garbage
replies, cookie replies, partial loss, responses addressed to another session, and
random UDP noise. None of them are ever counted as a working endpoint.

## References

- Donenfeld, J. A. — *WireGuard: Next Generation Kernel Network Tunnel* (protocol,
  section 5.4)
- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
- RFC 7693 — The BLAKE2 Cryptographic Hash and MAC
