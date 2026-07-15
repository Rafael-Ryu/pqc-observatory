# pqc-observatory

Measures adoption of post-quantum key exchange (`X25519MLKEM768`, the hybrid
ML-KEM group) in TLS, by completing a real TLS 1.3 handshake against public
endpoints and reading the group the server negotiated in its ServerHello. The
output is a versioned, reproducible dataset.

The signal is deliberately narrow: a host counts as `supported` only when the
server negotiated the PQC group over a completed, certificate-verified TLS 1.3
handshake. Nothing is inferred from cipher lists, ALPN, or banners. A server
that negotiated a classical group is `not_observed` — that proves PQC was not
selected on this path, not that the server is incapable of it. Timeouts,
handshake errors, certificate failures, and TLS 1.2-only servers are `unknown`,
never a false positive.

## How it works

A small Go probe (`probe/`, using Go's `crypto/tls`) enables
`X25519MLKEM768` and `X25519` over TLS 1.3 and reports the group the server
selected. Go ignores the offered order and applies its own preference, so the
two groups are an enabled set, not a ranking. Certificate identity is verified
against the hostname, so a result is only attributed to an endpoint that proved
that identity. A Python layer (`src/pqc_observatory/`) runs the probe over a
pinned target list, samples each host five times, and aggregates by
unanimity into one verdict per host. Verdict logic is pure and unit-tested;
the dataset re-derives byte-identically from the raw handshake results. See
METHODOLOGY.md for the full specification and caveats.

Cross-checked independently with OpenSSL 3.6 (`openssl s_client -groups
X25519MLKEM768`), which agrees with the probe on the negotiated group.

## Usage

```
uv sync
uv run pqc-observatory scan --targets targets/2026-07.txt --out data --date 2026-07
```

This writes `data/raw-<date>.jsonl` (raw handshake results) and
`data/pqc-adoption-<date>.json` (the classified dataset with per-host verdicts
and counts).

## What this does not measure

- **Edge variance.** A hostname can resolve to different PoPs with different
  configuration. Each host is sampled five times, and a host counts as
  `supported` only when all five agree; a host whose samples disagree stays
  `unknown` rather than being reported as supported. This catches divergence
  across the paths we happen to hit, but from one vantage it cannot see every
  edge, and `peer_ip` is a weak proxy for edge identity (anycast hides many
  edges behind one address).
- **The legacy draft group** `X25519Kyber768Draft00` (`0x6399`). Go's TLS stack
  cannot offer it, so it is not measured here yet.
- **Anything above the key exchange.** This says nothing about certificate
  signatures, session resumption, or application-layer behavior.

The `supported` count is a **lower bound for this specific client and network
path**, not a full adoption rate. The probe sends a large ML-KEM ClientHello
over a TLS-1.3-only, Go-shaped handshake, so a server that is genuinely
PQC-capable can still land in `unknown` or `not_observed`: a middlebox
intolerant of large or TLS-1.3-only ClientHellos can drop the handshake, and an
anycast host may answer from a classical edge on the paths sampled. A positive
proves the sampled paths all support PQC; a negative does not characterize the
whole host.

## Ethics

Only public TLS handshakes against public endpoints, a few spaced handshakes
per host, no authentication and no scanning of private infrastructure — the
same kind of
capability measurement SSL Labs and Cloudflare Radar publish. A peer that
resolves to a private, loopback, link-local, or carrier-grade-NAT address is
rejected before the connection is made, so internal infrastructure is never
handshaked.
