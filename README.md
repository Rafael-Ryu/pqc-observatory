# pqc-observatory

Measures adoption of post-quantum key exchange (`X25519MLKEM768`, the hybrid
ML-KEM group) in TLS, by completing a real TLS 1.3 handshake against public
endpoints and reading the group the server negotiated in its ServerHello. The
output is a versioned, reproducible dataset.

The signal is deliberately narrow: a host counts as `supported` only when the
server actually negotiated the PQC group. Nothing is inferred from cipher
lists, ALPN, or banners. Timeouts, handshake errors, and TLS 1.2-only servers
are recorded as `unknown`, never as a negative or a false positive.

## How it works

A small Go probe (`probe/`, using Go's `crypto/tls`) offers
`[X25519MLKEM768, X25519]` over TLS 1.3 and reports the negotiated group. A
Python layer (`src/pqc_observatory/`) runs the probe over a pinned target list
and derives the dataset. Verdict logic is pure and unit-tested; the dataset
re-derives byte-identically from the raw handshake results.

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
  configuration. A single sample is a point-in-time observation of one path,
  not a guarantee for every edge. Multi-sample confirmation is planned.
- **The legacy draft group** `X25519Kyber768Draft00` (`0x6399`). Go's TLS stack
  cannot offer it, so it is not measured here yet.
- **Anything above the key exchange.** This says nothing about certificate
  signatures, session resumption, or application-layer behavior.

## Ethics

Only public TLS handshakes against public endpoints, one handshake per host, no
authentication and no scanning of private infrastructure — the same kind of
capability measurement SSL Labs and Cloudflare Radar publish.
