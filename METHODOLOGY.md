# Methodology

This document is the finite specification of what pqc-observatory measures,
how, and what the numbers do and do not mean. If a claim in a release or in
the README is unclear, this document is the tiebreaker.

## What is measured

Whether a host, over a real TLS 1.3 handshake, negotiates
`X25519MLKEM768` — TLS Supported Groups id 4588 (`0x11EC`), a hybrid of
X25519 and ML-KEM-768, defined by draft-kwiatkowski-tls-ecdhe-mlkem and
registered in the IANA TLS Supported Groups registry.

Nothing is inferred from cipher lists, ALPN, or server banners. The only
signal that counts is the group id the server actually selected in its
handshake.

## The probe

A Go program (`probe/probe.go`) using Go's `crypto/tls` (Go 1.26) opens a
TLS 1.3 connection to each host and offers the set `{X25519MLKEM768,
X25519}`. Go treats `CurvePreferences` as a set, not a ranking: it ignores
the order the two groups are listed in and applies its own internal
preference. Enabling classical X25519 alongside the PQC group lets a
non-PQC server complete the handshake normally, so the probe observes its
actual choice instead of a bare failure.

The handshake is TLS 1.3 only (`MinVersion` = `MaxVersion` = TLS 1.3).
Certificate identity is verified against the hostname on every real target;
`InsecureSkipVerify` is never set for a named peer. A result is attributed
to a host only if that host's certificate proved its identity. A group
negotiated with a misrouted vhost, captive portal, or MITM does not produce
a verdict for the intended hostname.

Before the socket connects, the probe resolves DNS and rejects any
non-public destination address: loopback, private, CGNAT, link-local,
multicast, unspecified. Non-public infrastructure is never handshaked, even
if a target list were to point at one by mistake.

### Probe integrity

The probe's source (`probe.go` and `go.mod`) is pinned by SHA-256 in
`probe/source.sha256`. `verify_probe_source()` recomputes that hash before
every scan and aborts if it does not match, so a scan only ever runs
reviewed, committed code.

Before touching a single real host, the probe runs an in-memory self-test:
an in-process TLS 1.3 handshake, over a `net.Pipe`, against a server
configured to accept only `X25519MLKEM768`. If the client does not land on
that group, the probe exits with an error instead of proceeding. This
catches runtime poisoning that source pinning cannot — `GODEBUG=tlsmlkem=0`
and similar flags can silently strip ML-KEM from Go's effective ClientHello
without changing a single byte of source. A poisoned runtime aborts the run
rather than quietly publishing an all-classical dataset.

## Verdict grammar

Every sample classifies to exactly one of three verdicts. There is no
fourth option and no partial credit.

| Verdict | Meaning |
|---|---|
| `supported` | The server negotiated `X25519MLKEM768` over a completed, certificate-verified TLS 1.3 handshake. |
| `not_observed` | The server negotiated a classical group. This proves PQC was not selected on this path, not that the server is incapable of it. Go ignores the offered order, and a server may simply prefer classical when both are on the table. |
| `unknown` | Timeout, handshake or connection error, certificate failure, TLS 1.2-only response, an internally inconsistent probe record, or a missing sample. |

`not_observed` is deliberately not named `not_supported`: the probe
observes one negotiation on one path, not the server's full capability.

`unknown` is the deliberate default for anything ambiguous. A corrupted or
self-contradictory record (for example, a PQC group id paired with a
non-TLS-1.3 version, or a group id that does not match the reported group
name) is classified `unknown` rather than trusted. This never produces a
false positive.

## Multi-sample aggregation

Each host is sampled **five times** (`SAMPLES_PER_HOST = 5`), spaced roughly
750ms apart, each sample doing its own independent DNS resolution and TCP
connection. This exists because a single hostname can resolve to different
edges (anycast, CDN PoPs, load-balanced backends) that do not all run the
same TLS configuration.

The five samples reduce to one host-level verdict by unanimity:

- `supported` only if all five samples are `supported`.
- `not_observed` only if all five samples are `not_observed`.
- `unknown` for everything else: any error, any missing sample, or any mix
  of `supported` and `not_observed` across the five.

A single dissenting sample is never voted away. A host with four
`supported` samples and one timeout is `unknown`, not `supported`. It is the
same standard the pqcheck lineage applies to code-level findings: precision
before recall.

Each entry in the dataset records the full per-sample distribution
(`distribution: {supported, not_observed, unknown}` counts) alongside the
verdict, so a reader can see exactly how close a host was to unanimous
without having to re-run anything.

## peer_ip: recorded, never a gate

Every sample records the TCP peer's resolved IP address. The host-level
entry reports `distinct_peer_ips` and two flags:

- `single_vantage`: all samples hit the same IP (one distinct address).
- `divergent`: at least one sample was `supported` and at least one was
  `not_observed`, i.e. verdict-level disagreement, not just IP-level
  variation.

`peer_ip` never gates the verdict. Anycast can hide many distinct edges
behind a single address, and DNS round-robin can spread one identical
configuration across many addresses, so IP count alone says little about how
many actually distinct server configurations were sampled. It is recorded
for transparency, so a reader auditing a `supported` verdict can see
whether it came from one address or several.

## The adoption number

The denominator for any published count is **all pinned target hosts**.
`unknown`, `single_vantage`, and `divergent` hosts are never dropped from
the denominator to make a headline ratio look better. Any published count
of `supported` hosts is reported beside the full verdict distribution
(`supported` / `not_observed` / `unknown`), not in isolation.

`supported` means: unanimous observation of `X25519MLKEM768`, across five
samples, from this vantage point, during this run's time window. It does
not mean universal support for the hostname — see Lower bound, below.

## Lower bound, not an upper bound

`supported` is a **lower bound** for this specific client and network path,
not a ceiling on what a host can do. The probe sends a large ML-KEM
ClientHello over a TLS-1.3-only, Go-shaped handshake. A server that is
genuinely PQC-capable can still land in `unknown` or `not_observed`:

- A middlebox intolerant of large ClientHellos, or of TLS-1.3-only
  handshakes, can drop the connection before the server ever answers.
- An anycast or load-balanced host can route the sampled connections to an
  edge that answers classical, while a different edge behind the same
  hostname would have answered PQC.

A `supported` verdict is solid: it means the sampled paths, unanimously,
completed a real handshake on the PQC group. A `not_observed` or `unknown`
verdict says less than it might look like. It says this probe, from this
vantage, on these five attempts, did not observe PQC. It does not
characterize the host as a whole.

## What is not measured

- **The legacy draft group**, `X25519Kyber768Draft00` (`0x6399`). Go's TLS
  stack has no way to offer it, so it is out of scope for this probe.
- **Anything past the key exchange.** Certificate signature algorithms,
  session resumption behavior, and application-layer behavior are not
  observed or scored.
- **Universal edge coverage.** From a single vantage point, five samples
  cannot see every PoP a hostname may serve behind a CDN or anycast
  network. The five samples for one host also run within a few seconds of
  each other — they are spaced to avoid hammering the endpoint, but they
  are not temporally independent. Treat them as reducing point-in-time
  flakiness in a single run, not as sampling the target's configuration
  over time.
- **Real-world network state at any time other than the run.** What is
  reproducible is the *derivation* of the dataset from preserved raw
  evidence, not the network itself. Re-running the scan later can produce
  different results as deployments change; that is not a reproducibility
  failure, it is the network changing.

## Reproducibility

The dataset (`pqc-adoption-<date>.json`) is a deterministic projection of
the raw handshake results (`raw-<date>.jsonl`), the target list's SHA-256,
and a fixed methodology version. Same raw results plus same inputs produce
byte-identical JSON, regardless of who rebuilds it or on what machine.
`build_dataset()` in `src/pqc_observatory/dataset.py` has no I/O and no
dependency on wall-clock time, environment, or filesystem state beyond its
arguments.

Environment and provenance data that could explain *why* a run looks the
way it does (Go version, `GODEBUG`, the probe source SHA-256, and the
SHA-256 of each published artifact) is written to a sidecar
`manifest-<date>.json`, outside the dataset itself. This is deliberate: the
manifest can grow or change shape over time without ever touching the
byte-identical reproducibility contract of the dataset that third parties
rebuild and diff.

To reproduce a published dataset:

1. Recompute the SHA-256 of the pinned target list and compare it to
   `targets_sha256` in the dataset.
2. Rebuild the dataset from the published raw results and compare bytes.
3. Check that the manifest's `raw_sha256` and `dataset_sha256` match the
   published files, and that `probe_source_sha256` matches
   `probe/source.sha256` at the commit the run was built from.

What is reproducible is the *derivation* from preserved evidence, not a
claim that the network still looks the same today.

## Cross-check

An independent second implementation, OpenSSL 3.6's `s_client`, is used to
confirm the Go probe's result on a host:

```
openssl s_client -groups X25519MLKEM768 -tls1_3 -servername HOST -connect HOST:443
```

Agreement between the Go probe and OpenSSL on the negotiated group is the
two-independent-methods confidence check: two unrelated TLS stacks reading
the same ServerHello the same way.

## Provenance and signing

Today, anyone can verify a published dataset without trusting this project:
recompute the target list's SHA-256, rebuild the dataset from the raw
results and diff the bytes, and check that the manifest's SHA-256s bind the
raw file, the dataset, and the probe source together (see Reproducibility,
above).

Published datasets are additionally signed over the manifest bytes using
Sigstore keyless signing (Fulcio/Rekor), issued to the release workflow's
GitHub Actions OIDC identity. The exact verification command, constrained
to that identity, will be documented alongside the signing workflow when it
ships.

A valid signature proves that the named release workflow published exactly
these bytes. It does not prove that the probe actually contacted the hosts
in the dataset, and it does not prove the raw results were not fabricated
before signing. Signing binds provenance of the published artifact; it does
not substitute for independently re-running the scan.

## Ethics

Every measurement is a standard, public TLS handshake against a public
endpoint on its normal port. Non-public destination addresses (loopback,
private, CGNAT, link-local, multicast) are rejected before the probe ever
connects, so misconfigured targets cannot point it at internal
infrastructure. There is no authentication, no exploitation, and no
scanning beyond completing the handshake itself: a few spaced connections
per host, never sustained load.

This is a capability measurement in the style of SSL Labs or Cloudflare
Radar: it records what a server announces it can negotiate, publicly
attributes that to a hostname, and frames every positive result as a lower
bound rather than a certification.
