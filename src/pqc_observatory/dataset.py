"""Pure functions that turn raw probe results into a classified, reproducible
dataset. No I/O, no network — so the verdict logic is testable in isolation and
the dataset re-derives byte-identically from the same raw results."""

from __future__ import annotations

from typing import Literal, TypedDict

# Hybrid post-quantum key exchange we enable and confirm. id 4588 == 0x11EC,
# defined by draft-kwiatkowski-tls-ecdhe-mlkem and registered in the IANA TLS
# Supported Groups registry. This is the only group whose negotiation we treat
# as PQC support.
PQC_GROUP_ID = 4588
PQC_GROUP_NAME = "X25519MLKEM768"

# A supported verdict requires a completed TLS 1.3 handshake (0x0304); anything
# else is not a valid observation of the group being negotiated.
TLS13_VERSION = 0x0304

METHODOLOGY_VERSION = "m2-2026-07"

# Fixed methodology, not a tunable: N independent samples per host, aggregated
# with unanimity (see aggregate()). Documented in METHODOLOGY.md.
SAMPLES_PER_HOST = 5

# not_observed, not "not_supported": the server negotiated a classical group,
# which proves PQC was not selected, not that the server is incapable of it (Go
# ignores our offered order, and a server may simply prefer classical).
Verdict = Literal["supported", "not_observed", "unknown"]


class ProbeResult(TypedDict, total=False):
    host: str
    sample_index: int
    group: str
    group_id: int
    tls_version: int
    peer_ip: str
    error: str


class Entry(TypedDict):
    host: str
    verdict: Verdict
    samples: int
    distribution: dict[str, int]  # per-sample verdict counts
    distinct_peer_ips: int
    flags: list[str]
    detail: str


def classify(result: ProbeResult) -> Verdict:
    """Precision over recall: `supported` only when the server negotiated the
    PQC group over a completed TLS 1.3 handshake. Anything ambiguous or
    internally inconsistent is `unknown`, never a false positive."""
    if result.get("error"):
        return "unknown"
    group_id = result.get("group_id", 0)
    # bool is an int subclass but never a valid group id; reject anything that
    # is not a plain int so a corrupted record (e.g. 4588.0) cannot pass.
    if not isinstance(group_id, int) or isinstance(group_id, bool):
        return "unknown"
    if group_id == PQC_GROUP_ID:
        # An internally inconsistent record (PQC group id without a TLS 1.3
        # handshake, or with a mismatched group name) means the probe output
        # cannot be trusted for this host. Same type guard as group_id above:
        # 772.0 == TLS13_VERSION in Python, so a corrupted float must not pass.
        tv = result.get("tls_version")
        if not isinstance(tv, int) or isinstance(tv, bool) or tv != TLS13_VERSION:
            return "unknown"
        if result.get("group") != PQC_GROUP_NAME:
            return "unknown"
        return "supported"
    if group_id == 0:
        # Handshake produced no TLS 1.3 group (e.g. TLS 1.2-only server).
        return "unknown"
    return "not_observed"


def aggregate(host: str, samples: list[ProbeResult]) -> Entry:
    """Reduce N independent samples of one host to a single verdict by
    unanimity: a lone dissenting sample (a load balancer with one non-PQC
    backend, a transient timeout) must not be swallowed into a majority vote,
    since that would be exactly the kind of inference-from-partial-evidence
    precision forbids. peer_ip count is recorded, never used to gate the
    verdict — anycast/DNS round-robin makes it a weak, noisy edge proxy."""
    n = SAMPLES_PER_HOST
    indices = [s.get("sample_index") for s in samples]
    if len(samples) != n or set(indices) != set(range(n)):
        raise ValueError(
            f"host {host!r}: expected {n} samples with indices 0..{n - 1}, "
            f"got {sorted(i for i in indices if isinstance(i, int))}"
        )

    verdicts = [classify(s) for s in samples]
    distribution = {v: 0 for v in ("supported", "not_observed", "unknown")}
    for v in verdicts:
        distribution[v] += 1

    if distribution["supported"] == n:
        verdict: Verdict = "supported"
    elif distribution["not_observed"] == n:
        verdict = "not_observed"
    else:
        verdict = "unknown"

    peer_ips = {s["peer_ip"] for s in samples if s.get("peer_ip")}
    distinct_peer_ips = len(peer_ips)
    divergent = distribution["supported"] > 0 and distribution["not_observed"] > 0

    flags = []
    if distinct_peer_ips <= 1:
        flags.append("single_vantage")
    if divergent:
        flags.append("divergent")
    flags.sort()

    if verdict == "supported":
        detail = (
            f"unanimous {PQC_GROUP_NAME} across {n} samples, "
            f"{distinct_peer_ips} peer ip(s)"
        )
    elif verdict == "not_observed":
        detail = f"unanimous classical across {n} samples"
    elif divergent:
        detail = (
            f"divergent: {distribution['supported']} supported / "
            f"{distribution['not_observed']} not_observed"
        )
    else:
        detail = next(
            (s["error"] for s in samples if s.get("error")), "incomplete agreement"
        )

    return {
        "host": host,
        "verdict": verdict,
        "samples": n,
        "distribution": distribution,
        "distinct_peer_ips": distinct_peer_ips,
        "flags": flags,
        "detail": detail,
    }


def build_dataset(
    results: list[ProbeResult],
    *,
    hosts: list[str],
    run_date: str,
    targets_sha256: str,
) -> dict[str, object]:
    """The canonical dataset is a deterministic projection of the raw results
    and stable methodology inputs only: same raw + same inputs → byte-identical
    JSON (callers dump with sort_keys=True), independent of who or what machine
    re-derives it. Environment provenance is recorded separately, not here, so
    it cannot break third-party reproduction. Entries are sorted by host, each
    host's samples sorted by sample_index before aggregation.

    `hosts` anchors the expected host set to the pinned target list, not to
    whatever hosts happen to appear in `results` — a raw file with an entire
    host's samples deleted must fail loudly instead of re-deriving a smaller,
    byte-identical dataset that silently passes reproduction."""
    by_host: dict[str, list[ProbeResult]] = {}
    for r in results:
        by_host.setdefault(r["host"], []).append(r)

    missing = sorted(set(hosts) - by_host.keys())
    unexpected = sorted(by_host.keys() - set(hosts))
    if missing or unexpected:
        raise ValueError(
            f"raw results host set does not match pinned targets: "
            f"missing={missing} unexpected={unexpected}"
        )

    entries: list[Entry] = [
        aggregate(host, sorted(by_host[host], key=lambda s: s.get("sample_index", 0)))
        for host in sorted(by_host)
    ]
    counts = {v: 0 for v in ("supported", "not_observed", "unknown")}
    for e in entries:
        counts[e["verdict"]] += 1
    return {
        "methodology_version": METHODOLOGY_VERSION,
        "run_date": run_date,
        "pqc_group": {"name": PQC_GROUP_NAME, "id": PQC_GROUP_ID},
        "targets_sha256": targets_sha256,
        "samples_per_host": SAMPLES_PER_HOST,
        "total": len(entries),
        "counts": counts,
        "entries": entries,
    }
