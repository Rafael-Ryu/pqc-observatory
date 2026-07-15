"""Pure functions that turn raw probe results into a classified, reproducible
dataset. No I/O, no network — so the verdict logic is testable in isolation and
the dataset re-derives byte-identically from the same raw results."""

from __future__ import annotations

from typing import Literal, TypedDict

# Hybrid post-quantum key exchange we offer and confirm. id 4588 == 0x11EC,
# RFC 9370 / draft-ietf-tls-hybrid-design final. This is the only group whose
# negotiation we treat as PQC support.
PQC_GROUP_ID = 4588
PQC_GROUP_NAME = "X25519MLKEM768"

METHODOLOGY_VERSION = "m0-2026-07"

Verdict = Literal["supported", "not_supported", "unknown"]


class ProbeResult(TypedDict, total=False):
    host: str
    group: str
    group_id: int
    tls_version: int
    error: str


class Entry(TypedDict):
    host: str
    verdict: Verdict
    group: str
    group_id: int
    detail: str


def classify(result: ProbeResult) -> Verdict:
    """Precision over recall: `supported` only when the server negotiated the
    PQC group in its ServerHello. Anything ambiguous is `unknown`, never a
    false positive."""
    if result.get("error"):
        return "unknown"
    group_id = result.get("group_id", 0)
    if group_id == PQC_GROUP_ID:
        return "supported"
    if group_id == 0:
        # Handshake produced no TLS 1.3 group (e.g. TLS 1.2-only server).
        return "unknown"
    return "not_supported"


def _detail(result: ProbeResult, verdict: Verdict) -> str:
    if verdict == "unknown":
        return result.get("error") or "no TLS 1.3 group negotiated"
    return f"negotiated {result.get('group') or result['group_id']}"


def build_dataset(
    results: list[ProbeResult],
    *,
    run_date: str,
    targets_sha256: str,
) -> dict[str, object]:
    """Deterministic: same raw results + same inputs → byte-identical JSON
    (callers dump with sort_keys=True). Entries are sorted by host."""
    entries: list[Entry] = [
        {
            "host": r["host"],
            "verdict": classify(r),
            "group": r.get("group", ""),
            "group_id": r.get("group_id", 0),
            "detail": _detail(r, classify(r)),
        }
        for r in sorted(results, key=lambda r: r["host"])
    ]
    counts = {v: 0 for v in ("supported", "not_supported", "unknown")}
    for e in entries:
        counts[e["verdict"]] += 1
    return {
        "methodology_version": METHODOLOGY_VERSION,
        "run_date": run_date,
        "pqc_group": {"name": PQC_GROUP_NAME, "id": PQC_GROUP_ID},
        "targets_sha256": targets_sha256,
        "total": len(entries),
        "counts": counts,
        "entries": entries,
    }
