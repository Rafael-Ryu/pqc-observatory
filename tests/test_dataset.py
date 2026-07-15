from pqc_observatory.dataset import (
    PQC_GROUP_ID,
    TLS13_VERSION,
    ProbeResult,
    build_dataset,
    classify,
)

_PROV = {"go_version": "go version test", "godebug": ""}


def _supported(host: str = "a") -> ProbeResult:
    return {
        "host": host,
        "group_id": PQC_GROUP_ID,
        "group": "X25519MLKEM768",
        "tls_version": TLS13_VERSION,
    }


def _classical(host: str = "a") -> ProbeResult:
    return {
        "host": host,
        "group_id": 29,
        "group": "X25519",
        "tls_version": TLS13_VERSION,
    }


def test_supported_requires_pqc_group_over_tls13() -> None:
    assert classify(_supported()) == "supported"


def test_pqc_group_without_tls13_is_unknown() -> None:
    # An impossible record: PQC group id but not a TLS 1.3 handshake.
    bad: ProbeResult = {"host": "a", "group_id": PQC_GROUP_ID, "tls_version": 771}
    assert classify(bad) == "unknown"


def test_non_int_group_id_is_unknown() -> None:
    # A corrupted 4588.0 must not equal the int group id and pass.
    bad: ProbeResult = {"host": "a", "tls_version": TLS13_VERSION}
    bad["group_id"] = 4588.0  # type: ignore[typeddict-item]
    assert classify(bad) == "unknown"


def test_classical_group_is_not_observed() -> None:
    assert classify(_classical()) == "not_observed"


def test_error_is_unknown_never_false_positive() -> None:
    assert classify({"host": "a", "error": "handshake failure"}) == "unknown"
    stale: ProbeResult = {"host": "a", "group_id": PQC_GROUP_ID, "error": "timeout"}
    assert classify(stale) == "unknown"


def test_no_group_is_unknown() -> None:
    assert classify({"host": "a", "group_id": 0}) == "unknown"


def test_dataset_is_deterministic_and_sorted() -> None:
    results: list[ProbeResult] = [
        _classical("b.example"),
        _supported("a.example"),
        {"host": "c.example", "error": "timeout"},
    ]
    d1 = build_dataset(
        results, run_date="2026-07", targets_sha256="x", provenance=_PROV
    )
    d2 = build_dataset(
        list(reversed(results)),
        run_date="2026-07",
        targets_sha256="x",
        provenance=_PROV,
    )
    assert d1 == d2
    entries = d1["entries"]
    assert isinstance(entries, list)
    assert [e["host"] for e in entries] == ["a.example", "b.example", "c.example"]
    assert d1["counts"] == {"supported": 1, "not_observed": 1, "unknown": 1}
    assert d1["total"] == 3
