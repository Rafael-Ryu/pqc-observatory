from pqc_observatory.dataset import (
    PQC_GROUP_ID,
    ProbeResult,
    build_dataset,
    classify,
)


def test_supported_only_on_pqc_group() -> None:
    r: ProbeResult = {"host": "a", "group_id": PQC_GROUP_ID, "group": "X25519MLKEM768"}
    assert classify(r) == "supported"


def test_classical_group_is_not_supported() -> None:
    assert classify({"host": "a", "group_id": 29, "group": "X25519"}) == "not_supported"


def test_error_is_unknown_never_false_positive() -> None:
    assert classify({"host": "a", "error": "handshake failure"}) == "unknown"
    # An error must win even if a stale group_id is present.
    stale: ProbeResult = {"host": "a", "group_id": PQC_GROUP_ID, "error": "timeout"}
    assert classify(stale) == "unknown"


def test_no_group_is_unknown() -> None:
    assert classify({"host": "a", "group_id": 0}) == "unknown"


def test_dataset_is_deterministic_and_sorted() -> None:
    results: list[ProbeResult] = [
        {"host": "b.example", "group_id": 29, "group": "X25519"},
        {"host": "a.example", "group_id": PQC_GROUP_ID, "group": "X25519MLKEM768"},
        {"host": "c.example", "error": "timeout"},
    ]
    d1 = build_dataset(results, run_date="2026-07", targets_sha256="deadbeef")
    d2 = build_dataset(
        list(reversed(results)), run_date="2026-07", targets_sha256="deadbeef"
    )
    assert d1 == d2
    entries = d1["entries"]
    assert isinstance(entries, list)
    assert [e["host"] for e in entries] == ["a.example", "b.example", "c.example"]
    assert d1["counts"] == {"supported": 1, "not_supported": 1, "unknown": 1}
    assert d1["total"] == 3
