import json
from collections.abc import Callable
from typing import cast

import pytest

from pqc_observatory.dataset import (
    PQC_GROUP_ID,
    SAMPLES_PER_HOST,
    TLS13_VERSION,
    ProbeResult,
    aggregate,
    build_dataset,
    classify,
)


def _supported(host: str = "a", peer_ip: str = "1.1.1.1") -> ProbeResult:
    return {
        "host": host,
        "group_id": PQC_GROUP_ID,
        "group": "X25519MLKEM768",
        "tls_version": TLS13_VERSION,
        "peer_ip": peer_ip,
    }


def _classical(host: str = "a", peer_ip: str = "1.1.1.1") -> ProbeResult:
    return {
        "host": host,
        "group_id": 29,
        "group": "X25519",
        "tls_version": TLS13_VERSION,
        "peer_ip": peer_ip,
    }


def _samples(*results: ProbeResult) -> list[ProbeResult]:
    """Attach sample_index 0..N-1 in argument order, as the probe would."""
    out: list[ProbeResult] = []
    for i, r in enumerate(results):
        s: ProbeResult = dict(r)  # type: ignore[assignment]
        s["sample_index"] = i
        out.append(s)
    return out


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


def test_non_int_tls_version_is_unknown() -> None:
    # A corrupted 772.0 must not equal the int TLS13_VERSION and pass.
    bad: ProbeResult = {
        "host": "a",
        "group_id": PQC_GROUP_ID,
        "group": "X25519MLKEM768",
    }
    bad["tls_version"] = 772.0  # type: ignore[typeddict-item]
    assert classify(bad) == "unknown"


def test_bool_tls_version_is_unknown() -> None:
    for tv in (True, False):
        bad: ProbeResult = {
            "host": "a",
            "group_id": PQC_GROUP_ID,
            "group": "X25519MLKEM768",
        }
        bad["tls_version"] = tv
        assert classify(bad) == "unknown"


def test_inconsistent_group_name_and_id_is_unknown() -> None:
    bad: ProbeResult = {
        "host": "a",
        "group_id": PQC_GROUP_ID,
        "group": "X25519",
        "tls_version": TLS13_VERSION,
    }
    assert classify(bad) == "unknown"


def test_classical_group_is_not_observed() -> None:
    assert classify(_classical()) == "not_observed"


def test_error_is_unknown_never_false_positive() -> None:
    assert classify({"host": "a", "error": "handshake failure"}) == "unknown"
    stale: ProbeResult = {"host": "a", "group_id": PQC_GROUP_ID, "error": "timeout"}
    assert classify(stale) == "unknown"


def test_no_group_is_unknown() -> None:
    assert classify({"host": "a", "group_id": 0}) == "unknown"


def test_classical_group_without_tls13_is_unknown() -> None:
    # A corrupted classical record: not_observed must also require a
    # completed TLS 1.3 handshake, not just a nonzero non-PQC group id.
    bad: ProbeResult = {
        "host": "a",
        "group_id": 29,
        "group": "X25519",
        "tls_version": 0,
    }
    assert classify(bad) == "unknown"


def test_classical_group_wrong_tls_version_is_unknown() -> None:
    bad: ProbeResult = {
        "host": "a",
        "group_id": 29,
        "group": "X25519",
        "tls_version": 771,
    }
    assert classify(bad) == "unknown"


def test_pqc_group_name_with_classical_id_is_unknown() -> None:
    # Group name carries PQC meaning but the id disagrees: internally
    # inconsistent, must not be reported as not_observed.
    bad: ProbeResult = {
        "host": "a",
        "group_id": 29,
        "group": "X25519MLKEM768",
        "tls_version": TLS13_VERSION,
    }
    assert classify(bad) == "unknown"


def _unanimous(
    host: str, make: Callable[[str, str], ProbeResult], peer_ip: str = "1.1.1.1"
) -> list[ProbeResult]:
    return _samples(*[make(host, peer_ip) for _ in range(SAMPLES_PER_HOST)])


def test_dataset_is_deterministic_and_sorted() -> None:
    results: list[ProbeResult] = [
        *_unanimous("b.example", _classical),
        *_unanimous("a.example", _supported),
        *_samples(
            *[
                cast("ProbeResult", {"host": "c.example", "error": "timeout"})
                for _ in range(5)
            ]
        ),
    ]
    hosts = ["a.example", "b.example", "c.example"]
    d1 = build_dataset(results, hosts=hosts, run_date="2026-07", targets_sha256="x")
    d2 = build_dataset(
        list(reversed(results)), hosts=hosts, run_date="2026-07", targets_sha256="x"
    )
    assert d1 == d2
    entries = d1["entries"]
    assert isinstance(entries, list)
    assert [e["host"] for e in entries] == ["a.example", "b.example", "c.example"]
    assert d1["counts"] == {"supported": 1, "not_observed": 1, "unknown": 1}
    assert d1["total"] == 3
    assert d1["samples_per_host"] == SAMPLES_PER_HOST


def test_aggregate_unanimous_supported_with_multiple_peer_ips() -> None:
    samples = _samples(
        *[_supported("a", peer_ip=f"1.1.1.{i}") for i in range(SAMPLES_PER_HOST)]
    )
    entry = aggregate("a", samples)
    assert entry["verdict"] == "supported"
    assert entry["distinct_peer_ips"] == SAMPLES_PER_HOST
    assert "single_vantage" not in entry["flags"]
    assert "divergent" not in entry["flags"]


def test_aggregate_unanimous_supported_single_vantage_still_supported() -> None:
    # Anycast/CDN legitimately answers from one IP for every sample. The
    # verdict must not be demoted — single_vantage is descriptive, not gating.
    samples = _samples(*[_supported("a") for _ in range(SAMPLES_PER_HOST)])
    entry = aggregate("a", samples)
    assert entry["verdict"] == "supported"
    assert entry["distinct_peer_ips"] == 1
    assert entry["flags"] == ["single_vantage"]


def test_aggregate_zero_peers_no_single_vantage_flag() -> None:
    # Every handshake failed (e.g. microsoft.com timing out): distinct_peer_ips
    # is 0, not 1, and single_vantage would misleadingly imply a peer was
    # actually reached. The verdict alone (unknown) already conveys the
    # total failure.
    samples = _samples(
        *[
            cast("ProbeResult", {"host": "a", "error": "timeout"})
            for _ in range(SAMPLES_PER_HOST)
        ]
    )
    entry = aggregate("a", samples)
    assert entry["distinct_peer_ips"] == 0
    assert "single_vantage" not in entry["flags"]


def test_aggregate_divergent_mix_is_unknown() -> None:
    samples = _samples(
        _supported("a"),
        _supported("a"),
        _supported("a"),
        _supported("a"),
        _classical("a"),
    )
    entry = aggregate("a", samples)
    assert entry["verdict"] == "unknown"
    assert "divergent" in entry["flags"]
    assert entry["distribution"] == {"supported": 4, "not_observed": 1, "unknown": 0}
    assert "divergent" in entry["detail"]


def test_aggregate_mostly_supported_with_error_is_unknown_not_divergent() -> None:
    samples = _samples(
        _supported("a"),
        _supported("a"),
        _supported("a"),
        _supported("a"),
        {"host": "a", "error": "timeout"},
    )
    entry = aggregate("a", samples)
    assert entry["verdict"] == "unknown"
    assert "divergent" not in entry["flags"]
    assert entry["detail"] == "timeout"


def test_aggregate_unanimous_not_observed() -> None:
    samples = _samples(*[_classical("a") for _ in range(SAMPLES_PER_HOST)])
    entry = aggregate("a", samples)
    assert entry["verdict"] == "not_observed"


def test_aggregate_and_build_dataset_agree_regardless_of_sample_order() -> None:
    samples = _samples(
        _supported("a"),
        _classical("a"),
        _supported("a"),
        _supported("a"),
        _supported("a"),
    )
    d1 = build_dataset(samples, hosts=["a"], run_date="2026-07", targets_sha256="x")
    d2 = build_dataset(
        list(reversed(samples)), hosts=["a"], run_date="2026-07", targets_sha256="x"
    )
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)


def test_aggregate_rejects_wrong_sample_count() -> None:
    samples = _samples(*[_supported("a") for _ in range(SAMPLES_PER_HOST - 1)])
    with pytest.raises(ValueError, match="expected 5 samples"):
        aggregate("a", samples)


def test_aggregate_rejects_duplicate_sample_index() -> None:
    samples = _samples(*[_supported("a") for _ in range(SAMPLES_PER_HOST)])
    samples[-1] = cast("ProbeResult", dict(samples[0]))
    with pytest.raises(ValueError, match="expected 5 samples"):
        aggregate("a", samples)


def test_build_dataset_rejects_missing_host() -> None:
    # A raw file with an entire host's samples deleted must not silently
    # re-derive a smaller, byte-identical dataset — it must fail loudly.
    results = _unanimous("a.example", _supported)
    with pytest.raises(ValueError, match=r"missing=\['b\.example'\]"):
        build_dataset(
            results,
            hosts=["a.example", "b.example"],
            run_date="2026-07",
            targets_sha256="x",
        )


def test_build_dataset_rejects_unexpected_host() -> None:
    # A host in the raw results but absent from the pinned target list is a
    # broken contract, not a valid dataset input.
    results = [
        *_unanimous("a.example", _supported),
        *_unanimous("evil.example", _classical),
    ]
    with pytest.raises(ValueError, match=r"unexpected=\['evil\.example'\]"):
        build_dataset(
            results,
            hosts=["a.example"],
            run_date="2026-07",
            targets_sha256="x",
        )
