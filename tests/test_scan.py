import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from pqc_observatory import scan
from pqc_observatory.dataset import SAMPLES_PER_HOST, ProbeResult, build_dataset

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_load_targets_strips_comments_and_blanks(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("# comment\n\ncloudflare.com\n  github.com  \n")
    hosts, sha = scan.load_targets(f)
    assert hosts == ["cloudflare.com", "github.com"]
    assert len(sha) == 64


def test_load_targets_rejects_duplicates(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("a.example\nb.example\na.example\n")
    with pytest.raises(ValueError, match="duplicate targets"):
        scan.load_targets(f)


def test_load_targets_accepts_normal_hostnames_and_punycode(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("cloudflare.com\nxn--nxasmq6b.example\n")
    hosts, _ = scan.load_targets(f)
    assert hosts == ["cloudflare.com", "xn--nxasmq6b.example"]


def test_load_targets_rejects_leading_hyphen(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("-evil.example\n")
    with pytest.raises(ValueError, match="invalid target hostnames"):
        scan.load_targets(f)


def test_load_targets_rejects_port(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("host.example:8443\n")
    with pytest.raises(ValueError, match="invalid target hostnames"):
        scan.load_targets(f)


def test_load_targets_rejects_slash(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("host.example/path\n")
    with pytest.raises(ValueError, match="invalid target hostnames"):
        scan.load_targets(f)


def test_load_targets_rejects_over_length(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("a" * 254 + ".example\n")
    with pytest.raises(ValueError, match="invalid target hostnames"):
        scan.load_targets(f)


def _sample(host: str, i: int, **extra: object) -> ProbeResult:
    return cast("ProbeResult", {"host": host, "sample_index": i, **extra})


def test_reconcile_synthesizes_missing_slots_up_to_samples_per_host() -> None:
    # Host "a" is missing every sample but index 0; host "b" got none at all.
    out = scan.reconcile(["a", "b"], [_sample("a", 0, group_id=4588, tls_version=772)])
    assert len(out) == 2 * SAMPLES_PER_HOST
    assert [(r["host"], r["sample_index"]) for r in out] == [
        (h, i) for h in ("a", "b") for i in range(SAMPLES_PER_HOST)
    ]
    assert out[1] == {"host": "a", "sample_index": 1, "error": "no probe result"}
    assert out[SAMPLES_PER_HOST] == {
        "host": "b",
        "sample_index": 0,
        "error": "no probe result",
    }


def test_reconcile_rejects_unrequested_host() -> None:
    with pytest.raises(ValueError, match="unrequested"):
        scan.reconcile(["a"], [_sample("evil", 0)])


def test_reconcile_rejects_duplicate_sample_index() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        scan.reconcile(["a"], [_sample("a", 0), _sample("a", 0)])


def test_reconcile_rejects_out_of_range_sample_index() -> None:
    with pytest.raises(ValueError, match="out-of-range"):
        scan.reconcile(["a"], [_sample("a", SAMPLES_PER_HOST)])
    with pytest.raises(ValueError, match="out-of-range"):
        scan.reconcile(["a"], [_sample("a", -1)])


def test_run_probe_empty_hosts_skips_subprocess() -> None:
    assert scan.run_probe(Path("/nonexistent"), []) == []


def test_run_probe_parses_jsonl(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProc:
        stdout = (
            '{"host":"a","sample_index":0,"group_id":4588,"group":"X25519MLKEM768"}\n'
            "\n"
            '{"host":"b","sample_index":0,"group_id":29,"group":"X25519"}\n'
        )

    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> FakeProc:
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = scan.run_probe(Path("/probe"), ["a", "b"])
    assert [r["host"] for r in out] == ["a", "b"]
    # -samples must reflect the fixed methodology constant, not be hardcoded.
    # "--" must end flag parsing so a host is always read as positional, even
    # if one somehow reaches here with a leading "-".
    assert captured["cmd"] == [
        "/probe",
        "-samples",
        str(SAMPLES_PER_HOST),
        "--",
        "a",
        "b",
    ]


def test_probe_source_pin_matches_committed() -> None:
    # Drift guard: fails the moment probe.go/go.mod change without the pin
    # being regenerated, not just for one hand-picked tampering case.
    pin = (_REPO_ROOT / "probe" / "source.sha256").read_text().strip()
    assert scan._probe_source_sha256() == pin


def test_verify_probe_source_rejects_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan, "_probe_source_sha256", lambda: "deadbeef")
    with pytest.raises(ValueError, match="probe source does not match"):
        scan.verify_probe_source()


def test_scan_verifies_probe_before_building(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("a.example\n")

    def boom() -> str:
        raise ValueError("probe source does not match probe/source.sha256")

    def unreachable(*args: object, **kwargs: object) -> object:
        raise AssertionError("must not be called once source verification fails")

    monkeypatch.setattr(scan, "verify_probe_source", boom)
    monkeypatch.setattr(scan, "build_probe", unreachable)
    monkeypatch.setattr(scan, "run_probe", unreachable)

    with pytest.raises(ValueError, match="probe source does not match"):
        scan.scan(targets, tmp_path / "data", run_date="2026-07")


@pytest.mark.parametrize("bad_date", ["2026-07-01/../x", "../../etc"])
def test_scan_rejects_path_traversal_run_date(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_date: str
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("a.example\n")

    def unreachable(*args: object, **kwargs: object) -> object:
        raise AssertionError("must not run once run_date validation fails")

    monkeypatch.setattr(scan, "verify_probe_source", unreachable)

    out_dir = tmp_path / "data"
    with pytest.raises(ValueError, match="run_date must be YYYY-MM"):
        scan.scan(targets, out_dir, run_date=bad_date)
    assert not out_dir.exists() or not list(out_dir.iterdir())


def test_scan_writes_raw_and_dataset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("b.example\na.example\n")

    monkeypatch.setattr(scan, "build_probe", lambda out: out)
    fake_results = [
        _sample("b.example", i, group_id=29, group="X25519", tls_version=772)
        for i in range(SAMPLES_PER_HOST)
    ] + [
        _sample("a.example", i, group_id=4588, group="X25519MLKEM768", tls_version=772)
        for i in range(SAMPLES_PER_HOST)
    ]
    monkeypatch.setattr(scan, "run_probe", lambda binary, hosts: fake_results)
    monkeypatch.setattr(scan, "_provenance", lambda: {"go_version": "t", "godebug": ""})
    monkeypatch.setattr(scan, "verify_probe_source", lambda: "fixed-source-sha")

    out_dir = tmp_path / "data"
    dataset_path = scan.scan(targets, out_dir, run_date="2026-07")

    data = json.loads(dataset_path.read_text())
    assert data["counts"] == {"supported": 1, "not_observed": 1, "unknown": 0}
    assert [e["host"] for e in data["entries"]] == ["a.example", "b.example"]
    assert data["samples_per_host"] == SAMPLES_PER_HOST
    assert "provenance" not in data  # provenance lives in the sidecar, not here

    raw_lines = [
        json.loads(line)
        for line in (out_dir / "raw-2026-07.jsonl").read_text().splitlines()
    ]
    assert [(r["host"], r["sample_index"]) for r in raw_lines] == [
        (h, i) for h in ("a.example", "b.example") for i in range(SAMPLES_PER_HOST)
    ]

    manifest = json.loads((out_dir / "manifest-2026-07.json").read_text())
    assert manifest["go_version"] == "t"
    assert manifest["probe_source_sha256"] == "fixed-source-sha"
    assert manifest["dataset_sha256"] == hashlib.sha256(
        dataset_path.read_bytes()
    ).hexdigest()


def _monkeypatch_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shared fake probe pipeline so publish tests exercise scan()'s write
    tail without a real Go build or network handshake."""
    fake_results = [
        _sample("b.example", i, group_id=29, group="X25519", tls_version=772)
        for i in range(SAMPLES_PER_HOST)
    ] + [
        _sample("a.example", i, group_id=4588, group="X25519MLKEM768", tls_version=772)
        for i in range(SAMPLES_PER_HOST)
    ]
    monkeypatch.setattr(scan, "build_probe", lambda out: out)
    monkeypatch.setattr(scan, "run_probe", lambda binary, hosts: fake_results)
    monkeypatch.setattr(scan, "_provenance", lambda: {"go_version": "t", "godebug": ""})
    monkeypatch.setattr(scan, "verify_probe_source", lambda: "fixed-source-sha")


def test_publish_is_atomic_on_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("b.example\na.example\n")
    _monkeypatch_probe(monkeypatch)

    out_dir = tmp_path / "data"
    out_dir.mkdir()
    raw_path = out_dir / "raw-2026-07.jsonl"
    dataset_path = out_dir / "pqc-adoption-2026-07.json"
    manifest_path = out_dir / "manifest-2026-07.json"
    raw_path.write_text("old-raw\n")
    dataset_path.write_text("old-dataset\n")
    manifest_path.write_text("old-manifest\n")

    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated failure mid-publish")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(OSError, match="simulated failure"):
        scan.scan(targets, out_dir, run_date="2026-07")

    # The file whose replace never ran, or ran after the failure, must be
    # left exactly as published before this run — a torn set is detectable
    # (per the manifest shas) but never silently corrupted.
    assert dataset_path.read_text() == "old-dataset\n"
    assert manifest_path.read_text() == "old-manifest\n"
    assert not list(out_dir.glob("*.tmp-*"))


def test_publish_detects_short_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("b.example\na.example\n")
    _monkeypatch_probe(monkeypatch)

    out_dir = tmp_path / "data"
    out_dir.mkdir()
    raw_path = out_dir / "raw-2026-07.jsonl"
    dataset_path = out_dir / "pqc-adoption-2026-07.json"
    manifest_path = out_dir / "manifest-2026-07.json"
    raw_path.write_text("old-raw\n")
    dataset_path.write_text("old-dataset\n")
    manifest_path.write_text("old-manifest\n")

    real_read_bytes = Path.read_bytes

    def corrupting_read_bytes(self: Path) -> bytes:
        data = real_read_bytes(self)
        # Only tamper with the staged temp files, so load_targets() upstream
        # still reads the real target list untouched.
        return data + b"corrupt" if ".tmp-" in self.name else data

    monkeypatch.setattr(Path, "read_bytes", corrupting_read_bytes)

    def forbidden_replace(
        src: str | os.PathLike[str], dst: str | os.PathLike[str]
    ) -> None:
        raise AssertionError("os.replace must not run once a temp write is torn")

    monkeypatch.setattr(os, "replace", forbidden_replace)

    with pytest.raises(OSError, match="sha mismatch"):
        scan.scan(targets, out_dir, run_date="2026-07")

    assert raw_path.read_text() == "old-raw\n"
    assert dataset_path.read_text() == "old-dataset\n"
    assert manifest_path.read_text() == "old-manifest\n"
    assert not list(out_dir.glob("*.tmp-*"))


def test_publish_atomic_refuses_preexisting_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(os, "getpid", lambda: 4242)

    target = tmp_path / "out.json"
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("do not touch\n")
    tmp = tmp_path / "out.json.tmp-4242"
    tmp.symlink_to(sentinel)

    with pytest.raises(OSError):
        scan._publish_atomic({target: "new-data\n"})

    assert sentinel.read_text() == "do not touch\n"
    assert not target.exists()


def test_committed_dataset_rederives_from_raw() -> None:
    """Gate: the published dataset must re-derive byte-identically from its raw
    results and the pinned target file alone — no environment input — so a
    hand-edited or stale dataset fails CI and third-party reproduction holds.
    The target hash is recomputed from the file, not trusted from the dataset."""
    data_dir = _REPO_ROOT / "data"
    dataset_path = next(data_dir.glob("pqc-adoption-*.json"))
    dataset = json.loads(dataset_path.read_text())
    run_date = dataset["run_date"]

    raw_path = data_dir / f"raw-{run_date}.jsonl"
    raw = [
        json.loads(line)
        for line in raw_path.read_text().splitlines()
        if line.strip()
    ]
    targets_file = _REPO_ROOT / "targets" / f"{run_date}.txt"
    hosts, targets_sha = scan.load_targets(targets_file)
    assert targets_sha == dataset["targets_sha256"]

    rebuilt = build_dataset(
        raw, hosts=hosts, run_date=run_date, targets_sha256=targets_sha
    )
    expected = json.dumps(dataset, indent=2, sort_keys=True) + "\n"
    actual = json.dumps(rebuilt, indent=2, sort_keys=True) + "\n"
    assert actual == expected
