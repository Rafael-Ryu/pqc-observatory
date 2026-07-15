import json
import subprocess
from pathlib import Path

import pytest

from pqc_observatory import scan
from pqc_observatory.dataset import build_dataset

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


def test_reconcile_synthesizes_unknown_for_missing_host() -> None:
    out = scan.reconcile(
        ["a", "b"], [{"host": "a", "group_id": 4588, "tls_version": 772}]
    )
    assert [r["host"] for r in out] == ["a", "b"]
    assert out[1] == {"host": "b", "error": "no probe result"}


def test_reconcile_rejects_unrequested_and_duplicate_hosts() -> None:
    with pytest.raises(ValueError, match="unrequested"):
        scan.reconcile(["a"], [{"host": "evil"}])
    with pytest.raises(ValueError, match="duplicate"):
        scan.reconcile(["a"], [{"host": "a"}, {"host": "a"}])


def test_run_probe_empty_hosts_skips_subprocess() -> None:
    assert scan.run_probe(Path("/nonexistent"), []) == []


def test_run_probe_parses_jsonl(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProc:
        stdout = (
            '{"host":"a","group_id":4588,"group":"X25519MLKEM768"}\n'
            "\n"
            '{"host":"b","group_id":29,"group":"X25519"}\n'
        )

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    out = scan.run_probe(Path("/probe"), ["a", "b"])
    assert [r["host"] for r in out] == ["a", "b"]


def test_scan_writes_raw_and_dataset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("b.example\na.example\n")

    monkeypatch.setattr(scan, "build_probe", lambda out: out)
    fake_results = [
        {"host": "b.example", "group_id": 29, "group": "X25519", "tls_version": 772},
        {
            "host": "a.example",
            "group_id": 4588,
            "group": "X25519MLKEM768",
            "tls_version": 772,
        },
    ]
    monkeypatch.setattr(scan, "run_probe", lambda binary, hosts: fake_results)
    monkeypatch.setattr(
        scan, "_provenance", lambda binary: {"go_version": "t", "godebug": ""}
    )

    out_dir = tmp_path / "data"
    dataset_path = scan.scan(targets, out_dir, run_date="2026-07")

    data = json.loads(dataset_path.read_text())
    assert data["counts"] == {"supported": 1, "not_observed": 1, "unknown": 0}
    assert [e["host"] for e in data["entries"]] == ["a.example", "b.example"]
    raw_lines = (out_dir / "raw-2026-07.jsonl").read_text().splitlines()
    assert json.loads(raw_lines[0])["host"] == "a.example"


def test_committed_dataset_rederives_from_raw() -> None:
    """Gate: the published dataset must re-derive byte-identically from its raw
    results, so a hand-edited or stale dataset fails CI."""
    data_dir = _REPO_ROOT / "data"
    dataset_path = next(data_dir.glob("pqc-adoption-*.json"))
    dataset = json.loads(dataset_path.read_text())
    raw_path = data_dir / f"raw-{dataset['run_date']}.jsonl"
    raw = [
        json.loads(line)
        for line in raw_path.read_text().splitlines()
        if line.strip()
    ]

    rebuilt = build_dataset(
        raw,
        run_date=dataset["run_date"],
        targets_sha256=dataset["targets_sha256"],
        provenance=dataset["provenance"],
    )
    expected = json.dumps(dataset, indent=2, sort_keys=True) + "\n"
    actual = json.dumps(rebuilt, indent=2, sort_keys=True) + "\n"
    assert actual == expected
