import json
import subprocess
from pathlib import Path

import pytest

from pqc_observatory import scan


def test_load_targets_strips_comments_and_blanks(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("# comment\n\ncloudflare.com\n  github.com  \n")
    hosts, sha = scan.load_targets(f)
    assert hosts == ["cloudflare.com", "github.com"]
    assert len(sha) == 64  # sha256 hex


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
    assert out[0]["group_id"] == 4588


def test_scan_writes_raw_and_dataset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("b.example\na.example\n")

    monkeypatch.setattr(scan, "build_probe", lambda out: out)
    monkeypatch.setattr(
        scan,
        "run_probe",
        lambda binary, hosts: [
            {"host": "b.example", "group_id": 29, "group": "X25519"},
            {"host": "a.example", "group_id": 4588, "group": "X25519MLKEM768"},
        ],
    )

    out_dir = tmp_path / "data"
    dataset_path = scan.scan(targets, out_dir, run_date="2026-07")

    assert dataset_path == out_dir / "pqc-adoption-2026-07.json"
    data = json.loads(dataset_path.read_text())
    assert data["counts"] == {"supported": 1, "not_supported": 1, "unknown": 0}
    assert [e["host"] for e in data["entries"]] == ["a.example", "b.example"]

    raw_lines = (out_dir / "raw-2026-07.jsonl").read_text().splitlines()
    assert json.loads(raw_lines[0])["host"] == "a.example"  # sorted
