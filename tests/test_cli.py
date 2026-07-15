from pathlib import Path

import pytest

from pqc_observatory import cli


def test_scan_command_invokes_scan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = {}

    def fake_scan(targets: Path, out: Path, run_date: str) -> Path:
        calls["args"] = (targets, out, run_date)
        return out / f"pqc-adoption-{run_date}.json"

    monkeypatch.setattr(cli, "scan", fake_scan)
    rc = cli.main(
        ["scan", "--targets", "t.txt", "--out", "d", "--date", "2026-07"]
    )
    assert rc == 0
    assert calls["args"] == (Path("t.txt"), Path("d"), "2026-07")
    assert "pqc-adoption-2026-07.json" in capsys.readouterr().out


def test_missing_command_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit):
        cli.main([])
