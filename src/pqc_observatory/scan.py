"""Build the Go probe, run it over a pinned target list, and write both the raw
handshake results and the derived dataset. The network/subprocess boundary
lives here; verdict logic lives in dataset.py."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from .dataset import ProbeResult, build_dataset

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PROBE_DIR = _REPO_ROOT / "probe"


def build_probe(out: Path) -> Path:
    """Compile the Go probe. ponytail: build-then-run for now; SHA-256 pinning
    of a released binary (per the pqcheck pattern) lands with the first signed
    dataset, not the M0 spike."""
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=_PROBE_DIR,
        check=True,
    )
    return out


def run_probe(binary: Path, hosts: list[str]) -> list[ProbeResult]:
    if not hosts:
        return []
    proc = subprocess.run(
        [str(binary), *hosts],
        capture_output=True,
        text=True,
        check=True,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def load_targets(path: Path) -> tuple[list[str], str]:
    """Return (hosts, sha256-of-file). Blank lines and `#` comments ignored for
    the host list; the hash covers the raw file bytes so the exact pinned list
    is recorded in the dataset."""
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    hosts = [
        line.strip()
        for line in raw.decode().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return hosts, sha


def scan(targets_path: Path, out_dir: Path, run_date: str) -> Path:
    hosts, sha = load_targets(targets_path)
    binary = build_probe(_REPO_ROOT / "build" / "probe")
    results = run_probe(binary, hosts)

    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / f"raw-{run_date}.jsonl"
    raw_path.write_text(
        "".join(
            json.dumps(r, sort_keys=True) + "\n"
            for r in sorted(results, key=lambda r: r["host"])
        )
    )

    dataset = build_dataset(results, run_date=run_date, targets_sha256=sha)
    dataset_path = out_dir / f"pqc-adoption-{run_date}.json"
    dataset_path.write_text(json.dumps(dataset, indent=2, sort_keys=True) + "\n")
    return dataset_path
