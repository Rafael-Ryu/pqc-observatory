"""Build the Go probe, run it over a pinned target list, and write both the raw
handshake results and the derived dataset. The network/subprocess boundary
lives here; verdict logic lives in dataset.py."""

from __future__ import annotations

import hashlib
import json
import os
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


def reconcile(hosts: list[str], results: list[ProbeResult]) -> list[ProbeResult]:
    """Guarantee exactly one result per requested host. A host with no result
    (probe crashed on it, emitted a short run, or was a wrong binary) becomes
    `unknown` instead of silently vanishing; an unexpected or duplicate result
    host is a broken contract and aborts the run."""
    requested = set(hosts)
    by_host: dict[str, ProbeResult] = {}
    for r in results:
        h = r.get("host", "")
        if h not in requested:
            raise ValueError(f"probe returned an unrequested host: {h!r}")
        if h in by_host:
            raise ValueError(f"probe returned a duplicate result for: {h!r}")
        by_host[h] = r
    for h in hosts:
        by_host.setdefault(h, {"host": h, "error": "no probe result"})
    return [by_host[h] for h in hosts]


def load_targets(path: Path) -> tuple[list[str], str]:
    """Return (hosts, sha256-of-file). Blank lines and `#` comments ignored for
    the host list; the hash covers the raw file bytes so the exact pinned list
    is recorded in the dataset. Duplicate hosts are rejected so results stay
    one-per-host and the dataset is deterministic."""
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    hosts = [
        line.strip()
        for line in raw.decode("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    dupes = sorted({h for h in hosts if hosts.count(h) > 1})
    if dupes:
        raise ValueError(f"duplicate targets: {dupes}")
    return hosts, sha


def _provenance() -> dict[str, str]:
    """Record what could silently change the measurement, so a poisoned run is
    detectable after the fact (notably GODEBUG=tlsmlkem=0, which removes ML-KEM
    from Go's key exchange set)."""
    go_version = subprocess.run(
        ["go", "version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    return {"go_version": go_version, "godebug": os.environ.get("GODEBUG", "")}


def _write(path: Path, text: str) -> str:
    """Write UTF-8 text with LF newlines and return its sha256."""
    data = text.encode("utf-8")
    with path.open("wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def scan(targets_path: Path, out_dir: Path, run_date: str) -> Path:
    hosts, sha = load_targets(targets_path)
    binary = build_probe(_REPO_ROOT / "build" / "probe")
    results = reconcile(hosts, run_probe(binary, hosts))

    out_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(results, key=lambda r: r["host"])
    raw_sha = _write(
        out_dir / f"raw-{run_date}.jsonl",
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in ordered),
    )

    dataset = build_dataset(results, run_date=run_date, targets_sha256=sha)
    dataset_path = out_dir / f"pqc-adoption-{run_date}.json"
    dataset_sha = _write(
        dataset_path, json.dumps(dataset, indent=2, sort_keys=True) + "\n"
    )

    # Provenance and artifact hashes live in a sidecar, outside the byte-
    # identical reproducibility contract of the dataset itself.
    manifest = {
        "run_date": run_date,
        "dataset_sha256": dataset_sha,
        "raw_sha256": raw_sha,
        "targets_sha256": sha,
        **_provenance(),
    }
    _write(
        out_dir / f"manifest-{run_date}.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )
    return dataset_path
