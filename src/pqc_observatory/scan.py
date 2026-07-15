"""Build the Go probe, run it over a pinned target list, and write both the raw
handshake results and the derived dataset. The network/subprocess boundary
lives here; verdict logic lives in dataset.py."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from .dataset import SAMPLES_PER_HOST, ProbeResult, build_dataset

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PROBE_DIR = _REPO_ROOT / "probe"

# ponytail: hostnames only, no ports — the probe always uses 443; full IDN
# normalization is deferred (issue #7). Bounded length, labels 1-63 chars,
# no leading/trailing hyphen per label — rejects a leading `-` (which a Go
# flag parser would read as an option), an embedded `:port`, `/`, whitespace,
# and empty labels. Punycode (`xn--...`) still matches.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _probe_source_sha256() -> str:
    # Hashes the per-file digests in a fixed order so the pin is a stable
    # function of the two source files' exact committed bytes (LF, as the
    # repo stores them), independent of filesystem iteration order.
    h = hashlib.sha256()
    for name in ("probe.go", "go.mod"):
        h.update(hashlib.sha256((_PROBE_DIR / name).read_bytes()).digest())
    return h.hexdigest()


def verify_probe_source() -> str:
    """Compare the probe source against the committed pin before anything is
    built or run, so a tampered or unexpectedly changed probe aborts the scan
    instead of producing raw evidence from code nobody reviewed."""
    expected = (_PROBE_DIR / "source.sha256").read_text().strip()
    actual = _probe_source_sha256()
    if actual != expected:
        raise ValueError(
            f"probe source does not match probe/source.sha256: "
            f"expected {expected}, got {actual}. If probe.go/go.mod changed "
            f"legitimately, regenerate probe/source.sha256."
        )
    return actual


def build_probe(out: Path) -> Path:
    """Compile the Go probe. Integrity is anchored at the source, not the
    binary: `verify_probe_source` checks probe.go/go.mod against the committed
    pin before this runs, so a build here reflects reviewed source. A locally
    built binary's own hash is self-referential and is deliberately not pinned."""
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
        # "--" ends flag parsing so a host (even one load_targets somehow let
        # through with a leading "-") is always read as a positional arg, not
        # a Go flag — belt and suspenders with the load_targets validation.
        [str(binary), "-samples", str(SAMPLES_PER_HOST), "--", *hosts],
        capture_output=True,
        text=True,
        check=True,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def reconcile(hosts: list[str], results: list[ProbeResult]) -> list[ProbeResult]:
    """Guarantee exactly SAMPLES_PER_HOST results per requested host, one per
    sample_index. A missing (host, sample_index) slot (probe crashed mid-run,
    dropped a line) becomes an `unknown` sample instead of silently vanishing
    or crashing the whole run — a flaky sample must not cost the other N-1. An
    unexpected host, or a duplicate/out-of-range sample_index, is a broken
    contract and aborts the run."""
    requested = set(hosts)
    n = SAMPLES_PER_HOST
    by_key: dict[tuple[str, int], ProbeResult] = {}
    for r in results:
        h = r.get("host", "")
        if h not in requested:
            raise ValueError(f"probe returned an unrequested host: {h!r}")
        i = r.get("sample_index", -1)
        if not isinstance(i, int) or not (0 <= i < n):
            raise ValueError(
                f"probe returned an out-of-range sample_index for {h!r}: {i!r}"
            )
        if (h, i) in by_key:
            raise ValueError(f"probe returned a duplicate sample_index {i} for: {h!r}")
        by_key[h, i] = r
    for h in hosts:
        for i in range(n):
            by_key.setdefault(
                (h, i), {"host": h, "sample_index": i, "error": "no probe result"}
            )
    return [by_key[h, i] for h in hosts for i in range(n)]


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
    bad = sorted(h for h in hosts if not _HOSTNAME_RE.fullmatch(h))
    if bad:
        raise ValueError(f"invalid target hostnames: {bad}")
    seen: set[str] = set()
    dupes: set[str] = set()
    for h in hosts:
        if h in seen:
            dupes.add(h)
        seen.add(h)
    if dupes:
        raise ValueError(f"duplicate targets: {sorted(dupes)}")
    return hosts, sha


def _provenance() -> dict[str, str]:
    """Record what could silently change the measurement, so a poisoned run is
    detectable after the fact (notably GODEBUG=tlsmlkem=0, which removes ML-KEM
    from Go's key exchange set)."""
    go_version = subprocess.run(
        ["go", "version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    return {"go_version": go_version, "godebug": os.environ.get("GODEBUG", "")}


def _publish_atomic(artifacts: dict[Path, str]) -> None:
    """Stage every artifact to a sibling temp file, verify each was written
    intact, and only then swap all of them into place. A run that dies partway
    through must leave the previously published set untouched, not a raw file
    beside a stale dataset/manifest.

    ponytail: per-file os.replace is atomic, but publishing the set of three
    is still a tight loop, not one transaction — a crash between two replaces
    can still leave a torn set on disk. The manifest binds the three shas
    together so that's detectable after the fact, and a full set-atomic swap
    (writing to a fresh run-dir and renaming the directory) isn't worth the
    layout change for three small files."""
    tmp_paths: list[Path] = []
    try:
        for path, text in artifacts.items():
            data = text.encode("utf-8")
            want_sha = hashlib.sha256(data).hexdigest()
            # .tmp-{pid} makes collision between concurrent runs unlikely, but
            # O_EXCL|O_NOFOLLOW is what actually refuses a pre-existing file
            # or a symlink planted at that path — plain Path.open("wb") would
            # silently follow a symlink and clobber whatever it points at.
            tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
            tmp_paths.append(tmp)
            fd = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644
            )
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            got_sha = hashlib.sha256(tmp.read_bytes()).hexdigest()
            if got_sha != want_sha:
                raise OSError(f"short/torn write staging {path.name}: sha mismatch")
        for path in artifacts:
            tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
            os.replace(tmp, path)
            tmp_paths.remove(tmp)
    finally:
        for tmp in tmp_paths:
            tmp.unlink(missing_ok=True)


def scan(targets_path: Path, out_dir: Path, run_date: str) -> Path:
    # Validated before any path is built from it: out_dir / f"raw-{run_date}.jsonl"
    # would otherwise let a run_date like "../../x" escape out_dir.
    if not re.fullmatch(r"\d{4}-\d{2}", run_date):
        raise ValueError(f"run_date must be YYYY-MM: {run_date!r}")
    probe_source_sha = verify_probe_source()
    hosts, sha = load_targets(targets_path)
    binary = build_probe(_REPO_ROOT / "build" / "probe")
    results = reconcile(hosts, run_probe(binary, hosts))

    out_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(results, key=lambda r: (r["host"], r.get("sample_index", 0)))
    raw_text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in ordered)
    raw_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    dataset = build_dataset(results, hosts=hosts, run_date=run_date, targets_sha256=sha)
    dataset_text = json.dumps(dataset, indent=2, sort_keys=True) + "\n"
    dataset_sha = hashlib.sha256(dataset_text.encode("utf-8")).hexdigest()

    # Provenance and artifact hashes live in a sidecar, outside the byte-
    # identical reproducibility contract of the dataset itself.
    manifest = {
        "run_date": run_date,
        "dataset_sha256": dataset_sha,
        "raw_sha256": raw_sha,
        "targets_sha256": sha,
        "probe_source_sha256": probe_source_sha,
        **_provenance(),
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

    dataset_path = out_dir / f"pqc-adoption-{run_date}.json"
    _publish_atomic(
        {
            out_dir / f"raw-{run_date}.jsonl": raw_text,
            dataset_path: dataset_text,
            out_dir / f"manifest-{run_date}.json": manifest_text,
        }
    )
    return dataset_path
