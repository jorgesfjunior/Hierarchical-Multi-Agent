"""Phase 8 regression fixture (Fase 1 baseline guard): seeds 0-2 of the EXPLORATORY Phase 8 pilot.

The fixture is built from the RAW pilot outputs ``results/phase8_pilot/exp_p1..p5.csv`` (the exact
rows ``simulation/phase8_experiments.py pilot`` wrote on 2026-10-15, not a re-run of today's code).
Those CSVs are not version-controlled (``.gitignore``), so the rows of the units below are frozen in
``tests/fixtures/phase8_regression_s012.json``: per unit its row count, a SHA-256 over the canonical
rows, and the rows themselves when the unit is small (<= ``MAX_INLINE_ROWS``), so a failure shows
the diverging row. ``tests/test_fase1_phase8_regression.py`` re-runs each unit with the job
functions of ``simulation/phase8_experiments.py`` and requires an exact match.

Canonical row: every value as the CSV writer wrote it (``str(v)``; ``None`` -> ``""``), with empty
values dropped (the CSV header is the union over a whole experiment, so a row carries empty columns
it never had). Rows are sorted by their JSON text, so worker order (``imap_unordered``) is irrelevant.

Regenerate ONLY from the pilot CSVs, never from a fresh run (that would freeze whatever the code
does today):
    python3 tests/phase8_regression.py --write
Provenance (source CSV hashes, fixture hash, commits, command) is in
``tests/fixtures/phase8_regression_s012.meta.json``:
    python3 tests/phase8_regression.py --write-meta
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
from typing import Any, Callable, Iterable

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

FIXTURE_PATH = os.path.join(_BASE_DIR, "tests", "fixtures", "phase8_regression_s012.json")
PILOT_DIR = os.path.join(_BASE_DIR, "results", "phase8_pilot")
SEEDS = (0, 1, 2)
STATUS = "EXPLORATORY"
MAX_INLINE_ROWS = 100
P2_SCHEMA, P2_CONTROL = "domains_split_visibility", "domains_proactive_reactive"  # = phase8_experiments


def units() -> list[dict[str, Any]]:
    """(experiment, job args, CSV columns that select the unit's rows). Args are exactly the tuples
    ``phase8_experiments.pilot_jobs`` passes to the job functions."""
    out: list[dict[str, Any]] = []
    for s in SEEDS:
        for fam in ("campaign_multihost", "encryption_stream"):
            out.append({"exp": "p1", "args": [fam, s, STATUS], "select": {"family": fam, "seed": str(s)}})
        for schema in (P2_SCHEMA, P2_CONTROL):
            fam = "split_visibility_late_confirm"
            out.append({"exp": "p2", "args": [s, schema, fam, STATUS],
                        "select": {"schema": schema, "family": fam, "seed": str(s)}})
        for fam in ("split_visibility_late_confirm", "benign_patch_window"):
            out.append({"exp": "p3", "args": [fam, s, STATUS], "select": {"family": fam, "seed": str(s)}})
        for fam in ("encryption_stream", "split_visibility"):
            out.append({"exp": "p4", "args": [fam, s, "strict", STATUS],
                        "select": {"setting": "strict", "family": fam, "seed": str(s)}})
        for fam, d in (("campaign_multihost_late_confirm", 300.0), ("interleaved_late_confirm", 300.0),
                       ("campaign_multihost_late_confirm", 900.0)):
            out.append({"exp": "p5", "args": [fam, s, STATUS, d],
                        "select": {"family": fam, "seed": str(s), "outage_s": str(d)}})
    for u in out:
        u["id"] = u["exp"] + ":" + "/".join(str(a) for a in u["args"] if a != STATUS)
    return out


def canonical(rows: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    out = []
    for r in rows:
        row = {k: ("" if v is None else str(v)) for k, v in r.items()}
        out.append({k: v for k, v in sorted(row.items()) if v != ""})
    return sorted(out, key=lambda r: json.dumps(r, sort_keys=True))


def digest(rows: list[dict[str, str]]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode("utf-8")).hexdigest()


def job(exp: str) -> Callable[[tuple], list[dict[str, Any]]]:
    from simulation import phase8_experiments as p8

    return {"p1": p8.job_p1, "p2": p8.job_p2, "p3": p8.job_p3, "p4": p8.job_p4, "p5": p8.job_p5}[exp]


def _sha_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def build_from_pilot() -> dict[str, Any]:
    tables: dict[str, list[dict[str, str]]] = {}
    sources: dict[str, str] = {}
    entries = []
    for u in units():
        exp = u["exp"]
        if exp not in tables:
            path = os.path.join(PILOT_DIR, f"exp_{exp}.csv")
            with open(path, newline="", encoding="utf-8") as fh:
                tables[exp] = list(csv.DictReader(fh))
            sources[f"exp_{exp}.csv"] = _sha_file(path)
        rows = canonical(r for r in tables[exp] if all(r.get(k) == v for k, v in u["select"].items()))
        if not rows:
            raise SystemExit(f"no pilot rows for {u['id']}")
        entry = {"id": u["id"], "exp": exp, "args": u["args"], "n_rows": len(rows), "sha256": digest(rows)}
        if len(rows) <= MAX_INLINE_ROWS:
            entry["rows"] = rows
        entries.append(entry)
    return {"source": "results/phase8_pilot/exp_p*.csv (EXPLORATORY pilot, A3, 2026-10-15)",
            "source_sha256": sources, "seeds": list(SEEDS), "units": entries}


META_PATH = os.path.join(_BASE_DIR, "tests", "fixtures", "phase8_regression_s012.meta.json")
BUILD_COMMAND = "python3 tests/phase8_regression.py --write"


def _git(*args: str) -> str:
    import subprocess

    return subprocess.run(["git", *args], cwd=_BASE_DIR, check=True, capture_output=True, text=True).stdout.strip()


def build_meta() -> dict[str, Any]:
    """Provenance of the committed fixture: hashes of the (unversioned) source CSVs, of the fixture
    itself, the commits involved and the command. Requires the pilot CSVs and git."""
    import platform

    with open(FIXTURE_PATH, encoding="utf-8") as fh:
        fixture = json.load(fh)
    sources = {f"exp_{e}.csv": _sha_file(os.path.join(PILOT_DIR, f"exp_{e}.csv")) for e in ("p1", "p2", "p3", "p4", "p5")}
    if sources != fixture["source_sha256"]:
        raise SystemExit("the local pilot CSVs are not the ones the fixture was built from; not writing meta")
    rel = os.path.relpath(FIXTURE_PATH, _BASE_DIR)
    fixture_commit = _git("log", "-1", "--format=%H", "--", rel)
    return {
        "fixture": rel,
        "fixture_sha256": _sha_file(FIXTURE_PATH),
        "fixture_commit": fixture_commit,
        "code_commit_verified": _git("rev-parse", f"{fixture_commit}^"),
        "pilot_results_commit": _git("log", "-1", "--format=%H", "--", "results/phase8_pilot/REPORT.md"),
        "source_dir": os.path.relpath(PILOT_DIR, _BASE_DIR),
        "source_csvs_versioned": False,
        "source_csv_sha256": sources,
        "command": BUILD_COMMAND,
        "python": platform.python_version(),
        "seeds": fixture["seeds"],
        "units": len(fixture["units"]),
        "note": ("Fixture rows come from the raw Phase 8 pilot CSVs (A3, 2026-10-15), not from a re-run. "
                 "code_commit_verified = the code the fixture was checked to reproduce exactly when it was "
                 "committed (the parent of fixture_commit)."),
    }


if __name__ == "__main__":
    if "--write-meta" in sys.argv:
        with open(META_PATH, "w", encoding="utf-8") as fh:
            json.dump(build_meta(), fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(f"wrote {META_PATH}")
        sys.exit(0)
    fixture = build_from_pilot()
    if "--write" in sys.argv:
        os.makedirs(os.path.dirname(FIXTURE_PATH), exist_ok=True)
        with open(FIXTURE_PATH, "w", encoding="utf-8") as fh:
            json.dump(fixture, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(f"wrote {FIXTURE_PATH}: {len(fixture['units'])} units")
    else:
        print(json.dumps({u["id"]: u["n_rows"] for u in fixture["units"]}, indent=1))
