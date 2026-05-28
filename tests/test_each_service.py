"""Parametrized per-service tests.

For each of the 30 services:
  1. Build a fresh git repo from the fixture files
  2. Generate the gitleaks config from registry
  3. Run gitleaks
  4. Assert expected_secrets all detected
  5. Assert expected_negatives NOT detected
  6. Assert pairing engine produces expected_pairs
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pairing import pair  # noqa: E402
from src.registry import load_all  # noqa: E402
from src.scanner import ScanOptions, run_gitleaks, write_config  # noqa: E402
from tests.fixtures import FIXTURES, Fixture  # noqa: E402


def _build_fixture_repo(fixture: Fixture, tmp: Path) -> Path:
    """Materialize a fixture as a git repo with one commit."""
    repo = tmp / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "T"], check=True)
    for rel_path, content in fixture.files.items():
        file_path = repo / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "fixture commit"],
        check=True, env={**os.environ, "GIT_AUTHOR_DATE": "2026-01-01T00:00:00", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00"},
    )
    return repo


def _run_one(service_id: str, fixture: Fixture) -> tuple[bool, list[str]]:
    """Return (passed, errors)."""
    errors: list[str] = []
    services = load_all()
    if service_id not in services:
        return False, [f"unknown service id: {service_id}"]
    service = services[service_id]

    tmp = Path(tempfile.mkdtemp(prefix=f"fixt-{service_id}-"))
    try:
        repo_path = _build_fixture_repo(fixture, tmp)
        cfg_path = write_config(service.to_gitleaks_toml(include_test_keys=True))
        try:
            findings = run_gitleaks(repo_path, cfg_path, ScanOptions())
        finally:
            cfg_path.unlink(missing_ok=True)

        secret_values = {f.secret for f in findings}

        # 1. All expected_secrets must be in findings
        for needle in fixture.expected_secrets:
            if needle not in secret_values:
                errors.append(f"  MISSED expected: {needle[:50]!r}")

        # 2. No expected_negatives in findings
        for fp in fixture.expected_negatives:
            if fp in secret_values:
                errors.append(f"  FALSE POSITIVE: {fp[:50]!r}")

        # 3. Expected pairs produced by pairing engine
        records = pair(findings, service)
        actual_pairs: set[tuple[str, str]] = set()
        for r in records:
            if r.paired and r.paired_with:
                actual_pairs.add((r.paired_with["value"], r.secret_value))
        for expected in fixture.expected_pairs:
            if expected not in actual_pairs and (expected[1], expected[0]) not in actual_pairs:
                errors.append(f"  MISSED pair: id={expected[0][:30]!r}  secret={expected[1][:30]!r}")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return (not errors), errors


def main() -> int:
    services = sorted(FIXTURES.keys())
    print(f"Running {len(services)} per-service fixture tests")
    print("=" * 70)
    passes = 0
    fails = 0
    failures: dict[str, list[str]] = {}
    for sid in services:
        ok, errs = _run_one(sid, FIXTURES[sid])
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {sid}")
        if ok:
            passes += 1
        else:
            fails += 1
            failures[sid] = errs
    print("=" * 70)
    print(f"Results: {passes} passed, {fails} failed")
    if failures:
        print()
        for sid, errs in failures.items():
            print(f"--- {sid} ---")
            for e in errs:
                print(e)
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
