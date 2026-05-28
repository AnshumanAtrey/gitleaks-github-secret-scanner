"""Scanner: clone a repo with full git capabilities, run gitleaks, return findings.

This module exposes the underlying `git` + `gitleaks` capabilities through a
ScanOptions dataclass instead of hardcoding a single shallow clone-and-scan
strategy. The defaults give a deeper scan than v0.11 (all branches + PR refs
fetched), while opt-in flags unlock dangling-commit scanning, submodule
recursion, and git-log-level filters (date, author, message, pickaxe).
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

CLONE_TIMEOUT = 180     # seconds — per-repo clone budget (raised for --no-single-branch)
FETCH_PR_TIMEOUT = 120  # seconds — PR refs fetch budget
SCAN_TIMEOUT = 300      # seconds — per-repo scan budget
DANGLING_TIMEOUT = 180  # seconds — fsck + cat-file budget


# ────────────────────────────────────────────────────────────────────────────
# ScanOptions — every knob exposed to callers (and through to INPUT_SCHEMA)
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class ScanOptions:
    """All advanced git / gitleaks options exposed to the user."""
    # Clone-time options
    include_all_branches: bool = True       # --no-single-branch
    include_submodules: bool = False        # --recurse-submodules
    include_pr_refs: bool = True            # fetch refs/pull/*/head after clone
    include_dangling_objects: bool = False  # git fsck --dangling + scan each

    # gitleaks --log-opts pass-through (filters which commits are scanned)
    commit_since: str | None = None         # --since=YYYY-MM-DD
    commit_until: str | None = None         # --until=YYYY-MM-DD
    commit_author: str | None = None        # --author=PATTERN
    commit_message_grep: str | None = None  # --grep=PATTERN
    commit_introduced_string: str | None = None  # -S=STRING (pickaxe)

    # File-level limit
    max_file_size_mb: int = 100             # --max-target-megabytes


# ────────────────────────────────────────────────────────────────────────────
# Errors + Finding dataclass
# ────────────────────────────────────────────────────────────────────────────


class ScannerError(Exception):
    pass


@dataclass
class Finding:
    rule_id: str
    secret: str
    file: str
    start_line: int
    commit: str
    match: str
    is_test_key: bool
    author_name: str
    author_email: str
    commit_date: str
    branch_ref: str = ""        # NEW in v0.12 — which ref the leak lives on
    is_dangling: bool = False   # NEW in v0.12 — true if from `git fsck --dangling`

    @classmethod
    def from_gitleaks(cls, d: dict) -> "Finding":
        rid = d.get("RuleID", "")
        return cls(
            rule_id=rid,
            secret=d.get("Secret", ""),
            file=d.get("File", ""),
            start_line=int(d.get("StartLine", 0)),
            commit=d.get("Commit", ""),
            match=d.get("Match", ""),
            is_test_key=":testkey:" in rid,
            author_name=d.get("Author", ""),
            author_email=d.get("Email", ""),
            commit_date=d.get("Date", ""),
        )


# ────────────────────────────────────────────────────────────────────────────
# Clone + fetch
# ────────────────────────────────────────────────────────────────────────────


def clone(clone_url: str, dest: Path, opts: ScanOptions) -> None:
    """git clone with optional --no-single-branch and --recurse-submodules.

    Raises ScannerError on failure.
    """
    cmd = ["git", "clone", "--quiet"]
    if opts.include_all_branches:
        cmd.append("--no-single-branch")
    if opts.include_submodules:
        cmd.append("--recurse-submodules")
    cmd.extend([clone_url, str(dest)])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"clone timeout ({CLONE_TIMEOUT}s) for {clone_url}")
    if proc.returncode != 0:
        raise ScannerError(
            f"clone failed for {clone_url}: {proc.stderr.strip()[:300]}"
        )


def fetch_pr_refs(repo_path: Path) -> bool:
    """Fetch refs/pull/*/head into refs/remotes/origin/pull/*.

    Returns True on success, False on failure (we don't fail the scan).
    PR refs catch secrets that were committed to a PR and then squash-merged
    away — the PR head ref still holds them on GitHub.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_path), "fetch", "--quiet", "origin",
             "+refs/pull/*/head:refs/remotes/origin/pull/*"],
            capture_output=True, text=True, timeout=FETCH_PR_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning("PR refs fetch timeout for %s", repo_path)
        return False
    if proc.returncode != 0:
        # Often fails on repos with no PRs — not an error
        log.debug("PR refs fetch returned %d for %s", proc.returncode, repo_path)
        return False
    return True


# ────────────────────────────────────────────────────────────────────────────
# gitleaks invocation
# ────────────────────────────────────────────────────────────────────────────


def _build_log_opts(opts: ScanOptions) -> str:
    """Translate ScanOptions filter fields into a `git log` args string."""
    parts = ["--all"]  # always scan all refs (which now includes PR refs)
    if opts.commit_since:
        parts.append(f"--since={opts.commit_since}")
    if opts.commit_until:
        parts.append(f"--until={opts.commit_until}")
    if opts.commit_author:
        parts.append(f"--author={opts.commit_author}")
    if opts.commit_message_grep:
        parts.append(f"--grep={opts.commit_message_grep}")
    if opts.commit_introduced_string:
        # gitleaks passes log-opts as one string; quoting the -S value protects spaces
        parts.append(f"-S{opts.commit_introduced_string}")
    return " ".join(parts)


def run_gitleaks(repo_path: Path, config_path: Path, opts: ScanOptions) -> list[Finding]:
    """Run gitleaks against the cloned repo with the supplied options.

    The --log-opts pass-through is the killer feature here — date / author /
    message / pickaxe filters are honored without us needing to parse anything.
    """
    report = repo_path.parent / f"{repo_path.name}-leaks.json"
    log_opts_str = _build_log_opts(opts)
    cmd = [
        "gitleaks", "git", str(repo_path),
        "--config", str(config_path),
        "--report-format", "json",
        "--report-path", str(report),
        "--no-banner",
        "--exit-code", "0",
        f"--max-target-megabytes={opts.max_file_size_mb}",
        f"--log-opts={log_opts_str}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"gitleaks timeout ({SCAN_TIMEOUT}s) for {repo_path}")
    if proc.returncode not in (0, 1):
        raise ScannerError(
            f"gitleaks error (exit {proc.returncode}): {proc.stderr.strip()[:300]}"
        )
    if not report.exists():
        return []
    try:
        raw = json.loads(report.read_text() or "[]")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"gitleaks emitted invalid JSON: {exc}")
    finally:
        report.unlink(missing_ok=True)
    return [Finding.from_gitleaks(d) for d in raw]


# ────────────────────────────────────────────────────────────────────────────
# Dangling commit scan (opt-in)
# ────────────────────────────────────────────────────────────────────────────


def find_dangling_commits(repo_path: Path) -> list[str]:
    """List commits unreachable from any ref. These are the 'rebased-away' ones."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_path), "fsck", "--dangling", "--no-progress"],
            capture_output=True, text=True, timeout=DANGLING_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return []
    return [
        ln.split()[-1]
        for ln in proc.stdout.splitlines()
        if ln.startswith("dangling commit")
    ]


def scan_dangling_commits(
    repo_path: Path, config_path: Path, danglings: list[str]
) -> list[Finding]:
    """For each dangling commit SHA, `git show` it and pipe through `gitleaks stdin`."""
    findings: list[Finding] = []
    for sha in danglings:
        try:
            diff = subprocess.run(
                ["git", "-C", str(repo_path), "show", sha],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except subprocess.TimeoutExpired:
            continue
        if not diff:
            continue
        try:
            proc = subprocess.run(
                ["gitleaks", "stdin",
                 "--config", str(config_path),
                 "--report-format", "json",
                 "--no-banner",
                 "--exit-code", "0"],
                input=diff, capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            continue
        # gitleaks stdin emits JSON to stdout
        try:
            raw = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            continue
        for d in raw:
            f = Finding.from_gitleaks(d)
            f.commit = sha
            f.is_dangling = True
            f.branch_ref = "dangling"
            findings.append(f)
    return findings


# ────────────────────────────────────────────────────────────────────────────
# End-to-end scan
# ────────────────────────────────────────────────────────────────────────────


def scan_repo(
    clone_url: str,
    config_path: Path,
    *,
    opts: ScanOptions | None = None,
    work_root: Path | None = None,
) -> list[Finding]:
    """Clone → fetch PR refs → gitleaks history → (optional) dangling → cleanup."""
    opts = opts or ScanOptions()
    work_root = work_root or Path(tempfile.mkdtemp(prefix="repo-audit-"))
    work_root.mkdir(parents=True, exist_ok=True)
    safe_name = clone_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in safe_name)
    clone_path = work_root / safe_name

    try:
        clone(clone_url, clone_path, opts)
        if opts.include_pr_refs:
            fetch_pr_refs(clone_path)

        findings = run_gitleaks(clone_path, config_path, opts)

        # Tag findings with branch_ref (best-effort — gitleaks doesn't expose
        # which ref a commit was reached from; we infer from `git for-each-ref`
        # later in main.py if needed). Default: "history" for normal findings.
        for f in findings:
            if not f.branch_ref:
                f.branch_ref = "history"

        if opts.include_dangling_objects:
            danglings = find_dangling_commits(clone_path)
            if danglings:
                log.info("  found %d dangling commits, scanning…", len(danglings))
                findings.extend(scan_dangling_commits(clone_path, config_path, danglings))

        return findings
    finally:
        shutil.rmtree(clone_path, ignore_errors=True)


def write_config(gitleaks_toml: str) -> Path:
    """Persist a generated gitleaks TOML to a temp file. Returns the path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
    f.write(gitleaks_toml)
    f.flush()
    f.close()
    return Path(f.name)
