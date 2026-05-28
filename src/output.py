"""Build the final dataset record shape from PairedRecord + repo context."""
from __future__ import annotations

from src.lister import Repo
from src.pairing import PairedRecord


def _normalize_ext(ext: str) -> str:
    """Normalize an extension: ensure leading dot, lowercase. '.PY' -> '.py'."""
    ext = ext.strip().lower()
    if not ext.startswith("."):
        ext = "." + ext
    return ext


def matches_extension_filter(file_path: str, allowlist: list[str] | None) -> bool:
    """Return True if file_path passes the include_extensions filter.

    If allowlist is empty/None, everything passes. Otherwise, the file's path
    must end with one of the listed extensions (case-insensitive).
    Also matches the bare filename for entries without a leading dot (e.g.
    'Dockerfile', 'Makefile') — useful for extensionless config files.
    """
    if not allowlist:
        return True
    fp_lower = file_path.lower()
    fname_lower = fp_lower.rsplit("/", 1)[-1]
    for raw in allowlist:
        ext = _normalize_ext(raw)
        if fp_lower.endswith(ext):
            return True
        # Also handle bare-filename entries like 'Dockerfile' (passed as '.dockerfile' after normalize)
        if fname_lower == raw.strip().lower():
            return True
    return False


def to_record(record: PairedRecord, repo: Repo, platform: str) -> dict:
    """Flatten a PairedRecord into the per-finding output schema."""
    repo_url = repo.clone_url.removesuffix(".git")
    permalink = (
        f"{repo_url}/blob/{record.commit}/{record.file}#L{record.line}"
        if record.commit else f"{repo_url}/blob/HEAD/{record.file}#L{record.line}"
    )
    return {
        "repo_url": repo_url,
        "file": record.file,
        "line": record.line,
        "permalink": permalink,
        "secret_name": record.secret_name,
        "secret_value": record.secret_value,
        "paired": "yes" if record.paired else "no",
        "paired_with": record.paired_with,
        "platform": platform,
        "rule_id": record.secret_name,
        "commit_sha": record.commit,
        "is_test_key": record.is_test_key,
        "author_name": record.author_name,
        "author_email": record.author_email,
        "commit_date": record.commit_date,
        "scan_method": "clone",
    }
