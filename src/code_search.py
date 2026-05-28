"""GitHub Code Search client — the fast path that doesn't clone.

When the user provides a PAT and picks scope=all_github (or any scope with a
specific pattern), we use GitHub's Code Search API to find files containing the
pattern, then fetch each file's raw content via the blob endpoint and extract
matches with our own regex.

Why no cloning:
  * Code Search returns files across all of GitHub in ~1s per query
  * Cloning 100 repos to maybe find one matching string is wasteful
  * Per-API-call charge is 20x cheaper than per-repo charge

Limitations to know:
  * Requires authenticated PAT (Code Search is auth-only)
  * Searches the default branch's CURRENT state only — no git history
  * 30 req/min rate limit (secondary)
  * Capped at 1000 results per query (10 pages × 100)
  * Star/pushed-date filters don't apply (those are repo-search qualifiers only)
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Iterator

import requests

GITHUB_API = "https://api.github.com"
log = logging.getLogger(__name__)


class CodeSearchError(Exception):
    pass


@dataclass
class CodeSearchHit:
    """One file match returned by Code Search."""
    repo_full_name: str    # "octocat/Hello-World"
    repo_url: str          # "https://github.com/octocat/Hello-World"
    path: str              # "config/anthropic.env"
    sha: str               # blob SHA (used to fetch raw content)
    html_url: str          # GitHub UI link for the file
    default_branch: str = "main"


_GH_PREFIX = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/")


def normalize_user(target: str) -> str:
    """Extract a username/org from various input formats."""
    target = target.strip().rstrip("/").lstrip("@")
    target = _GH_PREFIX.sub("", target)
    target = re.sub(r"^git@github\.com:", "", target)
    target = target.split("/", 1)[0]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9\-]*$", target):
        raise CodeSearchError(
            f"can't parse a GitHub username/org from {target!r}. "
            "Expected something like 'octocat' or 'github.com/octocat'."
        )
    return target


def normalize_repo(target: str) -> str:
    """Extract owner/name from a repo URL or owner/name string."""
    target = target.strip().rstrip("/")
    target = _GH_PREFIX.sub("", target)
    target = re.sub(r"^git@github\.com:", "", target)
    target = target.removesuffix(".git")
    parts = target.split("/")
    if len(parts) < 2:
        raise CodeSearchError(
            f"can't parse owner/name from {target!r}. "
            "Expected 'owner/name' or 'https://github.com/owner/name'."
        )
    owner, name = parts[0], parts[1]
    if not (re.match(r"^[A-Za-z0-9][A-Za-z0-9\-]*$", owner)
            and re.match(r"^[A-Za-z0-9][A-Za-z0-9._\-]*$", name)):
        raise CodeSearchError(f"invalid repo identifier: {owner}/{name}")
    return f"{owner}/{name}"


class CodeSearchClient:
    """GitHub Code Search API wrapper."""

    def __init__(self, pat: str):
        if not pat:
            raise ValueError("GitHub Code Search requires a Personal Access Token (PAT)")
        self.pat = pat
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gitleaks-cloud-actor/0.6",
        })

    @staticmethod
    def build_query(
        base_query: str,
        scope: str = "all_github",
        target: str | None = None,
        language: str | None = None,
    ) -> str:
        """Combine the base search expression with scope + filter qualifiers."""
        parts = [base_query.strip()]
        if scope == "user_or_org" and target:
            parts.append(f"user:{normalize_user(target)}")
        elif scope == "single_repo" and target:
            parts.append(f"repo:{normalize_repo(target)}")
        if language:
            parts.append(f"language:{language.strip().lower()}")
        return " ".join(p for p in parts if p)

    def search(self, query: str, max_results: int = 100) -> Iterator[CodeSearchHit]:
        """Yield up to max_results hits for the query.

        Implements pagination (100 per page, max 10 pages = 1000 results).
        Each page is one API call that counts against the 30 req/min limit.
        """
        per_page = min(100, max(1, max_results))
        page = 1
        returned = 0
        while returned < max_results and page <= 10:
            r = self._get_with_retry(
                f"{GITHUB_API}/search/code",
                {"q": query, "per_page": per_page, "page": page},
            )
            data = r.json()
            if data.get("incomplete_results"):
                log.warning("Code Search reported incomplete_results — query may be slow")
            items = data.get("items", [])
            if not items:
                return
            for item in items:
                repo = item.get("repository", {})
                yield CodeSearchHit(
                    repo_full_name=repo.get("full_name", ""),
                    repo_url=repo.get("html_url", ""),
                    path=item.get("path", ""),
                    sha=item.get("sha", ""),
                    html_url=item.get("html_url", ""),
                    default_branch=repo.get("default_branch", "main"),
                )
                returned += 1
                if returned >= max_results:
                    return
            if len(items) < per_page:
                return
            page += 1

    def fetch_blob(self, repo_full_name: str, sha: str, max_bytes: int = 1_000_000) -> str:
        """Fetch raw file content for one blob SHA.

        Returns the file text. Caps at max_bytes to bound memory; larger files
        are truncated (the start usually contains the relevant config).
        """
        url = f"{GITHUB_API}/repos/{repo_full_name}/git/blobs/{sha}"
        r = self.session.get(
            url,
            headers={"Accept": "application/vnd.github.raw"},
            timeout=30,
            stream=True,
        )
        if r.status_code == 200:
            content = r.raw.read(max_bytes + 1, decode_content=True)
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                text = ""
            if len(content) > max_bytes:
                log.info("truncated %s@%s at %d bytes", repo_full_name, sha[:8], max_bytes)
                text = text[:max_bytes]
            return text
        if r.status_code == 404:
            raise CodeSearchError(f"blob 404: {repo_full_name}@{sha[:8]}")
        if r.status_code in (401, 403):
            raise CodeSearchError(
                f"blob fetch refused ({r.status_code}). "
                "Either your PAT lacks 'repo' scope for this repo, or you hit the rate limit. "
                f"Body: {r.text[:200]}"
            )
        raise CodeSearchError(
            f"blob fetch returned {r.status_code}: {r.text[:200]}"
        )

    def _get_with_retry(self, url: str, params: dict, retries: int = 2):
        """GET with secondary-rate-limit awareness and actionable errors."""
        for attempt in range(retries + 1):
            r = self.session.get(url, params=params, timeout=30)
            if r.status_code == 200:
                return r

            body_lower = r.text.lower()

            if r.status_code == 401:
                raise CodeSearchError(
                    "GitHub rejected the PAT (401 Unauthorized). "
                    "Regenerate at https://github.com/settings/tokens. "
                    "For public-repo Code Search, no scopes needed; for private repos, grant 'repo' scope."
                )

            if r.status_code in (403, 429) and (
                "rate limit" in body_lower
                or "secondary rate" in body_lower
                or r.headers.get("X-RateLimit-Remaining") == "0"
            ):
                reset = r.headers.get("X-RateLimit-Reset")
                wait = max(0, int(reset) - int(time.time())) + 1 if reset else 30
                if wait <= 120 and attempt < retries:
                    log.warning("Code Search rate limit hit; sleeping %ds", wait)
                    time.sleep(wait)
                    continue
                raise CodeSearchError(
                    f"GitHub Code Search rate limit hit (30 req/min secondary limit). "
                    f"Wait {wait}s and retry, or lower max_results to reduce pagination."
                )

            if r.status_code == 422:
                raise CodeSearchError(
                    f"GitHub rejected the Code Search query (422). "
                    f"Likely cause: too many OR terms (max 5 boolean operators per query), or unsupported qualifier. "
                    f"Server said: {r.text[:200]}"
                )

            if r.status_code == 404:
                raise CodeSearchError(
                    f"Code Search endpoint returned 404. Check that the scoped target exists "
                    f"(user/org/repo). URL: {url}"
                )

            if r.status_code >= 500 and attempt < retries:
                time.sleep(2 ** attempt)
                continue

            raise CodeSearchError(
                f"Code Search returned {r.status_code}: {r.text[:300]}"
            )
        raise CodeSearchError("Code Search retries exhausted")
