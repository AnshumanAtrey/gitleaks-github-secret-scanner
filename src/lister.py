"""GitHub repo lister — produces the list of clone URLs to scan.

Three scopes (named to match the user-facing INPUT_SCHEMA):
  * all_github   — search public repos by keyword (sort=updated), capped at max_repos
  * user_or_org  — list a user's/org's public repos
  * single_repo  — return [the URL] as-is

Uses unauth GitHub API by default (10 req/min, public-only). With a PAT:
30 req/min, can include private repos owned by the token holder.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Iterable

import requests

GITHUB_API = "https://api.github.com"
log = logging.getLogger(__name__)


class ListerError(Exception):
    pass


@dataclass
class Repo:
    full_name: str       # "owner/name"
    clone_url: str       # "https://github.com/owner/name.git"
    size_kb: int         # GitHub-reported repo size (KB)
    pushed_at: str       # ISO timestamp


def _headers(pat: str | None) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "repo-credential-audit/0.1",
    }
    if pat:
        h["Authorization"] = f"Bearer {pat}"
    return h


def _get(url: str, params: dict, pat: str | None, *, retries: int = 2) -> dict:
    """GET with retry, rate-limit awareness, and actionable error messages."""
    for attempt in range(retries + 1):
        r = requests.get(url, params=params, headers=_headers(pat), timeout=30)
        if r.status_code == 200:
            return r.json()

        body = r.text.lower()

        # Auth failures — distinct from rate limits
        if r.status_code == 401 or (r.status_code == 403 and "bad credentials" in body):
            if pat:
                raise ListerError(
                    "GitHub rejected the provided Personal Access Token (bad credentials). "
                    "Generate a new one at https://github.com/settings/tokens and paste it into the 'github_pat' field. "
                    "For public-repo scanning, no scopes are needed; for private repos, grant 'repo' scope."
                )
            raise ListerError(
                "GitHub authentication failed even though no PAT was provided — this should not happen. Try again."
            )

        # Rate limit — give different messages for auth vs unauth
        if r.status_code in (403, 429) and ("rate limit" in body or "abuse" in body or r.headers.get("X-RateLimit-Remaining") == "0"):
            reset = r.headers.get("X-RateLimit-Reset")
            wait = 0
            if reset:
                wait = max(0, int(reset) - int(time.time())) + 1

            if pat:
                # User HAS a PAT and still hit limit — rare, just wait or back off
                if wait and wait <= 120:
                    log.warning("rate limit hit with PAT; sleeping %ds before retry", wait)
                    time.sleep(wait)
                    continue
                raise ListerError(
                    f"GitHub rate limit hit even with PAT (30 req/min). Resets in {wait}s. "
                    "Wait, then retry. If this happens repeatedly, your PAT may have low quota on its account."
                )
            else:
                # No PAT — push the user to add one, this is the common case
                raise ListerError(
                    "GitHub rate limit hit (10 req/min unauthenticated, shared across Apify's IP pool). "
                    "Add a GitHub Personal Access Token in the 'github_pat' field to raise the limit to 30 req/min "
                    "and use YOUR quota instead of the shared pool. "
                    "Generate one at https://github.com/settings/tokens (no scopes needed for public repos). "
                    "The token is marked isSecret — it never leaves this run."
                )

        # Validation errors (bad query, bad date format, etc.)
        if r.status_code == 422:
            raise ListerError(
                f"GitHub rejected the search query (422). Check date format (must be YYYY-MM-DD) and that "
                f"'pushed_after' is not later than 'pushed_before'. Server said: {r.text[:200]}"
            )

        if r.status_code == 404:
            raise ListerError(
                f"GitHub returned 404 for {url.split('?')[0]}. "
                "If scope=user_or_org, check the username/org exists. "
                "If scope=single_repo, check the URL is correct and the repo is public (or grant your PAT access)."
            )

        # Server errors — retry with backoff
        if r.status_code >= 500 and attempt < retries:
            time.sleep(2 ** attempt)
            continue

        raise ListerError(
            f"GitHub API returned {r.status_code} for {url.split('?')[0]}. Response: {r.text[:300]}"
        )
    raise ListerError("retries exhausted")


def _build_pushed_qualifier(pushed_after: str | None, pushed_before: str | None) -> str:
    """Build the ' pushed:...' qualifier for the search query, or '' if no dates given."""
    if pushed_after and pushed_before:
        return f" pushed:{pushed_after}..{pushed_before}"
    if pushed_after:
        return f" pushed:>{pushed_after}"
    if pushed_before:
        return f" pushed:<{pushed_before}"
    return ""


def _build_extra_qualifiers(
    language: str | None,
    min_stars: int | None,
    max_stars: int | None,
) -> str:
    """Build extra GitHub search qualifiers: language, stars range."""
    parts = []
    if language:
        parts.append(f"language:{language.strip().lower()}")
    if min_stars is not None and max_stars is not None:
        parts.append(f"stars:{min_stars}..{max_stars}")
    elif min_stars is not None:
        parts.append(f"stars:>={min_stars}")
    elif max_stars is not None:
        parts.append(f"stars:<={max_stars}")
    return (" " + " ".join(parts)) if parts else ""


def _matches_date_range(
    pushed_at: str, pushed_after: str | None, pushed_before: str | None
) -> bool:
    """Check if a repo's pushed_at (ISO timestamp) falls in the requested range."""
    if not pushed_at:
        return True  # don't filter out repos with missing data
    # Compare ISO date prefix (YYYY-MM-DD) lexicographically — same as numeric compare.
    date_str = pushed_at[:10]
    if pushed_after and date_str < pushed_after:
        return False
    if pushed_before and date_str > pushed_before:
        return False
    return True


def _parse_repo_url(url: str) -> tuple[str, str]:
    """Extract (owner, name) from a github URL. Accepts:
    https://github.com/owner/name
    https://github.com/owner/name.git
    git@github.com:owner/name.git
    """
    m = re.match(r"(?:https?://github\.com/|git@github\.com:)([^/]+)/([^/.]+?)(?:\.git)?/?$", url.strip())
    if not m:
        raise ListerError(f"can't parse GitHub repo URL: {url!r}")
    return m.group(1), m.group(2)


def list_global(
    keyword: str,
    max_repos: int,
    pat: str | None,
    pushed_after: str | None = None,
    pushed_before: str | None = None,
    language: str | None = None,
    min_stars: int | None = None,
    max_stars: int | None = None,
) -> list[Repo]:
    """Search public repos mentioning the keyword. Sort by recently-updated.

    Optional pushed_after / pushed_before constrain the pushed_at window.
    Optional language, min_stars, max_stars further refine via GitHub qualifiers.

    We paginate up to max_repos. GitHub returns 100 per page max.
    Repos > 500MB are skipped to keep scan time bounded.
    """
    query = (
        keyword
        + _build_pushed_qualifier(pushed_after, pushed_before)
        + _build_extra_qualifiers(language, min_stars, max_stars)
    )
    repos: list[Repo] = []
    page = 1
    per_page = min(100, max_repos)
    while len(repos) < max_repos:
        data = _get(
            f"{GITHUB_API}/search/repositories",
            {"q": query, "sort": "updated", "order": "desc", "per_page": per_page, "page": page},
            pat,
        )
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            if item.get("size", 0) > 500_000:  # >500MB
                continue
            repos.append(Repo(
                full_name=item["full_name"],
                clone_url=item["clone_url"],
                size_kb=item.get("size", 0),
                pushed_at=item.get("pushed_at", ""),
            ))
            if len(repos) >= max_repos:
                break
        page += 1
        if page > 10:  # GitHub search caps at 1000 results (10 pages × 100)
            break
    return repos


def list_user(
    username: str,
    max_repos: int,
    pat: str | None,
    pushed_after: str | None = None,
    pushed_before: str | None = None,
    language: str | None = None,
    min_stars: int | None = None,
    max_stars: int | None = None,
) -> list[Repo]:
    """List a user's or org's public repos, sorted by recently-pushed.

    The /users/{u}/repos and /orgs/{u}/repos endpoints don't support GitHub
    search qualifiers, so all filters (date, language, stars) are applied
    post-fetch. We may walk more pages to fill max_repos with matching results.
    """
    repos: list[Repo] = []
    page = 1
    per_page = 100
    base = f"{GITHUB_API}/users/{username}/repos"
    try:
        _get(base, {"per_page": 1}, pat)
    except ListerError:
        base = f"{GITHUB_API}/orgs/{username}/repos"

    lang_lower = language.strip().lower() if language else None

    while len(repos) < max_repos:
        items = _get(base, {"sort": "pushed", "per_page": per_page, "page": page}, pat)
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if item.get("size", 0) > 500_000:
                continue
            if not _matches_date_range(item.get("pushed_at", ""), pushed_after, pushed_before):
                continue
            if lang_lower and (item.get("language") or "").lower() != lang_lower:
                continue
            stars = item.get("stargazers_count", 0)
            if min_stars is not None and stars < min_stars:
                continue
            if max_stars is not None and stars > max_stars:
                continue
            repos.append(Repo(
                full_name=item["full_name"],
                clone_url=item["clone_url"],
                size_kb=item.get("size", 0),
                pushed_at=item.get("pushed_at", ""),
            ))
            if len(repos) >= max_repos:
                break
        page += 1
        if page > 10:
            break
    return repos


def list_single(repo_url: str, pat: str | None) -> list[Repo]:
    """Validate the URL and return one Repo entry."""
    owner, name = _parse_repo_url(repo_url)
    item = _get(f"{GITHUB_API}/repos/{owner}/{name}", {}, pat)
    return [Repo(
        full_name=item["full_name"],
        clone_url=item["clone_url"],
        size_kb=item.get("size", 0),
        pushed_at=item.get("pushed_at", ""),
    )]


def list_repos(
    *,
    scope: str,
    target: str | None,
    keyword: str,
    max_repos: int,
    pat: str | None,
    pushed_after: str | None = None,
    pushed_before: str | None = None,
    language: str | None = None,
    min_stars: int | None = None,
    max_stars: int | None = None,
) -> list[Repo]:
    """Dispatch by scope. Returns up to max_repos.

    All filters (date, language, stars) are ignored for single_repo scope.
    """
    _validate_dates(pushed_after, pushed_before)
    if min_stars is not None and max_stars is not None and min_stars > max_stars:
        raise ListerError(
            f"min_stars ({min_stars}) is greater than max_stars ({max_stars}). "
            "Swap them or remove one."
        )

    if scope == "all_github":
        return list_global(
            keyword, max_repos, pat,
            pushed_after, pushed_before, language, min_stars, max_stars,
        )
    if scope == "user_or_org":
        if not target:
            raise ListerError("scope=user_or_org requires 'target' (the username or org name)")
        return list_user(
            target.strip("/"), max_repos, pat,
            pushed_after, pushed_before, language, min_stars, max_stars,
        )
    if scope == "single_repo":
        if not target:
            raise ListerError("scope=single_repo requires 'target' (the repo URL)")
        return list_single(target, pat)
    raise ListerError(f"unknown scope: {scope!r}. Expected: all_github | user_or_org | single_repo")


def _validate_dates(pushed_after: str | None, pushed_before: str | None) -> None:
    """Validate ISO date format and ordering. Raises ListerError on bad input."""
    iso_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for label, value in (("pushed_after", pushed_after), ("pushed_before", pushed_before)):
        if value and not iso_re.match(value):
            raise ListerError(
                f"{label}={value!r} is not a valid ISO date. "
                "Expected format: YYYY-MM-DD (e.g. 2025-01-15)."
            )
    if pushed_after and pushed_before and pushed_after > pushed_before:
        raise ListerError(
            f"pushed_after ({pushed_after}) is later than pushed_before ({pushed_before}). "
            "Swap them or remove one."
        )
