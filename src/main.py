"""Apify entry point — v0.12 unified engine.

Single flow:
  1. Discover candidate repos
       - scope=all_github + PAT  → GitHub Code Search (precision)
       - scope=all_github + no PAT → GitHub repo search (broad keyword)
       - scope=user_or_org → list owner's repos
       - scope=single_repo → 1 repo
  2. Clone each repo (parallel, up to MAX_PARALLEL_CLONES)
       - --no-single-branch (all branches)
       - fetch refs/pull/*/head (PR refs)
       - optional: --recurse-submodules, git fsck --dangling
  3. Run gitleaks against full history with --log-opts filters honored
  4. Push findings (one record per finding, including branch_ref + is_dangling)

Pricing:
  $0.01  actor_start
  $0.001 per_code_search_query (fires only during PAT-enabled repo discovery)
  $0.02  per_repo_scanned
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from apify import Actor

from src.code_search import CodeSearchClient, CodeSearchError, CodeSearchHit
from src.keyword_expander import expand as expand_keyword
from src.lister import list_repos, ListerError, Repo
from src.output import to_record, matches_extension_filter
from src.pairing import pair
from src.registry import Allowlists, Pattern, RegistryError, Service, load_all
from src.scanner import Finding, ScanOptions, ScannerError, scan_repo, write_config

log = logging.getLogger("gitleaks-cloud")

MAX_PARALLEL_CLONES = 4  # how many repos to clone+scan concurrently


# ────────────────────────────────────────────────────────────────────────────
# Inputs
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class Inputs:
    # Core
    search_for: str
    platform: str
    platform_custom: str | None
    additional_platforms: list[str]
    keyword: str | None
    regex_pattern: str | None
    scope: str
    target: str | None
    github_pat: str | None
    max_results: int
    # Existing filters
    pushed_after: str | None
    pushed_before: str | None
    language: str | None
    min_stars: int | None
    max_stars: int | None
    include_extensions: list[str]
    include_test_keys: bool
    # New v0.12 advanced scan options (passed to ScanOptions)
    include_all_branches: bool
    include_submodules: bool
    include_pr_refs: bool
    include_dangling_objects: bool
    commit_since: str | None
    commit_until: str | None
    commit_author: str | None
    commit_message_grep: str | None
    commit_introduced_string: str | None
    max_file_size_mb: int


def read_inputs(data: dict) -> Inputs:
    pa = data.get("pushed_after") or None
    pb = data.get("pushed_before") or None
    if pa and len(pa) > 10: pa = pa[:10]
    if pb and len(pb) > 10: pb = pb[:10]
    cs = data.get("commit_since") or None
    cu = data.get("commit_until") or None
    if cs and len(cs) > 10: cs = cs[:10]
    if cu and len(cu) > 10: cu = cu[:10]
    return Inputs(
        search_for=data.get("search_for", "platform"),
        platform=data.get("platform", "razorpay"),
        platform_custom=data.get("platform_custom") or None,
        additional_platforms=data.get("additional_platforms") or [],
        keyword=data.get("keyword") or None,
        regex_pattern=data.get("regex_pattern") or None,
        scope=data.get("scope", "all_github"),
        target=data.get("target") or None,
        github_pat=data.get("github_pat") or None,
        max_results=int(data.get("max_results", 100)),
        pushed_after=pa,
        pushed_before=pb,
        language=data.get("language") or None,
        min_stars=data.get("min_stars"),
        max_stars=data.get("max_stars"),
        include_extensions=data.get("include_extensions") or [],
        include_test_keys=bool(data.get("include_test_keys", True)),
        include_all_branches=bool(data.get("include_all_branches", True)),
        include_submodules=bool(data.get("include_submodules", False)),
        include_pr_refs=bool(data.get("include_pr_refs", True)),
        include_dangling_objects=bool(data.get("include_dangling_objects", False)),
        commit_since=cs,
        commit_until=cu,
        commit_author=data.get("commit_author") or None,
        commit_message_grep=data.get("commit_message_grep") or None,
        commit_introduced_string=data.get("commit_introduced_string") or None,
        max_file_size_mb=int(data.get("max_file_size_mb", 100)),
    )


def inputs_to_scan_options(inputs: Inputs) -> ScanOptions:
    return ScanOptions(
        include_all_branches=inputs.include_all_branches,
        include_submodules=inputs.include_submodules,
        include_pr_refs=inputs.include_pr_refs,
        include_dangling_objects=inputs.include_dangling_objects,
        commit_since=inputs.commit_since,
        commit_until=inputs.commit_until,
        commit_author=inputs.commit_author,
        commit_message_grep=inputs.commit_message_grep,
        commit_introduced_string=inputs.commit_introduced_string,
        max_file_size_mb=inputs.max_file_size_mb,
    )


# ────────────────────────────────────────────────────────────────────────────
# Service construction (platform / keyword / regex) — unchanged from v0.11
# ────────────────────────────────────────────────────────────────────────────


def build_scan_service(inputs: Inputs, services: dict[str, Service]) -> tuple[Service, str]:
    if inputs.search_for == "platform":
        return _service_from_platform(inputs, services)
    if inputs.search_for == "keyword":
        if not inputs.keyword:
            raise ValueError("search_for='keyword' requires the 'keyword' field to be filled in")
        exp = expand_keyword(inputs.keyword)
        return exp.as_service(), f"keyword:{inputs.keyword}"
    if inputs.search_for == "regex":
        if not inputs.regex_pattern:
            raise ValueError("search_for='regex' requires the 'regex_pattern' field to be filled in")
        return _service_from_regex(inputs.regex_pattern), "regex:custom"
    raise ValueError(f"unknown search_for value: {inputs.search_for!r}")


def _service_from_platform(inputs: Inputs, services: dict[str, Service]) -> tuple[Service, str]:
    if inputs.platform == "custom":
        name = (inputs.platform_custom or "").strip()
        if not name:
            raise ValueError("platform='custom' requires platform_custom to be filled in")
        merged = _merge_services(services, display_name=f"custom:{name}")
        return merged, name
    if inputs.platform not in services:
        raise ValueError(
            f"unknown platform {inputs.platform!r}. Pick from: {sorted(services)} or use 'custom'."
        )
    primary = services[inputs.platform]
    if inputs.additional_platforms:
        unknown = [p for p in inputs.additional_platforms if p not in services]
        if unknown:
            raise ValueError(f"unknown additional_platforms entries: {unknown}")
        all_ids = [inputs.platform] + [p for p in inputs.additional_platforms if p != inputs.platform]
        if len(all_ids) > 1:
            subset = {sid: services[sid] for sid in all_ids}
            merged = _merge_services(subset, display_name="+".join(all_ids))
            return merged, "+".join(all_ids)
    return primary, inputs.platform


def _service_from_regex(regex_pattern: str) -> Service:
    try:
        re.compile(regex_pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex pattern: {exc}")
    return Service(
        id="regex-custom",
        display_name="Custom regex",
        auth_class="single",
        search_keywords=[],
        patterns=[Pattern(name="custom-regex", component="secret", regex=regex_pattern,
                          keywords=[], secret_group=None)],
        testkey_patterns=[],
        allowlists=Allowlists(paths=[], match_regexes=[]),
    )


def _merge_services(services: dict[str, Service], display_name: str) -> Service:
    merged_patterns: list[Pattern] = []
    merged_testkeys = []
    for s in services.values():
        merged_patterns.extend(s.patterns)
        merged_testkeys.extend(s.testkey_patterns)
    paths: list[str] = []
    seen_paths: set[str] = set()
    for s in services.values():
        for p in s.allowlists.paths:
            if p not in seen_paths:
                paths.append(p)
                seen_paths.add(p)
    return Service(
        id="custom", display_name=display_name, auth_class="paired",
        search_keywords=[], patterns=merged_patterns, testkey_patterns=merged_testkeys,
        allowlists=Allowlists(paths=paths, match_regexes=[]),
    )


# ────────────────────────────────────────────────────────────────────────────
# Repo discovery — Code Search becomes a precision repo selector, not a finder
# ────────────────────────────────────────────────────────────────────────────


_REGEX_META = set(r".^$|*+?()[]{}\\")


def extract_literal_prefix(regex_pattern: str) -> str:
    result: list[str] = []
    i = 0
    while i < len(regex_pattern):
        c = regex_pattern[i]
        if c == "\\" and i + 1 < len(regex_pattern):
            nxt = regex_pattern[i + 1]
            if nxt.lower() in "bdsswn" or nxt.isdigit():
                break
            result.append(nxt)
            i += 2
            continue
        if c in _REGEX_META:
            break
        result.append(c)
        i += 1
    return "".join(result)


def build_code_search_queries(inputs: Inputs, service: Service) -> list[str]:
    if inputs.search_for == "keyword" and inputs.keyword:
        return expand_keyword(inputs.keyword).code_search_queries
    if inputs.search_for == "regex" and inputs.regex_pattern:
        prefix = extract_literal_prefix(inputs.regex_pattern)
        if len(prefix) >= 4:
            return [f'"{prefix}"']
        return []
    queries: list[str] = []
    seen: set[str] = set()
    for kw in service.search_keywords:
        if len(kw) >= 4 and kw not in seen:
            queries.append(f'"{kw}"')
            seen.add(kw)
    for p in service.patterns:
        if p.component == "id":
            prefix = extract_literal_prefix(p.regex)
            if len(prefix) >= 4 and prefix not in seen:
                queries.append(f'"{prefix}"')
                seen.add(prefix)
    return queries


async def discover_repos_via_code_search(
    client: CodeSearchClient,
    queries: list[str],
    inputs: Inputs,
    max_repos: int,
) -> list[Repo]:
    """Use Code Search to find UNIQUE candidate repos. Returns list[Repo] ready to clone.

    This is the precision step: instead of cloning 50 repos that just happen to
    mention the keyword, we ask Code Search 'which files contain the actual
    pattern?' and dedupe to ~20-30 unique repos that truly contain the signal.

    Each query fires the `per_code_search_query` PPE event ($0.001) so the
    declared pricing matches actual behavior.
    """
    unique: dict[str, Repo] = {}
    for query_base in queries:
        if len(unique) >= max_repos:
            break
        full_query = CodeSearchClient.build_query(
            query_base, scope=inputs.scope, target=inputs.target, language=inputs.language,
        )
        Actor.log.info("repo-discovery query: %s", full_query)
        try:
            await Actor.charge("per_code_search_query")
        except Exception:
            pass  # PPE not configured locally; cloud-only
        try:
            hits = client.search(full_query, max_results=max_repos * 4)  # over-fetch for dedup
        except CodeSearchError as exc:
            Actor.log.warning("code search failed (%s) — continuing with other queries", exc)
            continue
        for hit in hits:
            if hit.repo_full_name in unique:
                continue
            unique[hit.repo_full_name] = Repo(
                full_name=hit.repo_full_name,
                clone_url=hit.repo_url + ".git",
                size_kb=0,
                pushed_at="",
            )
            if len(unique) >= max_repos:
                break
    return list(unique.values())


# ────────────────────────────────────────────────────────────────────────────
# Main — unified flow
# ────────────────────────────────────────────────────────────────────────────


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    async with Actor:
        try:
            await Actor.charge("actor_start")
        except Exception:
            pass

        inputs = read_inputs(await Actor.get_input() or {})
        scan_opts = inputs_to_scan_options(inputs)

        try:
            services = load_all()
        except RegistryError as exc:
            Actor.log.exception("registry load failed")
            await Actor.fail(status_message=f"Registry error: {exc}")
            return

        try:
            scan_service, platform_label = build_scan_service(inputs, services)
        except ValueError as exc:
            await Actor.fail(status_message=str(exc))
            return

        Actor.log.info(
            "v0.12 scan: search_for=%s platform=%s scope=%s pat=%s "
            "pr_refs=%s all_branches=%s submodules=%s dangling=%s parallel=%d",
            inputs.search_for, platform_label, inputs.scope,
            "<provided>" if inputs.github_pat else "<none>",
            inputs.include_pr_refs, inputs.include_all_branches,
            inputs.include_submodules, inputs.include_dangling_objects,
            MAX_PARALLEL_CLONES,
        )

        # ── Stage 1: discover candidate repos ────────────────────────────
        repos: list[Repo] = []
        try:
            if inputs.github_pat and inputs.scope == "all_github":
                queries = build_code_search_queries(inputs, scan_service)
                if queries:
                    client = CodeSearchClient(inputs.github_pat)
                    repos = await discover_repos_via_code_search(
                        client, queries, inputs, inputs.max_results,
                    )
                    Actor.log.info(
                        "discovered %d unique candidate repos via Code Search", len(repos)
                    )
                else:
                    Actor.log.info(
                        "no usable Code Search prefix — falling back to repo search"
                    )
            if not repos:
                # Fallback: GitHub repo search (broad) — or scope-specific list
                keyword = (
                    scan_service.search_keywords[0]
                    if scan_service.search_keywords
                    else (inputs.keyword or inputs.platform_custom or inputs.platform)
                )
                repos = list_repos(
                    scope=inputs.scope,
                    target=inputs.target,
                    keyword=keyword,
                    max_repos=inputs.max_results,
                    pat=inputs.github_pat,
                    pushed_after=inputs.pushed_after,
                    pushed_before=inputs.pushed_before,
                    language=inputs.language,
                    min_stars=inputs.min_stars,
                    max_stars=inputs.max_stars,
                )
                Actor.log.info("discovered %d candidate repos via repo search", len(repos))
        except ListerError as exc:
            Actor.log.error("repo discovery failed: %s", exc)
            await Actor.fail(status_message=str(exc))
            return

        if not repos:
            Actor.log.warning("no repos matched — nothing to scan")
            return

        # ── Stage 2: parallel clone + scan ───────────────────────────────
        cfg_path = write_config(
            scan_service.to_gitleaks_toml(include_test_keys=inputs.include_test_keys)
        )
        work_root = Path(tempfile.mkdtemp(prefix="repo-audit-"))

        sem = asyncio.Semaphore(MAX_PARALLEL_CLONES)
        total_findings = 0
        scanned = 0
        results_lock = asyncio.Lock()

        async def scan_one(repo: Repo, idx: int) -> None:
            nonlocal total_findings, scanned
            async with sem:
                t0 = time.time()
                try:
                    findings = await asyncio.to_thread(
                        scan_repo, repo.clone_url, cfg_path,
                        opts=scan_opts, work_root=work_root,
                    )
                except ScannerError as exc:
                    Actor.log.warning("skip %s: %s", repo.full_name, exc)
                    return
                except Exception as exc:
                    Actor.log.exception("unexpected error scanning %s: %s", repo.full_name, exc)
                    return

                records = pair(findings, scan_service)
                if not inputs.include_test_keys:
                    records = [r for r in records if not r.is_test_key]
                if inputs.include_extensions:
                    records = [
                        r for r in records
                        if matches_extension_filter(r.file, inputs.include_extensions)
                    ]

                async with results_lock:
                    for r in records:
                        record_dict = to_record(r, repo, platform_label)
                        # Look up branch_ref + is_dangling from the original Finding
                        # (PairedRecord doesn't carry them — match by commit+line)
                        orig = next(
                            (f for f in findings
                             if f.commit == r.commit and f.start_line == r.line),
                            None,
                        )
                        if orig:
                            record_dict["branch_ref"] = orig.branch_ref or "history"
                            record_dict["is_dangling"] = orig.is_dangling
                        else:
                            record_dict["branch_ref"] = "history"
                            record_dict["is_dangling"] = False
                        record_dict["scan_method"] = "clone"
                        await Actor.push_data(record_dict)
                    total_findings += len(records)
                    scanned += 1
                    try:
                        await Actor.charge("per_repo_scanned")
                    except Exception:
                        pass
                    Actor.log.info(
                        "[%d/%d] %s findings=%d elapsed=%.1fs",
                        scanned, len(repos), repo.full_name, len(records), time.time() - t0,
                    )

        tasks = [scan_one(r, i) for i, r in enumerate(repos)]
        await asyncio.gather(*tasks)

        Actor.log.info(
            "done. scanned=%d/%d total_findings=%d", scanned, len(repos), total_findings
        )


if __name__ == "__main__":
    asyncio.run(main())
