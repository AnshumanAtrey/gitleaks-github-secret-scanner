"""Tests for the v0.6 new modules: keyword_expander, code_search, main.extract_literal_prefix.

Pure-function tests — no network calls.
Usage: python tests/test_new_modes.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.code_search import CodeSearchClient, CodeSearchError, normalize_repo, normalize_user  # noqa: E402
from src.keyword_expander import expand  # noqa: E402
from src.main import extract_literal_prefix  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────


def t(name: str):
    """Decorator that registers a test."""
    def wrap(fn):
        _TESTS.append((name, fn))
        return fn
    return wrap


_TESTS: list[tuple[str, callable]] = []


def assert_eq(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}\n  expected: {expected!r}\n  actual:   {actual!r}")


def assert_in(needle, haystack, msg=""):
    if needle not in haystack:
        raise AssertionError(f"{msg}\n  needle not found: {needle!r}\n  haystack: {haystack!r}")


def assert_raises(exc_type, fn, msg=""):
    try:
        fn()
    except exc_type:
        return
    except Exception as e:
        raise AssertionError(f"{msg}: expected {exc_type.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"{msg}: expected {exc_type.__name__}, no exception raised")


# ──────────────────────────────────────────────────────────────────────────
# keyword_expander.expand
# ──────────────────────────────────────────────────────────────────────────


@t("expand('anthropic') generates expected variants")
def _():
    exp = expand("anthropic")
    assert_in("ANTHROPIC_API_KEY", exp.variants, "missing UPPER_API_KEY variant")
    assert_in("anthropic_api_key", exp.variants, "missing lower_api_key variant")
    assert_in("anthropicApiKey", exp.variants, "missing camelCase variant")
    assert_in("Anthropic.apiKey", exp.variants, "missing dot-notation variant")
    assert_in("ANTHROPIC_SECRET", exp.variants, "missing UPPER_SECRET variant")
    assert_in("ANTHROPIC_TOKEN", exp.variants, "missing UPPER_TOKEN variant")


@t("expand produces dedup'd variants")
def _():
    exp = expand("aws")
    assert_eq(len(exp.variants), len(set(exp.variants)), "variants should be unique")


@t("expand produces batched code_search_queries (<=4 OR per batch)")
def _():
    exp = expand("anthropic")
    assert len(exp.code_search_queries) >= 3, "should have multiple batched queries"
    for q in exp.code_search_queries:
        or_count = q.count(" OR ")
        if or_count > 3:
            raise AssertionError(f"too many OR terms in single query: {q}")


@t("extraction_regex matches realistic env file content")
def _():
    exp = expand("anthropic")
    regex = re.compile(exp.extraction_regex)
    samples = [
        ('ANTHROPIC_API_KEY=sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ', "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
        ('anthropic_api_key="sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ"', "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
        ("ANTHROPIC_SECRET: 'sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ'", "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
        ('"ANTHROPIC_API_KEY": "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ"', "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
    ]
    for content, expected_secret in samples:
        m = regex.search(content)
        if not m:
            raise AssertionError(f"failed to match: {content!r}")
        assert_in(expected_secret, m.group("secret"), f"in content: {content!r}")


@t("expand('') raises ValueError")
def _():
    assert_raises(ValueError, lambda: expand(""))


@t("expand with unsafe chars raises ValueError")
def _():
    assert_raises(ValueError, lambda: expand("evil; rm -rf /"))
    assert_raises(ValueError, lambda: expand("../path"))
    assert_raises(ValueError, lambda: expand("name with space"))


@t("expand.as_service() produces a usable Service")
def _():
    exp = expand("razorpay")
    svc = exp.as_service()
    assert_eq(svc.id, "keyword:razorpay")
    assert_eq(svc.auth_class, "single")
    assert len(svc.patterns) >= 1
    # Regex should compile
    re.compile(svc.patterns[0].regex)


# ──────────────────────────────────────────────────────────────────────────
# extract_literal_prefix
# ──────────────────────────────────────────────────────────────────────────


@t("extract_literal_prefix on simple prefix regex")
def _():
    assert_eq(extract_literal_prefix("rzp_live_[A-Za-z0-9]{14}"), "rzp_live_")


@t("extract_literal_prefix with anthropic-style regex")
def _():
    assert_eq(extract_literal_prefix("sk-ant-api03-[A-Za-z0-9_-]{93}"), "sk-ant-api03-")


@t("extract_literal_prefix with leading \\b word-boundary")
def _():
    assert_eq(extract_literal_prefix(r"\bAKIA[A-Z0-9]{16}\b"), "")


@t("extract_literal_prefix returns '' for pure regex")
def _():
    assert_eq(extract_literal_prefix("[A-Z]{20}"), "")


@t("extract_literal_prefix handles escaped metacharacters")
def _():
    assert_eq(extract_literal_prefix(r"sk\-ant\-[A-Z]+"), "sk-ant-")


# ──────────────────────────────────────────────────────────────────────────
# code_search.normalize_*
# ──────────────────────────────────────────────────────────────────────────


@t("normalize_user accepts bare username")
def _():
    assert_eq(normalize_user("octocat"), "octocat")


@t("normalize_user strips URL prefix")
def _():
    assert_eq(normalize_user("https://github.com/microsoft"), "microsoft")
    assert_eq(normalize_user("github.com/octocat"), "octocat")
    assert_eq(normalize_user("https://github.com/microsoft/"), "microsoft")


@t("normalize_user strips @ prefix")
def _():
    assert_eq(normalize_user("@razorpay"), "razorpay")


@t("normalize_user rejects empty")
def _():
    assert_raises(CodeSearchError, lambda: normalize_user(""))


@t("normalize_repo accepts owner/name")
def _():
    assert_eq(normalize_repo("octocat/Hello-World"), "octocat/Hello-World")


@t("normalize_repo strips URL and .git")
def _():
    assert_eq(normalize_repo("https://github.com/octocat/Hello-World.git"), "octocat/Hello-World")
    assert_eq(normalize_repo("https://github.com/octocat/Hello-World/"), "octocat/Hello-World")


@t("normalize_repo rejects single segment")
def _():
    assert_raises(CodeSearchError, lambda: normalize_repo("octocat"))


# ──────────────────────────────────────────────────────────────────────────
# code_search.build_query
# ──────────────────────────────────────────────────────────────────────────


@t("build_query passes through base query for all_github")
def _():
    q = CodeSearchClient.build_query('"sk-ant-"', scope="all_github")
    assert_eq(q, '"sk-ant-"')


@t("build_query adds user qualifier for user_or_org")
def _():
    q = CodeSearchClient.build_query('"sk-ant-"', scope="user_or_org", target="octocat")
    assert_eq(q, '"sk-ant-" user:octocat')


@t("build_query adds repo qualifier for single_repo")
def _():
    q = CodeSearchClient.build_query(
        '"sk-ant-"', scope="single_repo", target="octocat/Hello-World"
    )
    assert_eq(q, '"sk-ant-" repo:octocat/Hello-World')


@t("build_query adds language qualifier")
def _():
    q = CodeSearchClient.build_query('"sk-ant-"', scope="all_github", language="Python")
    assert_eq(q, '"sk-ant-" language:python')


@t("build_query combines scope + language")
def _():
    q = CodeSearchClient.build_query(
        '"sk-ant-"', scope="user_or_org", target="octocat", language="javascript"
    )
    assert_eq(q, '"sk-ant-" user:octocat language:javascript')


# ──────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    print(f"Running {len(_TESTS)} new-mode tests")
    print("=" * 70)
    passes = 0
    fails = 0
    failures: list[tuple[str, str]] = []
    for name, fn in _TESTS:
        try:
            fn()
            print(f"  [PASS] {name}")
            passes += 1
        except AssertionError as e:
            print(f"  [FAIL] {name}")
            failures.append((name, str(e)))
            fails += 1
        except Exception as e:
            print(f"  [ERR ] {name}: {type(e).__name__}: {e}")
            failures.append((name, f"{type(e).__name__}: {e}"))
            fails += 1
    print("=" * 70)
    print(f"Results: {passes} passed, {fails} failed")
    if failures:
        print()
        for name, msg in failures:
            print(f"--- {name} ---")
            print(msg)
            print()
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
