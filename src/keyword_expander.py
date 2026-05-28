"""Keyword expander: turn one word into a Service for scanning.

Users who don't know regex can just type a word like 'anthropic' or 'razorpay'
and we expand it into ~15 common variable-name variants:
  - UPPER_SNAKE: ANTHROPIC_API_KEY, ANTHROPIC_SECRET, ANTHROPIC_TOKEN
  - lower_snake: anthropic_api_key, anthropic_secret, anthropic_token
  - camelCase:   anthropicApiKey, anthropicSecret, anthropicToken
  - dot:         Anthropic.apiKey

The module emits three things:
  * KeywordExpansion.as_service() — a Service plugged into the gitleaks pipeline
  * KeywordExpansion.code_search_queries — batched OR-joined Code Search queries
  * KeywordExpansion.extraction_regex — Python regex with named groups for raw file parsing
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src.registry import Allowlists, Pattern, Service


# Templates expand a word into common variable-name shapes.
# Order matters — strongest signals first (least false-positive risk).
_TEMPLATES = [
    "{UPPER}_API_KEY",
    "{UPPER}_API_SECRET",
    "{UPPER}_SECRET_KEY",
    "{UPPER}_PRIVATE_KEY",
    "{UPPER}_ACCESS_TOKEN",
    "{UPPER}_SECRET",
    "{UPPER}_TOKEN",
    "{UPPER}_KEY",
    "{lower}_api_key",
    "{lower}_secret",
    "{lower}_token",
    "{camel}ApiKey",
    "{camel}Secret",
    "{camel}Token",
    "{Pascal}.apiKey",
]

# Secret value charset — covers JWT-like, base64-like, hex, alphanum-with-dashes.
# 12-256 chars: long enough to skip noise like `true`/`false`/short flags;
# short enough to not match entire paragraphs.
_SECRET_CHARSET = r"[A-Za-z0-9_\-\.\+/=]{12,256}"


@dataclass
class KeywordExpansion:
    word: str
    variants: list[str]               # e.g. ["ANTHROPIC_API_KEY", "anthropic_api_key", ...]
    code_search_queries: list[str]    # batched OR'd queries for Code Search
    extraction_regex: str             # one Python regex with named groups

    def as_service(self) -> Service:
        """Convert into a Service that the existing gitleaks pipeline accepts."""
        alt = "|".join(re.escape(v) for v in self.variants)
        # Allow optional quote around the variable name (JSON, Python dict, env)
        # followed by `:` or `=`, then the secret value (optionally quoted).
        regex = (
            f"(?:{alt})['\"]?\\s*[:=]\\s*['\"]?({_SECRET_CHARSET})"
        )
        return Service(
            id=f"keyword:{self.word}",
            display_name=f"Keyword: {self.word}",
            auth_class="single",
            search_keywords=[self.word],
            patterns=[Pattern(
                name=f"keyword-{_safe_id(self.word)}",
                component="secret",
                regex=regex,
                keywords=[self.word.upper(), self.word.lower()],
                secret_group=1,
            )],
            testkey_patterns=[],
            allowlists=Allowlists(
                paths=[
                    "(?i)node_modules", "(?i)vendor/", "(?i)dist/", "(?i)build/",
                    "(?i)\\.git/", "(?i)\\.lock$",
                ],
                match_regexes=[],
            ),
        )


def _safe_id(word: str) -> str:
    """Sanitize the word for use as a TOML rule id."""
    return re.sub(r"[^A-Za-z0-9]+", "-", word.lower()).strip("-") or "kw"


def _case_variants(word: str) -> tuple[str, str, str, str]:
    """Return (UPPER, lower, camel, Pascal) cases of the word."""
    if not word:
        return "", "", "", ""
    upper = word.upper()
    lower = word.lower()
    camel = lower
    pascal = lower[:1].upper() + lower[1:]
    return upper, lower, camel, pascal


_VALID_WORD = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]*$")


def expand(word: str) -> KeywordExpansion:
    """Expand one word into variants + Code Search queries + extraction regex.

    Raises ValueError if the word is empty or contains unsafe characters.
    """
    word = (word or "").strip()
    if not word:
        raise ValueError("keyword cannot be empty")
    if not _VALID_WORD.match(word):
        raise ValueError(
            f"keyword {word!r} must start with a letter and contain only "
            "letters, digits, underscore, or hyphen"
        )

    UPPER, lower, camel, Pascal = _case_variants(word)
    raw_variants = [
        tmpl.format(UPPER=UPPER, lower=lower, camel=camel, Pascal=Pascal)
        for tmpl in _TEMPLATES
    ]
    # Dedup while preserving order
    seen: set[str] = set()
    variants: list[str] = []
    for v in raw_variants:
        if v not in seen:
            variants.append(v)
            seen.add(v)

    queries = _batch_into_queries(variants, batch_size=4)

    alt = "|".join(re.escape(v) for v in variants)
    extraction_regex = (
        f"(?P<name>{alt})['\"]?\\s*[:=]\\s*['\"]?(?P<secret>{_SECRET_CHARSET})"
    )

    return KeywordExpansion(
        word=word,
        variants=variants,
        code_search_queries=queries,
        extraction_regex=extraction_regex,
    )


def _batch_into_queries(variants: list[str], batch_size: int = 4) -> list[str]:
    """Pack variants into OR-joined Code Search queries.

    GitHub Code Search allows up to 5 boolean operators per query; we use 4
    quoted terms per batch to stay under that comfortably.
    """
    queries: list[str] = []
    for i in range(0, len(variants), batch_size):
        chunk = variants[i:i + batch_size]
        quoted = [f'"{v}"' for v in chunk]
        queries.append(" OR ".join(quoted))
    return queries
