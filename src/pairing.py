"""Pairing engine: group findings so users see usable credential pairs.

For services with auth_class='paired' (Razorpay, AWS, Twilio, PayU):
  - If an `id` finding and a `secret` finding appear in the SAME FILE
    within PAIR_LINE_WINDOW lines of each other, emit one PAIRED record.
  - Standalone id or secret findings emit UNPAIRED records.

For services with auth_class='single' (OpenAI, GitHub PAT, Gemini, …):
  - Every finding is UNPAIRED (no companion exists).

For services with auth_class='pub_priv' (Stripe, Supabase):
  - Same shape as 'paired' but the publishable side is informational.

Dedup rule: within the same (repo, file, line, secret_value) tuple, only
the FIRST finding wins. This collapses the "rule fired twice" case where
e.g. a Razorpay test key matches both the generic id rule and the testkey rule.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

from src.registry import Service
from src.scanner import Finding

log = logging.getLogger(__name__)

PAIR_LINE_WINDOW = 10  # lines apart — pairs found in .env adjacent lines OR within same Python config block


@dataclass
class PairedRecord:
    """One emitted record per (deduped) finding, possibly with a paired companion."""
    file: str
    line: int
    commit: str
    secret_name: str           # the gitleaks rule's short name (e.g. "razorpay-key-secret")
    secret_value: str
    is_test_key: bool
    paired: bool
    paired_with: dict | None   # {"name": ..., "value": ..., "line": ...} or None
    author_name: str = ""
    author_email: str = ""
    commit_date: str = ""


def _component_for(finding: Finding, service: Service) -> str | None:
    """Return 'id' | 'secret' | None for this finding under this service's rules."""
    if finding.is_test_key:
        return "id"  # test keys are id-shaped (rzp_test_*, pk_test_*)
    for pat in service.patterns:
        if finding.rule_id.endswith(f":{pat.name}"):
            return pat.component
    return None


def _dedup(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates with same (file, line, secret). Prefer non-testkey rules."""
    seen: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file, f.start_line, f.secret)
        if key not in seen:
            seen[key] = f
        else:
            # Prefer the non-testkey label if both matched
            if seen[key].is_test_key and not f.is_test_key:
                seen[key] = f
    return list(seen.values())


def _short_name(rule_id: str) -> str:
    """Convert 'razorpay:razorpay-key-secret' → 'razorpay-key-secret'."""
    return rule_id.split(":", 1)[-1].removeprefix("testkey:")


def pair(findings: list[Finding], service: Service) -> list[PairedRecord]:
    """Apply pairing logic. Returns one PairedRecord per emitted output row.

    A paired record consumes BOTH its id and secret findings, so the secret
    won't also be emitted standalone in the same run.
    """
    deduped = _dedup(findings)

    # Bucket findings by file → list of (component, finding)
    by_file: dict[str, list[tuple[str | None, Finding]]] = {}
    for f in deduped:
        component = _component_for(f, service)
        by_file.setdefault(f.file, []).append((component, f))

    out: list[PairedRecord] = []
    paired_secret_ids: set[int] = set()
    referenced_id_ids: set[int] = set()  # ids that appeared as paired_with in any record

    if service.auth_class in ("paired", "pub_priv"):
        # For each secret, find its NEAREST id in the same file (within window).
        # Ids are reusable — one pk_live can be paired_with by multiple secrets
        # (e.g. Stripe account has 1 pk_live + 1 sk_live + many webhook secrets).
        for file_path, entries in by_file.items():
            ids = [f for c, f in entries if c == "id"]
            secrets = [f for c, f in entries if c == "secret"]
            for sec in secrets:
                candidates = [
                    fid for fid in ids
                    if abs(fid.start_line - sec.start_line) <= PAIR_LINE_WINDOW
                ]
                if candidates:
                    pair_id = min(candidates, key=lambda x: abs(x.start_line - sec.start_line))
                    paired_secret_ids.add(id(sec))
                    referenced_id_ids.add(id(pair_id))
                    out.append(PairedRecord(
                        file=sec.file,
                        line=sec.start_line,
                        commit=sec.commit,
                        secret_name=_short_name(sec.rule_id),
                        secret_value=sec.secret,
                        is_test_key=False,
                        paired=True,
                        paired_with={
                            "name": _short_name(pair_id.rule_id),
                            "value": pair_id.secret,
                            "line": pair_id.start_line,
                        },
                        author_name=sec.author_name,
                        author_email=sec.author_email,
                        commit_date=sec.commit_date,
                    ))

    # Emit findings not yet emitted:
    #   - secrets that didn't find an id partner → unpaired
    #   - ids that no secret referenced → unpaired (standalone id, informational)
    #   - non-component findings (testkeys, single-class) → unpaired
    for f in deduped:
        if id(f) in paired_secret_ids or id(f) in referenced_id_ids:
            continue
        out.append(PairedRecord(
            file=f.file,
            line=f.start_line,
            commit=f.commit,
            secret_name=_short_name(f.rule_id),
            secret_value=f.secret,
            is_test_key=f.is_test_key,
            paired=False,
            paired_with=None,
            author_name=f.author_name,
            author_email=f.author_email,
            commit_date=f.commit_date,
        ))

    # Stable sort: by file, then line
    out.sort(key=lambda r: (r.file, r.line))
    return out
