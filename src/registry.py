"""Service registry: load per-platform TOMLs and emit gitleaks configs.

Each rules/<name>.toml declares a service's auth class and detection patterns.
On startup we validate every TOML, fail-fast on a malformed one.
At scan time we generate a gitleaks config that includes only the patterns
relevant to the requested platform (or a permissive "all rules" config for
the 'custom' fallback).
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

AuthClass = Literal["single", "paired", "pub_priv"]
Component = Literal["id", "secret"]

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass
class Pattern:
    name: str
    component: Component
    regex: str
    keywords: list[str] = field(default_factory=list)
    secret_group: int | None = None


@dataclass
class TestKeyPattern:
    name: str
    regex: str


@dataclass
class Allowlists:
    paths: list[str] = field(default_factory=list)
    match_regexes: list[str] = field(default_factory=list)
    # New: regexes evaluated against the captured SECRET (not the full match).
    # If any regex matches, the finding is skipped. Used to block code
    # identifiers (e.g. 'payUMode', 'clientIDController') that share the
    # shape of real secret values but are obviously not credentials.
    secret_regexes: list[str] = field(default_factory=list)


@dataclass
class Service:
    id: str
    display_name: str
    auth_class: AuthClass
    search_keywords: list[str]
    patterns: list[Pattern]
    testkey_patterns: list[TestKeyPattern]
    allowlists: Allowlists

    def has_id_pattern(self) -> bool:
        return any(p.component == "id" for p in self.patterns)

    def has_secret_pattern(self) -> bool:
        return any(p.component == "secret" for p in self.patterns)

    def to_gitleaks_toml(self, include_test_keys: bool = True) -> str:
        """Generate a gitleaks TOML config that emits findings for this service."""
        lines = [f'title = "generated-{self.id}"']

        # Real-secret patterns
        for p in self.patterns:
            lines.append("")
            lines.append("[[rules]]")
            lines.append(f'id = "{self.id}:{p.name}"')
            lines.append(f'description = "{self.display_name} {p.component}"')
            lines.append(f"regex = '''{p.regex}'''")
            if p.secret_group is not None:
                lines.append(f"secretGroup = {p.secret_group}")
            if p.keywords:
                kws = ", ".join(f'"{k}"' for k in p.keywords)
                lines.append(f"keywords = [{kws}]")

            # Per-rule allowlist for match/path skips
            if self.allowlists.paths:
                lines.append("  [[rules.allowlists]]")
                lines.append('  description = "skip vendor/build dirs"')
                paths = ", ".join(f"'''{x}'''" for x in self.allowlists.paths)
                lines.append(f"  paths = [{paths}]")
            if self.allowlists.match_regexes:
                lines.append("  [[rules.allowlists]]")
                lines.append('  description = "skip placeholder/example patterns"')
                lines.append("  regexTarget = \"match\"")
                regs = ", ".join(f"'''{x}'''" for x in self.allowlists.match_regexes)
                lines.append(f"  regexes = [{regs}]")
            if self.allowlists.secret_regexes:
                lines.append("  [[rules.allowlists]]")
                lines.append('  description = "skip code-identifier-shaped values"')
                lines.append("  regexTarget = \"secret\"")
                regs = ", ".join(f"'''{x}'''" for x in self.allowlists.secret_regexes)
                lines.append(f"  regexes = [{regs}]")

        # Test-key patterns: emit as rules tagged 'testkey:' so we can label them
        if include_test_keys:
            for tp in self.testkey_patterns:
                lines.append("")
                lines.append("[[rules]]")
                lines.append(f'id = "{self.id}:testkey:{tp.name}"')
                lines.append(f'description = "{self.display_name} test/sandbox key (public by design)"')
                lines.append(f"regex = '''{tp.regex}'''")
                # Reuse same path allowlist for testkey rules
                if self.allowlists.paths:
                    lines.append("  [[rules.allowlists]]")
                    paths = ", ".join(f"'''{x}'''" for x in self.allowlists.paths)
                    lines.append(f"  paths = [{paths}]")

        return "\n".join(lines) + "\n"


class RegistryError(Exception):
    pass


def _parse_pattern(d: dict, idx: int, service_id: str) -> Pattern:
    for required in ("name", "component", "regex"):
        if required not in d:
            raise RegistryError(f"{service_id} pattern #{idx}: missing '{required}'")
    if d["component"] not in ("id", "secret"):
        raise RegistryError(
            f"{service_id} pattern '{d['name']}': component must be 'id' or 'secret'"
        )
    try:
        re.compile(d["regex"])
    except re.error as exc:
        raise RegistryError(
            f"{service_id} pattern '{d['name']}': bad regex — {exc}"
        )
    return Pattern(
        name=d["name"],
        component=d["component"],
        regex=d["regex"],
        keywords=list(d.get("keywords", [])),
        secret_group=d.get("secret_group"),
    )


def _parse_testkey(d: dict, idx: int, service_id: str) -> TestKeyPattern:
    for required in ("name", "regex"):
        if required not in d:
            raise RegistryError(f"{service_id} testkey #{idx}: missing '{required}'")
    try:
        re.compile(d["regex"])
    except re.error as exc:
        raise RegistryError(
            f"{service_id} testkey '{d['name']}': bad regex — {exc}"
        )
    return TestKeyPattern(name=d["name"], regex=d["regex"])


def load_service(path: Path) -> Service:
    """Parse and validate one TOML file."""
    raw = tomllib.loads(path.read_text())
    if "service" not in raw:
        raise RegistryError(f"{path}: missing [service] table")
    s = raw["service"]
    for required in ("id", "display_name", "auth_class", "search_keywords"):
        if required not in s:
            raise RegistryError(f"{path}: [service] missing '{required}'")
    if s["auth_class"] not in ("single", "paired", "pub_priv"):
        raise RegistryError(
            f"{path}: auth_class must be 'single' | 'paired' | 'pub_priv'"
        )

    patterns = [
        _parse_pattern(p, i, s["id"]) for i, p in enumerate(raw.get("patterns", []))
    ]
    if not patterns:
        raise RegistryError(f"{path}: at least one [[patterns]] entry required")

    if s["auth_class"] == "paired":
        has_id = any(p.component == "id" for p in patterns)
        has_secret = any(p.component == "secret" for p in patterns)
        if not (has_id and has_secret):
            raise RegistryError(
                f"{path}: auth_class='paired' requires both 'id' and 'secret' patterns"
            )

    testkeys = [
        _parse_testkey(t, i, s["id"])
        for i, t in enumerate(raw.get("testkey_patterns", []))
    ]

    allow_raw = raw.get("allowlists", {})
    allowlists = Allowlists(
        paths=list(allow_raw.get("paths", [])),
        match_regexes=list(allow_raw.get("match_regexes", [])),
        secret_regexes=list(allow_raw.get("secret_regexes", [])),
    )

    return Service(
        id=s["id"],
        display_name=s["display_name"],
        auth_class=s["auth_class"],
        search_keywords=list(s["search_keywords"]),
        patterns=patterns,
        testkey_patterns=testkeys,
        allowlists=allowlists,
    )


def load_all(rules_dir: Path = RULES_DIR) -> dict[str, Service]:
    """Load every rules/*.toml. Raises RegistryError if any TOML is malformed."""
    if not rules_dir.is_dir():
        raise RegistryError(f"rules directory not found: {rules_dir}")
    services: dict[str, Service] = {}
    for toml_path in sorted(rules_dir.glob("*.toml")):
        svc = load_service(toml_path)
        if svc.id in services:
            raise RegistryError(f"duplicate service id '{svc.id}' in {toml_path}")
        services[svc.id] = svc
    if not services:
        raise RegistryError(f"no service TOMLs found in {rules_dir}")
    return services
