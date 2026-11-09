"""Immutable core: the paths a mutating agent must never write.

The immutable core is everything that *judges* an agent: the evaluator, the
evaluator's test suites, held-out data, sandbox configuration, policy files,
the tool allowlist, the memory-write policy, credentials, the promotion gate, the audit log, IAM, CI
rules, and the control-plane enforcement code itself (an agent that can edit
this registry could simply delete a pattern).

Evidence that motivates putting these out of the agent's write path:

* STOP (self-taught optimizer): 0.42% of 10k GPT-4 self-improvement proposals
  flipped ``use_sandbox=True`` to ``False``; a written warning in the prompt did
  not reduce the rate. Hence sandbox config is core and the forbid is code.
* Darwin Goedel Machine: the agent fabricated "tests passed" logs and removed
  hallucination-detection markers; only the lineage archive caught it. Hence
  the evaluator and audit store sit outside the agent's write path.

Path handling is fail-closed: anything that cannot be normalised to a path
inside the repository root (empty, NUL/control characters, ``..`` escape,
absolute outside ``repo_root``, home or drive prefixes, URLs, surrounding
whitespace) classifies as core. A directory that *contains* a root-anchored
core pattern (``src`` contains ``src/acgs_lite/control_plane/**``) is core as
well, because deleting or moving it destroys the core.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from acgs_lite._compat import StrEnum

__all__ = [
    "DEFAULT_IMMUTABLE_CORE",
    "CoreCategory",
    "ImmutableCoreError",
    "ImmutableCoreRegistry",
    "UNRESOLVABLE_PATH_CATEGORY",
    "compile_glob",
    "literal_prefix",
    "IMPORT_SHADOW_PATTERNS",
    "module_shadow_patterns",
    "normalize_path",
]

MANIFEST_VERSION = 1


class ImmutableCoreError(ValueError):
    """Raised when a registry or manifest is malformed."""


class CoreCategory(StrEnum):
    """Categories of the immutable core.

    Declaration order is the classification precedence: when a path matches
    patterns in several categories, the earliest category wins (for example
    ``.github/CODEOWNERS`` is ``IAM`` rather than ``CI_RULES``).
    """

    EVALUATOR = "evaluator"
    TEST_SUITE = "test_suite"
    HELDOUT_DATA = "heldout_data"
    SANDBOX_CONFIG = "sandbox_config"
    POLICY = "policy"
    TOOL_ALLOWLIST = "tool_allowlist"
    MEMORY_WRITE_POLICY = "memory_write_policy"
    CREDENTIALS = "credentials"
    PROMOTION_GATE = "promotion_gate"
    AUDIT_LOG = "audit_log"
    IAM = "iam"
    CI_RULES = "ci_rules"
    CONTROL_PLANE = "control_plane"


# A path that cannot be normalised is reported as CONTROL_PLANE: it is the
# most restrictive category (human-only change at tier >= T2), and an
# unresolvable path may point anywhere, including at the control plane.
UNRESOLVABLE_PATH_CATEGORY = CoreCategory.CONTROL_PLANE

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_WILDCARDS = "*?["


def normalize_path(path: object, repo_root: str | None = None) -> str | None:
    """Normalise *path* to a repo-relative POSIX path, or ``None`` if unsafe.

    ``None`` means "cannot be resolved inside the root"; callers must treat it
    as core (deny side). The repository root itself normalises to ``"."``.
    Symlinks are not resolved.
    """
    # TODO(control-plane-gap): symlinks are not resolved (no filesystem access
    # here); an agent-created symlink into the core must be blocked by the
    # sandbox filesystem layer, which Phase 1 does not provide.
    # Subclasses can override normalization methods while retaining a different
    # filesystem spelling when the original argument reaches the tool.
    if type(path) is not str or not path:
        return None
    if _CONTROL_CHARS.search(path) or path != path.strip():
        return None
    # Look-alike and encoded spellings (fullwidth letters, ligatures,
    # ``evaluator%2fx``) may be decoded downstream into a core path; refuse
    # rather than guess.
    if unicodedata.normalize("NFKC", path) != path or _PERCENT_ESCAPE.search(path):
        return None
    # Do not authorize a rewritten spelling while the tool receives the raw
    # path: backslashes and trailing dots/spaces are distinct names on POSIX.
    if "\\" in path:
        return None
    # A tool may create raw parent directories before resolving '..'. Deny
    # traversal before absolute normalization can erase the outside prefix.
    if ".." in path.split("/"):
        return None
    candidate = path
    if candidate.startswith("~") or _DRIVE_PREFIX.match(candidate) or "://" in candidate:
        return None
    if candidate.startswith("/"):
        if repo_root is None:
            return None
        root = posixpath.normpath(repo_root.replace("\\", "/"))
        absolute = posixpath.normpath(candidate)
        if absolute == root:
            return "."
        prefix = root.rstrip("/") + "/"
        if not absolute.startswith(prefix):
            return None
        candidate = absolute[len(prefix) :]
    # Reject ambiguous Windows/SMB aliases instead of rewriting their names.
    segments = []
    for segment in candidate.split("/"):
        if segment in ("", "."):
            segments.append(segment)
            continue
        stripped = segment.rstrip(". ")
        if not stripped or stripped != segment:
            return None
        segments.append(stripped)
    normalized = posixpath.normpath("/".join(segments))
    if normalized == ".." or normalized.startswith("../") or normalized.startswith("/"):
        return None
    return normalized


def compile_glob(pattern: str, *, case_sensitive: bool = False) -> re.Pattern[str]:
    """Compile a repo glob into a full-match regex.

    Core classification defaults to conservative case-insensitive matching;
    permission grants use case-sensitive matching to avoid widening authority
    to distinct filesystem paths.

    Semantics (deliberately not :mod:`fnmatch`, whose ``*`` crosses ``/``):

    * ``*`` matches within one path segment; ``?`` one non-``/`` character.
    * ``**/`` at a segment start matches zero or more directories.
    * a trailing ``/**`` matches the directory itself and everything below it.
    * a bare ``**`` matches everything.
    * ``[...]`` is a character class (``[!...]`` negates); an unclosed ``[`` is
      literal.
    * patterns are anchored at the repository root.
    """
    # TODO(control-plane-gap): case-insensitive matching is a design inference
    # to survive case-folding filesystems (macOS/Windows); no primary evidence
    # that agents exploit case, and CODEOWNERS on GitHub is case-sensitive.
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        at_segment_start = i == 0 or pattern[i - 1] == "/"
        if pattern == "**":
            out.append(".*")
            break
        if at_segment_start and pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
            continue
        if pattern.startswith("/**", i) and i + 3 == n:
            out.append("(?:/.*)?")
            i += 3
            continue
        char = pattern[i]
        if char == "*":
            while i < n and pattern[i] == "*":
                i += 1
            out.append("[^/]*")
            continue
        if char == "?":
            out.append("[^/]")
            i += 1
            continue
        if char == "[":
            close = pattern.find("]", i + 2)
            if close == -1:
                out.append(re.escape(char))
                i += 1
                continue
            body = pattern[i + 1 : close]
            body = body.replace("\\", "\\\\")
            if body.startswith("!"):
                body = "^" + body[1:]
            elif body.startswith("^"):
                body = "\\" + body
            # Negated classes otherwise include '/', and ranges can include
            # it implicitly. Every class must remain inside one segment.
            out.append("(?!/)[" + body + "]")
            i = close + 1
            continue
        out.append(re.escape(char))
        i += 1
    flags = re.DOTALL if case_sensitive else re.IGNORECASE | re.DOTALL
    return re.compile("".join(out), flags)


def literal_prefix(pattern: str) -> str:
    """Return the part of *pattern* before its first wildcard, lower-cased."""
    cut = len(pattern)
    for wildcard in _WILDCARDS:
        index = pattern.find(wildcard)
        if index != -1:
            cut = min(cut, index)
    return pattern[:cut].lower()


def module_shadow_patterns(pattern: str) -> tuple[str, ...]:
    """Globs for files that Python would import *instead of* the module *pattern*.

    For a literal ``dir/name.py`` entry, CPython's path finder prefers a
    package directory ``dir/name/`` and extension modules ``dir/name.*.so``,
    and an unchecked-hash ``__pycache__`` entry can replace the source. All
    of them run in place of the protected module, so they are core too.
    Wildcard patterns already cover their own directory and return ``()``.
    """
    if literal_prefix(pattern) != pattern.lower() or not pattern.lower().endswith(".py"):
        return ()
    directory, base = posixpath.split(pattern)
    stem = base[: -len(".py")]
    if not stem:
        return ()
    prefix = directory + "/" if directory else ""
    shadows = [f"{prefix}{stem}.*", f"{prefix}__pycache__/{stem}.*"]
    if stem != "__init__":
        shadows.append(f"{prefix}{stem}/**")
    return tuple(shadows)


_STARTUP_HOOKS = frozenset({"sitecustomize", "usercustomize"})
IMPORT_SHADOW_PATTERNS = (
    "*.py",
    "*.pyc",
    "*.so",
    "*.pyd",
    "*/__init__.py",
    "*/__init__.pyc",
    "*/__init__*.so",
    "*/__init__*.pyd",
    "**/conftest.py",
    "src/*.py",
    "**/sitecustomize*",
    "**/sitecustomize*/**",
    "**/usercustomize*",
    "**/usercustomize*/**",
    "**/*.pth",
)


def _validate_pattern(pattern: object) -> str:
    if not isinstance(pattern, str) or not pattern.strip():
        raise ImmutableCoreError("core patterns must be non-empty strings")
    if pattern != pattern.strip() or _CONTROL_CHARS.search(pattern):
        raise ImmutableCoreError(f"core pattern has whitespace/control characters: {pattern!r}")
    cleaned = pattern[2:] if pattern.startswith("./") else pattern
    if cleaned.startswith("/") or "\\" in cleaned:
        raise ImmutableCoreError(f"core pattern must be relative POSIX: {pattern!r}")
    if any(segment in ("..", ".") for segment in cleaned.split("/")):
        raise ImmutableCoreError(f"core pattern must not contain '.' or '..': {pattern!r}")
    return cleaned


class ImmutableCoreRegistry:
    """Immutable mapping of :class:`CoreCategory` to repo globs."""

    __slots__ = (
        "_entries",
        "_shadows",
        "_compiled",
        "_anchored_prefixes",
        "_repo_root",
        "_src_packages",
    )

    _entries: tuple[tuple[CoreCategory, tuple[str, ...]], ...]
    _shadows: tuple[tuple[CoreCategory, tuple[str, ...]], ...]
    _src_packages: frozenset[str] | None
    _compiled: tuple[tuple[CoreCategory, tuple[re.Pattern[str], ...]], ...]
    _anchored_prefixes: tuple[tuple[CoreCategory, tuple[str, ...]], ...]
    _repo_root: str | None

    def __init__(
        self,
        patterns: Mapping[Any, Iterable[str]],
        *,
        repo_root: str | None = None,
    ) -> None:
        by_category: dict[CoreCategory, set[str]] = {category: set() for category in CoreCategory}
        for raw_category, raw_patterns in patterns.items():
            try:
                category = CoreCategory(raw_category)
            except ValueError as exc:
                raise ImmutableCoreError(f"unknown core category: {raw_category!r}") from exc
            if isinstance(raw_patterns, str):
                raise ImmutableCoreError("category patterns must be a list, not a string")
            by_category[category].update(_validate_pattern(p) for p in raw_patterns)
        if repo_root is not None and (
            not isinstance(repo_root, str) or not repo_root.replace("\\", "/").startswith("/")
        ):
            raise ImmutableCoreError("repo_root must be an absolute POSIX path")
        entries = tuple(
            (category, tuple(sorted(by_category[category]))) for category in CoreCategory
        )
        shadows = tuple(
            (
                category,
                tuple(sorted({s for p in pats for s in module_shadow_patterns(p)} - set(pats))),
            )
            for category, pats in entries
        )
        object.__setattr__(self, "_entries", entries)
        object.__setattr__(self, "_shadows", shadows)
        object.__setattr__(
            self,
            "_compiled",
            tuple(
                (cat, tuple(compile_glob(p) for p in (*pats, *shadow_pats)))
                for (cat, pats), (_, shadow_pats) in zip(entries, shadows, strict=True)
            ),
        )
        object.__setattr__(
            self,
            "_anchored_prefixes",
            tuple(
                (cat, tuple(literal_prefix(p) for p in pats if literal_prefix(p)))
                for cat, pats in entries
            ),
        )
        object.__setattr__(self, "_repo_root", repo_root)
        # Trusted modules under src/ make src/ an import root (PYTHONPATH=src),
        # so anything else importable from there can shadow them or the stdlib.
        src_packages = frozenset(
            p.lower().split("/")[1]
            for _, pats in entries
            for p in pats
            if module_shadow_patterns(p) and p.lower().startswith("src/") and p.count("/") >= 2
        )
        object.__setattr__(self, "_src_packages", src_packages or None)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ImmutableCoreRegistry is immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ImmutableCoreRegistry):
            return NotImplemented
        return self._entries == other._entries and self._repo_root == other._repo_root

    def __hash__(self) -> int:
        return hash((self._entries, self._repo_root))

    def __repr__(self) -> str:
        count = sum(len(pats) for _, pats in self._entries)
        return f"ImmutableCoreRegistry(patterns={count}, repo_root={self._repo_root!r})"

    @property
    def repo_root(self) -> str | None:
        return self._repo_root

    def with_repo_root(self, repo_root: str | None) -> ImmutableCoreRegistry:
        """Return a copy that relativises absolute paths against *repo_root*."""
        return ImmutableCoreRegistry(self.patterns(), repo_root=repo_root)

    def patterns(self) -> Mapping[CoreCategory, tuple[str, ...]]:
        """Return a read-only ``{category: sorted patterns}`` view."""
        return MappingProxyType(dict(self._entries))

    def shadow_patterns(self) -> Mapping[CoreCategory, tuple[str, ...]]:
        """Return the derived ``{category: globs}`` for module shadows
        (see :func:`module_shadow_patterns`); they are core like the
        :meth:`patterns` they derive from, but are not part of the manifest."""
        return MappingProxyType(dict(self._shadows))

    def import_shadow_patterns(self) -> tuple[str, ...]:
        """CODEOWNERS-expressible globs of :meth:`_import_shadow` (the
        ``src/<other>/`` rule has no glob form and is enforced in code)."""
        if self._src_packages is None:
            return ()
        return IMPORT_SHADOW_PATTERNS

    def _import_shadow(self, normalized: str) -> bool:
        """Paths that change what the trusted import closure executes:
        ``sitecustomize``/``usercustomize``, ``*.pth`` and ``conftest.py``
        anywhere, any repo-root module or package initializer, any
        top-level ``src/*.py`` (``src/json.py`` shadows the stdlib under
        PYTHONPATH=src) and any ``src/<entry>`` that is not a trusted package."""
        if self._src_packages is None:
            return False
        segments = normalized.lower().split("/")
        if any(seg.split(".", 1)[0] in _STARTUP_HOOKS for seg in segments):
            return True
        if segments[-1].endswith(".pth"):
            return True
        if segments[-1] == "conftest.py":
            # pytest imports every conftest on its collection path; one can
            # neuter `make verify` / CI.
            return True
        importable = segments[-1].endswith((".py", ".pyc", ".so", ".pyd"))
        if importable and (
            len(segments) == 1
            or (len(segments) == 2 and segments[-1].split(".", 1)[0] == "__init__")
        ):
            # The repo root is on sys.path (`python -m pytest`, PYTHONPATH=.):
            # modules and package initializers can shadow trusted imports.
            return True
        return (
            segments[0] == "src" and len(segments) >= 2 and (segments[1] not in self._src_packages)
        )

    def normalize(self, path: object) -> str | None:
        return normalize_path(path, self._repo_root)

    def classify(self, path: object) -> CoreCategory | None:
        """Return the core category of *path*, or ``None`` if it is not core.

        Only the highest-precedence category is returned; enforcement that
        depends on *which* category applies must use :meth:`categories`.
        """
        normalized = self.normalize(path)
        if normalized is None:
            return UNRESOLVABLE_PATH_CATEGORY
        by_pattern, by_prefix = self._matches(normalized)
        for found in (by_pattern, by_prefix):
            for category in CoreCategory:
                if category in found:
                    return category
        return None

    def categories(self, path: object) -> frozenset[CoreCategory]:
        """Return *every* core category *path* falls in (empty if not core).

        ``policies/.env`` is both ``POLICY`` and ``CREDENTIALS``; a check
        that looks only at the first category would lose the credential
        restriction.
        """
        normalized = self.normalize(path)
        if normalized is None:
            return frozenset({UNRESOLVABLE_PATH_CATEGORY})
        by_pattern, by_prefix = self._matches(normalized)
        return by_pattern | by_prefix

    def _matches(self, normalized: str) -> tuple[frozenset[CoreCategory], frozenset[CoreCategory]]:
        """(categories whose globs match, categories with a pattern below it)."""
        if normalized == ".":
            return frozenset(category for category, pats in self._entries if pats), frozenset()
        by_pattern = frozenset(
            category
            for category, regexes in self._compiled
            if any(regex.fullmatch(normalized) for regex in regexes)
        )
        if self._import_shadow(normalized):
            by_pattern |= {CoreCategory.CONTROL_PLANE}
        directory = normalized.lower() + "/"
        by_prefix = frozenset(
            category
            for category, prefixes in self._anchored_prefixes
            if any(prefix.startswith(directory) for prefix in prefixes)
        )
        return by_pattern, by_prefix

    def is_core(self, path: object) -> bool:
        return self.classify(path) is not None

    def has_unanchored_patterns(self) -> bool:
        """True if any pattern starts with a wildcard (e.g. ``**/.env*``), so
        that core files may exist under *any* directory."""
        return any(not literal_prefix(p) for _, pats in self._entries for p in pats)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": MANIFEST_VERSION,
            "categories": {category.value: list(pats) for category, pats in self._entries},
        }

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, Any], *, repo_root: str | None = None
    ) -> ImmutableCoreRegistry:
        """Build from ``{"version": 1, "categories": {name: [globs]}}``.

        Strict: unknown keys, an unknown version, unknown categories and
        missing categories all raise (a silently dropped category would
        silently un-protect paths).
        """
        if not isinstance(data, Mapping):
            raise ImmutableCoreError("manifest must be a mapping")
        unknown = set(data) - {"version", "categories"}
        if unknown:
            raise ImmutableCoreError(f"unknown manifest keys: {sorted(unknown)}")
        if data.get("version") != MANIFEST_VERSION:
            raise ImmutableCoreError(f"manifest version must be {MANIFEST_VERSION}")
        categories = data.get("categories")
        if not isinstance(categories, Mapping):
            raise ImmutableCoreError("manifest categories must be a mapping")
        missing = {category.value for category in CoreCategory} - set(categories)
        if missing:
            raise ImmutableCoreError(f"manifest is missing categories: {sorted(missing)}")
        for name, pats in categories.items():
            if not isinstance(pats, list):
                raise ImmutableCoreError(f"category {name!r} must be a list")
        return cls(categories, repo_root=repo_root)

    @classmethod
    def from_yaml_str(cls, text: str, *, repo_root: str | None = None) -> ImmutableCoreRegistry:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ImmutableCoreError(f"manifest is not valid YAML: {exc}") from exc
        return cls.from_mapping(data, repo_root=repo_root)

    @classmethod
    def from_yaml(cls, path: str | Path, *, repo_root: str | None = None) -> ImmutableCoreRegistry:
        return cls.from_yaml_str(Path(path).read_text(encoding="utf-8"), repo_root=repo_root)


# TODO(control-plane-gap): this default glob list is a design inference for a
# typical self-improving-agent repo layout, not derived from primary evidence.
# Deployments must supply their own manifest (control-plane/immutable-core.yaml).
DEFAULT_IMMUTABLE_CORE = ImmutableCoreRegistry(
    {
        CoreCategory.EVALUATOR: ("evaluator/**", "evals/**", "src/acgs_lite/evals/**"),
        CoreCategory.TEST_SUITE: ("eval_suites/**", "eval-suites/**", "test_suites/**"),
        CoreCategory.HELDOUT_DATA: (
            "heldout/**",
            "held_out/**",
            "data/heldout/**",
            "data/held_out/**",
        ),
        CoreCategory.SANDBOX_CONFIG: ("sandbox/**", "config/sandbox*", "config/sandbox*/**"),
        CoreCategory.POLICY: (
            "policies/**",
            "policy/**",
            # Phase 5: runbooks pre-authorise T1 actions, so they are policy
            # (POLICY precedes CONTROL_PLANE, so this wins over control-plane/**).
            "control-plane/runbooks/**",
            "**/constitution*.yaml",
            "**/constitution*.yml",
            "**/constitution*.json",
            "**/constitution*.toml",
        ),
        CoreCategory.TOOL_ALLOWLIST: ("**/tool_allowlist*", "**/tool-allowlist*"),
        # What an agent may persist into long-term memory decides what it
        # learns from; editing that policy is a human-only change (Phase 3).
        CoreCategory.MEMORY_WRITE_POLICY: (
            "**/memory_write_policy*",
            "**/memory-write-policy*",
            "memory-policy/**",
            "memory_policy/**",
        ),
        CoreCategory.CREDENTIALS: ("secrets/**", "credentials/**", "**/.env*"),
        CoreCategory.PROMOTION_GATE: ("promotion/**",),
        CoreCategory.AUDIT_LOG: ("audit/**", "audit_logs/**"),
        CoreCategory.IAM: ("iam/**", "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"),
        CoreCategory.CI_RULES: (
            ".github/**",
            ".gitlab-ci.yml",
            ".pre-commit-config.yaml",
            "Makefile",
            # CI installs this input; requirement entries can execute build code.
            "requirements-test-optional.txt",
            # Directly executed trusted scripts put this directory first on
            # sys.path. Sibling modules, packages and native extensions can
            # replace any dependency imported by a release or validation gate.
            "scripts/**",
            "scripts/check_critical_coverage.py",
            "scripts/release_candidate.py",
            "scripts/qualify_wheel.py",
            "scripts/run_governance_regression.py",
            "scripts/check_links.py",
            "scripts/check_release_coherence.py",
            # The regression runner executes package initializers and red-team code.
            "tests/__init__.py",
            "tests/red_team/**",
            # Pytest searches the argument directory before repository parents.
            "pytest.toml",
            ".pytest.toml",
            "pytest.ini",
            ".pytest.ini",
            "tox.ini",
            "setup.cfg",
            "tests/**/pytest.toml",
            "tests/**/.pytest.toml",
            "tests/**/pytest.ini",
            "tests/**/.pytest.ini",
            "tests/**/pyproject.toml",
            "tests/**/tox.ini",
            "tests/**/setup.cfg",
        ),
        CoreCategory.CONTROL_PLANE: (
            "control-plane/**",
            "src/acgs_lite/control_plane/**",
            "src/acgs_lite/integrations/control_plane_mcp.py",
            "scripts/check_immutable_core_diff.py",
            "scripts/render_codeowners.py",
            "tests/control_plane/**",
            # Trusted computing base: everything the PDP/dispatcher import
            # closure executes (tests/control_plane/test_immutable_core.py
            # walks the closure and fails if a module is missing here), plus
            # the build/test configuration that decides which code runs.
            # TODO(control-plane-gap): non-Python data read at import time is
            # only covered where listed; the closure test sees modules only.
            "src/acgs_lite/__init__.py",
            "src/acgs_lite/_compat.py",
            "src/acgs_lite/_meta.py",
            "src/acgs_lite/audit.py",
            "src/acgs_lite/circuit_breaker.py",
            # CI invokes the CLI capability gate; these imports execute eagerly.
            "src/acgs_lite/cli.py",
            "src/acgs_lite/commands/**",
            "src/acgs_lite/arckit/**",
            "src/acgs_lite/cdp/**",
            "src/acgs_lite/observability/__init__.py",
            "src/acgs_lite/observability/session_observer.py",
            "src/acgs_lite/constrained_output.py",
            "src/acgs_lite/errors.py",
            "src/acgs_lite/events.py",
            "src/acgs_lite/fail_closed.py",
            "src/acgs_lite/governed.py",
            "src/acgs_lite/lean_verify.py",
            "src/acgs_lite/licensing.py",
            "src/acgs_lite/production.py",
            "src/acgs_lite/provenance.py",
            "src/acgs_lite/provider_capabilities.py",
            "src/acgs_lite/provider_capabilities_manifest.json",
            "src/acgs_lite/scoring.py",
            "src/acgs_lite/serialization.py",
            "src/acgs_lite/trajectory.py",
            "src/acgs_lite/z3_verify.py",
            "src/acgs_lite/agents/**",
            "src/acgs_lite/constitution/**",
            "src/acgs_lite/engine/**",
            "src/acgs_lite/formal/**",
            "src/acgs_lite/legitimacy/**",
            "src/acgs_lite/maci/**",
            "src/acgs_lite/policygen/**",
            "src/acgs_lite/integrations/__init__.py",
            # The Python engine imports the native companion built by CI.
            # Protect its whole Cargo workspace and repository build overrides.
            "rust/**",
            ".cargo/**",
            "rust-toolchain",
            "rust-toolchain.toml",
            "pyproject.toml",
            "uv.lock",
            "tests/conftest.py",
        ),
    }
)
