# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Manifest capability adapter -- evidence-only dependency scanning.

:func:`scan_manifests` performs a static, offline scan of a project's dependency
manifests (``pyproject.toml``, ``requirements.txt``, ``package.json``) and maps
known package names onto governance *risk areas* understood by
:class:`~acgs_lite.policygen.research.PolicyResearcher`.

**This module produces evidence for policy proposal, never granted capability.**
The presence of a package such as ``stripe`` or ``boto3`` in a manifest is a
*signal* that a project may touch a risk area (payments, cloud infrastructure,
...) -- it is not proof the code exercises that capability, and it must never be
treated as an authorization, activation, or grant of any kind. Callers remain
responsible for routing the resulting :class:`~acgs_lite.policygen.context.PreContext`
through the normal policy-generation and human-review pipeline like any other
research input.

Hard constraints (do not relax without updating this docstring and the tests):

* Static text/JSON/TOML parsing only. This module never imports, introspects,
  executes, or otherwise loads target-project code or any discovered package.
* No lifecycle or activation wiring lives here or is imported here. Scanning a
  manifest never activates anything.
* Unknown (unmapped) packages are always reported explicitly via
  :attr:`ManifestScanResult.unknown` -- they are never silently dropped.
* :data:`CAPABILITY_MAP` is a single literal, versioned mapping in this module
  so it stays reviewable; the adapter never hand-sets ``risk_level`` -- that is
  left entirely to :class:`~acgs_lite.policygen.context.PreContextBuilder`'s
  existing classification logic.
* Deterministic: no network access, no wall-clock reads, no randomness; all
  output sequences are sorted.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from acgs_lite.policygen.context import PreContext, PreContextBuilder

# --- Capability map ----------------------------------------------------------------
# Package name (lowercase, normalized "-"/"_") -> risk-area key understood by
# acgs_lite.policygen.research.PolicyResearcher's knowledge base. Every value here
# MUST be a key present in that knowledge base (enforced by a zero-gaps test).
#
# Rationale per group:
#   - stripe                                          -> "financial"       (payments SDK)
#   - langchain*, openai, anthropic, litellm,
#     llama-index-core                                -> "transparency"    (these packages
#     drive automated, LLM-based decision-making; the KB's "transparency" entry
#     requires disclosure of automated decision-making, the closest real vocabulary
#     match -- there is no dedicated "llm"/"tooling" KB key).
#   - psycopg, psycopg2, sqlalchemy, pymongo          -> "data-deletion"   (direct DB
#     write/DDL access; the KB has no dedicated "database" key, and "data-deletion"
#     -- delete/drop/truncate without approval -- is the closest real match for raw
#     database drivers/ORMs).
#   - httpx, requests, aiohttp                        -> "network-egress" (exact KB key)
#   - pyjwt, cryptography, passlib                    -> "secrets"         (token/private
#     key/password-hash handling; the KB's "secrets" entry explicitly lists access
#     tokens and private keys, a closer match than "authentication", which is about
#     bypassing auth rather than handling credential material).
#   - boto3, google-cloud-*                           -> "production-deploy" (cloud SDKs
#     that can mutate live infrastructure; the KB has no dedicated "cloud" key, and
#     "production-deploy" -- mutate live infrastructure without approval -- is the
#     closest real match). google-cloud-* entries are exact package names, no globs.
_CAPABILITY_MAP_DATA: dict[str, str] = {
    "stripe": "financial",
    "langchain": "transparency",
    "langchain-core": "transparency",
    "openai": "transparency",
    "anthropic": "transparency",
    "litellm": "transparency",
    "llama-index-core": "transparency",
    "psycopg": "data-deletion",
    "psycopg2": "data-deletion",
    "sqlalchemy": "data-deletion",
    "pymongo": "data-deletion",
    "httpx": "network-egress",
    "requests": "network-egress",
    "aiohttp": "network-egress",
    "pyjwt": "secrets",
    "cryptography": "secrets",
    "passlib": "secrets",
    "boto3": "production-deploy",
    "google-cloud-storage": "production-deploy",
    "google-cloud-bigquery": "production-deploy",
    "google-cloud-pubsub": "production-deploy",
    "google-cloud-compute": "production-deploy",
}

#: Immutable, module-level, versioned/reviewable capability map. Package name
#: (lowercase, "_" normalized to "-") -> risk-area key.
CAPABILITY_MAP: MappingProxyType[str, str] = MappingProxyType(_CAPABILITY_MAP_DATA)

_MAX_MANIFEST_BYTES = 5 * 1024 * 1024  # 5 MiB; manifests are small, untrusted text.

# PEP 508-ish leading name token: letters/digits, then letters/digits/._- , ending
# in a letter/digit. Deliberately permissive about what follows (version specs,
# extras, markers) since we only need the name.
_PEP508_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")

_REQ_IGNORE_PREFIXES = ("-r", "-e", "-c", "--", "#")

# Inline comments only count when "#" is preceded by start-of-line or whitespace
# (pip's own convention) -- this avoids mangling URL fragments such as
# "git+https://example.com/pkg.git#egg=pkg".
_INLINE_COMMENT_RE = re.compile(r"(?:^|\s)#.*$")


def _strip_comment(raw_line: str) -> str:
    match = _INLINE_COMMENT_RE.search(raw_line)
    if match:
        return raw_line[: match.start()].rstrip()
    return raw_line.rstrip()


@dataclass(slots=True, frozen=True)
class ManifestScanResult:
    """Result of a static, evidence-only manifest scan.

    ``matched`` and ``unknown`` are evidence -- signals that a package touching a
    known risk area (or an unrecognized package) is declared as a dependency.
    Neither implies the code actually uses that capability, and neither is ever
    treated as a granted capability by this module.
    """

    precontext: PreContext
    matched: tuple[tuple[str, str], ...]
    unknown: tuple[str, ...]
    manifests: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "precontext": self.precontext.to_dict(),
            "matched": [list(pair) for pair in self.matched],
            "unknown": list(self.unknown),
            "manifests": list(self.manifests),
        }


def _normalize(name: str) -> str:
    """Normalize a package name: strip, lowercase, "_" -> "-"."""
    return name.strip().lower().replace("_", "-")


def _read_manifest_text(path: Path) -> str:
    """Read manifest text with a size guard against pathological input files."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"Cannot read manifest file {path}: {exc}") from exc
    if size > _MAX_MANIFEST_BYTES:
        raise ValueError(
            f"Manifest file too large to parse safely: {path} ({size} bytes, "
            f"limit {_MAX_MANIFEST_BYTES} bytes)"
        )
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Manifest file {path} is not valid UTF-8 text: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Cannot read manifest file {path}: {exc}") from exc


def _extract_name(spec: str) -> str | None:
    """Extract the leading package-name token from a PEP 508-ish dependency spec."""
    spec = spec.strip()
    if not spec:
        return None
    match = _PEP508_NAME_RE.match(spec)
    if not match:
        return None
    return match.group(0)


def _load_toml_module() -> Any:
    """Lazily import a TOML parser: stdlib ``tomllib`` first, ``tomli`` fallback.

    Kept out of module scope so importing :mod:`acgs_lite.policygen.manifest` --
    and scanning package.json-only projects -- never requires either dependency.
    """
    try:
        import tomllib

        return tomllib
    except ImportError:
        pass
    try:
        import tomli

        return tomli
    except ImportError as exc:
        raise RuntimeError(
            "Parsing pyproject.toml requires Python 3.11+ (stdlib 'tomllib') or the "
            "'tomli' package installed for Python < 3.11. Install with: pip install tomli"
        ) from exc


def _parse_pyproject(path: Path) -> tuple[list[str], str | None]:
    """Return (dependency name tokens, project's own declared name) from pyproject.toml."""
    tomllib = _load_toml_module()
    text = _read_manifest_text(path)
    try:
        data = tomllib.loads(text)
    except Exception as exc:  # tomllib/tomli raise a TOMLDecodeError subclass
        raise ValueError(f"Malformed pyproject.toml at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Malformed pyproject.toml at {path}: expected a table at top level")

    project = data.get("project", {})
    if not isinstance(project, dict):
        raise ValueError(f"Malformed pyproject.toml at {path}: '[project]' must be a table")

    names: list[str] = []

    deps = project.get("dependencies", [])
    if not isinstance(deps, list):
        raise ValueError(
            f"Malformed pyproject.toml at {path}: 'project.dependencies' must be a list"
        )
    for spec in deps:
        name = _extract_name(str(spec))
        if name:
            names.append(name)

    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ValueError(
            f"Malformed pyproject.toml at {path}: 'project.optional-dependencies' must be a table"
        )
    for group_name, group_deps in optional.items():
        if not isinstance(group_deps, list):
            raise ValueError(
                f"Malformed pyproject.toml at {path}: "
                f"'project.optional-dependencies.{group_name}' must be a list"
            )
        for spec in group_deps:
            name = _extract_name(str(spec))
            if name:
                names.append(name)

    own_name = project.get("name")
    return names, own_name if isinstance(own_name, str) and own_name.strip() else None


def _parse_requirements(path: Path) -> tuple[list[str], list[str]]:
    """Return (parsed package names, raw unparsable tokens) from requirements.txt."""
    text = _read_manifest_text(path)
    names: list[str] = []
    unparsed: list[str] = []
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith(_REQ_IGNORE_PREFIXES) or "://" in line or line.startswith("git+"):
            unparsed.append(line)
            continue
        name = _extract_name(line)
        if name is None:
            unparsed.append(line)
            continue
        names.append(name)
    return names, unparsed


def _parse_package_json(path: Path) -> tuple[list[str], str | None]:
    """Return (dependency names, project's own declared name) from package.json."""
    text = _read_manifest_text(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed package.json at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Malformed package.json at {path}: expected a JSON object")

    names: list[str] = []
    for key in ("dependencies", "devDependencies"):
        deps = data.get(key, {})
        if deps is None:
            continue
        if not isinstance(deps, dict):
            raise ValueError(f"Malformed package.json at {path}: '{key}' must be an object")
        names.extend(str(name) for name in deps)

    own_name = data.get("name")
    return names, own_name if isinstance(own_name, str) and own_name.strip() else None


def scan_manifests(
    root: Path,
    *,
    domain: str = "scanned-project",
    description: str | None = None,
) -> ManifestScanResult:
    """Statically scan ``root`` for dependency manifests and derive a :class:`PreContext`.

    Evidence only: this never imports, introspects, or executes any manifest or
    discovered package, and never implies a granted capability -- it only maps
    declared package names onto risk areas for downstream policy research.

    Recognizes ``pyproject.toml`` (``[project.dependencies]`` +
    ``[project.optional-dependencies]``), ``requirements.txt``, and
    ``package.json`` (``dependencies`` + ``devDependencies``) if present directly
    under ``root``. Missing manifest types are simply skipped -- absence is not an
    error. A project's own declared name (from ``pyproject.toml``'s
    ``[project].name`` or ``package.json``'s ``name``) is excluded from matching
    so self-referential entries never inflate the results.

    Raises ``ValueError`` for malformed manifest files (never crashes through with
    an unrelated exception) and ``RuntimeError`` if ``pyproject.toml`` is present
    but neither ``tomllib`` nor ``tomli`` is importable.
    """
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"Manifest scan root is not a directory: {root}")

    manifests_found: list[str] = []
    raw_names: list[str] = []
    unknown_raw: list[str] = []
    self_names: set[str] = set()

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        manifests_found.append("pyproject.toml")
        names, own_name = _parse_pyproject(pyproject_path)
        raw_names.extend(names)
        if own_name:
            self_names.add(_normalize(own_name))

    requirements_path = root / "requirements.txt"
    if requirements_path.is_file():
        manifests_found.append("requirements.txt")
        names, unparsed = _parse_requirements(requirements_path)
        raw_names.extend(names)
        unknown_raw.extend(unparsed)

    package_json_path = root / "package.json"
    if package_json_path.is_file():
        manifests_found.append("package.json")
        names, own_name = _parse_package_json(package_json_path)
        raw_names.extend(names)
        if own_name:
            self_names.add(_normalize(own_name))

    matched: dict[str, str] = {}
    unknown: set[str] = set(unknown_raw)
    for raw_name in raw_names:
        normalized = _normalize(raw_name)
        if normalized in self_names:
            continue
        area = CAPABILITY_MAP.get(normalized)
        if area is None:
            unknown.add(raw_name)
            continue
        matched[normalized] = area

    matched_tuple = tuple(sorted(matched.items()))
    unknown_tuple = tuple(sorted(unknown))
    manifests_tuple = tuple(sorted(manifests_found))
    risk_areas = sorted({area for _, area in matched_tuple})

    if description is None:
        description = (
            f"Manifest evidence scan of: {', '.join(manifests_tuple)}."
            if manifests_tuple
            else "Manifest evidence scan found no supported manifest files."
        )

    builder = PreContextBuilder(domain=domain, description=description)
    if risk_areas:
        builder.add_risk_area(*risk_areas)
    # Leave risk_level classification entirely to the builder's existing,
    # deterministic logic -- this adapter never hand-sets risk_level.
    builder.infer()
    precontext = builder.build()

    return ManifestScanResult(
        precontext=precontext,
        matched=matched_tuple,
        unknown=unknown_tuple,
        manifests=manifests_tuple,
    )


__all__ = ["CAPABILITY_MAP", "ManifestScanResult", "scan_manifests"]
