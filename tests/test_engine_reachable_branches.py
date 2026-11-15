"""Boundary-input tests for pure-Python engine branches.

Covers the legacy audit shims in ``acgs_lite.engine.types``, lazy loading in
``acgs_lite.engine``, matcher mixin stubs, and GovernanceEngine decision paths
that run without the Rust companion or Aho-Corasick.
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

import acgs_lite.engine as engine_pkg
from acgs_lite.audit import AuditEntry
from acgs_lite.constitution.constitution import Constitution
from acgs_lite.constitution.rule import Rule, Severity
from acgs_lite.engine import audit_runtime as engine_audit_runtime
from acgs_lite.engine import types as engine_types
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.engine.matcher import GovernanceMatcherMixin
from acgs_lite.errors import ConstitutionalViolationError

# --- A. audit shims, duplicated in acgs_lite.engine.audit_runtime and .types ----

_AUDIT_MODULES = pytest.mark.parametrize(
    "mod",
    [engine_audit_runtime, engine_types],
    ids=["audit_runtime", "types"],
)


@_AUDIT_MODULES
def test_noop_recorder_counts_appends(mod: ModuleType) -> None:
    r = mod._NoopRecorder()
    assert len(r) == 0
    r.append(object())
    r.append(None)
    assert len(r) == 2


@_AUDIT_MODULES
def test_fast_audit_log_entries_reconstruct(mod: ModuleType) -> None:
    log = mod._FastAuditLog("HASH1")
    assert len(log) == 0
    log.record_fast(
        "req-1", "agent-a", "deploy x", False, ["R-1"], "HASH1", 1.5, "2026-01-01T00:00:00"
    )
    # Compact allow record: the 2-tuple (request_id, action) shape defined in
    # the _FastAuditLog docstring.
    log._records.append(("req-2", "read y"))

    entries = log.entries

    assert len(entries) == 2
    assert all(isinstance(e, AuditEntry) for e in entries)
    deny, allow = entries
    assert deny.id == "req-1"
    assert deny.agent_id == "agent-a"
    assert deny.action == "deploy x"
    assert deny.valid is False
    assert deny.violations == ["R-1"]
    assert deny.constitutional_hash == "HASH1"
    assert deny.latency_ms == 1.5
    assert allow.id == "req-2"
    assert allow.agent_id == "anonymous"
    assert allow.action == "read y"
    assert allow.valid is True
    assert allow.violations == []
    assert allow.constitutional_hash == "HASH1"


@_AUDIT_MODULES
def test_fast_audit_log_record_shim(mod: ModuleType) -> None:
    log = mod._FastAuditLog("H")
    entry = AuditEntry(
        id="r3",
        type="validation",
        agent_id="b",
        action="x",
        valid=True,
        violations=[],
        constitutional_hash="H",
        latency_ms=0.0,
        timestamp="",
    )
    assert log.record(entry) == ""
    assert len(log) == 1
    assert log.entries[-1].agent_id == "b"
    assert "_FastAuditLog" in mod.__all__
    assert "_NoopRecorder" in mod.__all__


# --- B. engine package lazy loading and matcher stubs ---------------------------


def test_lazy_submodule_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(engine_pkg, "types", raising=False)
    assert "types" not in vars(engine_pkg)

    loaded = engine_pkg.types

    assert loaded is importlib.import_module("acgs_lite.engine.types")
    assert "types" in vars(engine_pkg)


def test_unknown_attribute_raises() -> None:
    with pytest.raises(AttributeError, match="has no attribute 'definitely_missing'"):
        engine_pkg.definitely_missing  # noqa: B018


def test_dir_lists_exports_and_submodules() -> None:
    names = dir(engine_pkg)
    assert {"GovernanceEngine", "Severity", "types", "models"} <= set(names)
    assert names == sorted(names)


def test_matcher_mixin_requires_host_overrides() -> None:
    m = GovernanceMatcherMixin()
    with pytest.raises(NotImplementedError):
        m._new_fast_allow_result()
    with pytest.raises(NotImplementedError):
        m._new_fast_result(valid=True, violations=[], action="x")


# --- C. GovernanceEngine boundary inputs on the Python-regex path ---------------

_SECRET_TEXT = "run job printing password sk-abcdefgh1"
_CLEAN_TEXT = "run job printing report"

PW = Rule(id="R-PW", text="no passwords", severity=Severity.HIGH, keywords=["password"])
PAT_CRIT = Rule(
    id="R-PAT", text="no secrets", severity=Severity.CRITICAL, patterns=[r"sk-[a-z0-9]{8}"]
)
PAT_HIGH = Rule(id="R-PAT", text="no secrets", severity=Severity.HIGH, patterns=[r"sk-[a-z0-9]{8}"])
DEL = Rule(id="R-DEL", text="no deletes", severity=Severity.HIGH, keywords=["delete"])


def test_invalid_audit_mode_rejected() -> None:
    with pytest.raises(ValueError, match="audit_mode must be 'fast' or 'full'"):
        GovernanceEngine(Constitution.default(), audit_mode="bogus")  # type: ignore[arg-type]


def test_positive_verb_duplicate_keyword_reported_once() -> None:
    engine = GovernanceEngine(Constitution.from_rules([PW]), strict=False)

    result = engine.validate("run job printing password and password")

    assert result.valid is False
    assert [v.rule_id for v in result.violations] == ["R-PW"]
    assert GovernanceEngine(Constitution.from_rules([PW]), strict=False).validate(_CLEAN_TEXT).valid


def test_positive_verb_critical_pattern_blocks() -> None:
    engine = GovernanceEngine(Constitution.from_rules([PW, PAT_CRIT]), strict=True)

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        engine.validate(_SECRET_TEXT)

    assert exc_info.value.rule_id == "R-PAT"
    clean = GovernanceEngine(Constitution.from_rules([PW, PAT_CRIT]), strict=True)
    result = clean.validate(_CLEAN_TEXT)
    assert result.valid is True
    assert result.violations == []


def test_positive_verb_pattern_reported_non_strict() -> None:
    engine = GovernanceEngine(Constitution.from_rules([PW, PAT_HIGH]), strict=False)

    result = engine.validate(_SECRET_TEXT)

    assert result.valid is False
    assert {v.rule_id for v in result.violations} == {"R-PW", "R-PAT"}
    clean = engine.validate(_CLEAN_TEXT)
    assert clean.valid is True
    assert clean.violations == []


def test_keyword_then_critical_pattern_blocks() -> None:
    engine = GovernanceEngine(Constitution.from_rules([DEL, PAT_CRIT]), strict=True)

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        engine.validate("please delete sk-abcdefgh1")

    assert exc_info.value.rule_id == "R-PAT"
    result = engine.validate(_CLEAN_TEXT)
    assert result.valid is True
    assert result.violations == []


# --- D. runtime-rule-filtering path ---------------------------------------------

COND = Rule(
    id="R-COND",
    text="no deletes in prod",
    severity=Severity.HIGH,
    keywords=["delete"],
    condition={"env": "prod"},
)


def _exploding_validator(action: str, ctx: dict) -> list:  # noqa: ARG001
    raise RuntimeError("validator exploded")


def test_context_detail_scanned_other_keys_skipped() -> None:
    engine = GovernanceEngine(Constitution.from_rules([COND]), strict=False)

    result = engine.validate(
        "tidy files",
        context={"env": "prod", "action_detail": "delete records", "note": "delete everything"},
    )

    assert result.valid is False
    hits = [v for v in result.violations if v.rule_id == "R-COND"]
    assert len(hits) == 1
    assert hits[0].matched_content.startswith("context[action_detail]")
    clean = engine.validate("tidy files", context={"env": "prod", "action_detail": "list records"})
    assert clean.valid is True


def test_raising_custom_validator_fails_closed_non_strict() -> None:
    engine = GovernanceEngine(
        Constitution.from_rules([COND]), strict=False, custom_validators=[_exploding_validator]
    )

    result = engine.validate("tidy files", context={"env": "prod"})

    assert result.valid is False
    errors = [v for v in result.violations if v.rule_id == "CUSTOM-ERROR"]
    assert len(errors) == 1
    assert errors[0].severity is Severity.HIGH
    assert "validator exploded" in errors[0].rule_text


def test_raising_custom_validator_blocks_strict() -> None:
    engine = GovernanceEngine(
        Constitution.from_rules([COND]), strict=True, custom_validators=[_exploding_validator]
    )

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        engine.validate("tidy files", context={"env": "prod"})

    assert exc_info.value.rule_id == "CUSTOM-ERROR"
