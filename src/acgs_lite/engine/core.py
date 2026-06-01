"""Governance validation engine.

The engine evaluates actions against constitutional rules and produces
structured validation results. `GovernanceEngine` supports explicit `audit_mode="fast"`
    (aggregate counters only) and `audit_mode="full"` (durable `AuditLog` entries).

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from contextlib import contextmanager, suppress
from typing import Any, Literal

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import (
    _KW_NEGATIVE_RE,
    _NEGATIVE_VERBS_RE,
    _POSITIVE_VERBS_SET,
    Constitution,
    Rule,
    Severity,
)
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.errors import ConstitutionalViolationError

from .audit_runtime import _ANON, _FastAuditLog, _NoopRecorder, _request_counter
from .batch import BatchValidationMixin
from .enforcement import EnforcementResolution, resolve_enforcement
from .matcher import _HAS_AHO, _HAS_RUST, GovernanceMatcherMixin, _ac, _rust
from .models import CustomValidator, ValidationResult, Violation, _dedup_violations


class GovernanceEngine(BatchValidationMixin, GovernanceMatcherMixin):
    """Core governance validation engine."""

    __slots__ = (
        "constitution",
        "audit_log",
        "_fast_records",
        "custom_validators",
        "strict",
        "_const_hash",
        "_active_rules",
        "_rules_count",
        "_rule_data",
        "_pattern_rule_idxs",
        "_kw_to_idxs",
        "_combined_kw_re",
        "_combined_findall",
        "_neg_kw_re",
        "_neg_findall",
        "_rule_excs",
        "_combined_search",
        "_pat_anchor_search",
        "_pat_anchor_dispatch",
        "_no_anchor_patterns",
        "_ac_iter",
        "_has_high_rules",
        "_hot",
        "_rust_validator",
        "_rule_id_to_exc_idx",
        "_rule_id_to_wa",
        "_audit_mode",
        "_requires_runtime_rule_filtering",
    )

    def __init__(
        self,
        constitution: Constitution,
        *,
        audit_log: AuditLog | None = None,
        custom_validators: list[CustomValidator] | None = None,
        strict: bool = True,
        disable_gc: bool = False,
        audit_mode: Literal["fast", "full"] | None = None,
        warmup: bool = True,
        freeze_gc: bool = True,
    ) -> None:
        self.constitution = constitution
        effective_audit_mode = audit_mode or ("full" if audit_log is not None else "fast")
        if effective_audit_mode not in {"fast", "full"}:
            raise ValueError("audit_mode must be 'fast' or 'full'")
        if effective_audit_mode == "fast" and audit_log is not None:
            raise ValueError("audit_log cannot be provided when audit_mode='fast'")

        self._audit_mode = effective_audit_mode
        if effective_audit_mode == "full":
            self.audit_log: Any = audit_log if audit_log is not None else AuditLog()
            self._fast_records: Any = None
        else:
            self.audit_log = _FastAuditLog(constitution.hash)
            self._fast_records = _NoopRecorder()
        self.custom_validators = custom_validators if custom_validators is not None else []
        self.strict = strict
        self._requires_runtime_rule_filtering = any(
            rule.condition or rule.deprecated or rule.valid_from or rule.valid_until
            for rule in constitution.rules
        )
        self._const_hash: str = constitution.hash
        self._active_rules: list[Rule] = constitution.active_rules()
        self._rules_count: int = len(self._active_rules)
        _C = Severity.CRITICAL
        self._rule_data: list[tuple] = [
            (
                rule.id,
                rule.text,
                rule.severity,
                rule.severity.value,
                rule.category,
                # is_crit: True only for CRITICAL rules that are NOT overridden to WARN.
                # WARN rules must never early-exit, even at CRITICAL severity.
                rule.severity is _C and rule.workflow_action is not ViolationAction.WARN,
                f"Action blocked by rule {rule.id}: {rule.text}",
            )
            for rule in self._active_rules
        ]
        self._rule_excs: list[Any] = [
            ConstitutionalViolationError(err_msg, rule_id=rid, severity=rsev_val, action="")
            if is_crit
            else None
            for rid, _, _, rsev_val, _, is_crit, err_msg in self._rule_data
        ]
        self._rule_id_to_exc_idx: dict[str, int] = {
            rd[0]: i for i, rd in enumerate(self._rule_data) if self._rule_excs[i] is not None
        }
        # workflow_action lookup: rule_id → ViolationAction (for post-collection dispatch)
        self._rule_id_to_wa: dict[str, ViolationAction] = {
            rule.id: rule.workflow_action for rule in self._active_rules
        }

        kw_to_idxs: dict[str, list[tuple[int, bool]]] = defaultdict(list)
        for idx, rule in enumerate(self._active_rules):
            for kw in rule._kw_lower:  # type: ignore[attr-defined]
                kw_has_neg = bool(_KW_NEGATIVE_RE.search(kw))
                kw_to_idxs[kw].append((idx, kw_has_neg))

        _pattern_rule_idxs: list[tuple[int, Any]] = []
        _anchor_patterns: dict[str, list[tuple[int, Any]]] = defaultdict(list)
        _no_anchor_patterns: list[tuple[int, Any]] = []
        for idx, rule in enumerate(self._active_rules):
            for pat, pat_str in zip(
                rule._compiled_pats,
                rule.patterns,
                strict=True,
            ):
                _pattern_rule_idxs.append((idx, pat))
                cleaned = re.sub(
                    r"\\[bBdDsSwW]|\\.|\{[^}]*\}|\[[^\]]*\]|[.+*?^$|(){}]", " ", pat_str
                )
                words = re.findall(r"[a-z]{3,}", cleaned.lower())
                anchor = None
                for w in words:
                    if w not in ("the", "and", "for", "with"):
                        anchor = w
                        break
                if anchor and re.search(r"\{[0-9,]+\}", pat_str):
                    _stopwords4 = frozenset(("the", "and", "for", "with"))
                    for w in reversed(words):
                        if w not in _stopwords4:
                            anchor = w
                            break
                if anchor:
                    if re.fullmatch(r"\\b[a-z]+\\b", pat_str, re.IGNORECASE):
                        anchor = anchor + " "
                    elif re.fullmatch(r"\\b[a-z]+\.[a-z]+\\b", pat_str, re.IGNORECASE):
                        anchor = anchor + "-"
                    elif re.fullmatch(r"\\b[a-z]+\\s\+[a-z]+\\b", pat_str, re.IGNORECASE):
                        words2 = re.findall(r"[a-z]{2,}", cleaned.lower())
                        if len(words2) >= 2:
                            anchor = words2[0] + " " + words2[1]
                    _anchor_patterns[anchor].append((idx, pat))
                else:
                    _no_anchor_patterns.append((idx, pat))

        self._pattern_rule_idxs = _pattern_rule_idxs
        self._pat_anchor_dispatch: tuple = tuple(
            (anchor, pats) for anchor, pats in _anchor_patterns.items()
        )
        self._no_anchor_patterns = _no_anchor_patterns
        all_anchors = set(_anchor_patterns.keys())
        if all_anchors:
            self._pat_anchor_search = re.compile(
                "|".join(re.escape(a) for a in sorted(all_anchors, key=len, reverse=True))
            ).search
        else:
            self._pat_anchor_search = None

        self._kw_to_idxs: dict[str, tuple[tuple[int, bool], ...]] = {
            k: tuple(v) for k, v in kw_to_idxs.items()
        }

        if kw_to_idxs:
            sorted_kws = sorted(kw_to_idxs.keys(), key=len, reverse=True)
            self._combined_kw_re: re.Pattern[str] | None = re.compile(
                "|".join(re.escape(kw) for kw in sorted_kws)
            )
            self._combined_findall = self._combined_kw_re.findall
            self._combined_search = self._combined_kw_re.search

            neg_kws = sorted(
                (kw for kw in kw_to_idxs if _KW_NEGATIVE_RE.search(kw)),
                key=len,
                reverse=True,
            )
            if neg_kws:
                self._neg_kw_re: re.Pattern[str] | None = re.compile(
                    "|".join(re.escape(kw) for kw in neg_kws)
                )
                self._neg_findall = self._neg_kw_re.findall
            else:
                self._neg_kw_re = None
                self._neg_findall = None
        else:
            self._combined_kw_re = None
            self._combined_findall = None
            self._combined_search = None
            self._neg_kw_re = None
            self._neg_findall = None

        if _HAS_AHO and (kw_to_idxs or _anchor_patterns):
            _kw_frozen = self._kw_to_idxs
            _anchor_to_idx = {a: i for i, (a, _) in enumerate(self._pat_anchor_dispatch)}
            _automaton = _ac.Automaton()
            for kw, idxs in _kw_frozen.items():
                if kw in _anchor_to_idx:
                    _automaton.add_word(kw, (2, idxs, _anchor_to_idx[kw]))
                else:
                    _automaton.add_word(kw, (0, idxs))
            for anchor, ai in _anchor_to_idx.items():
                if anchor not in _kw_frozen:
                    _automaton.add_word(anchor, (1, ai))
            _automaton.make_automaton()
            self._ac_iter = _automaton.iter
        else:
            self._ac_iter = None

        self._has_high_rules: bool = any(r.severity.value == "high" for r in self._active_rules)

        self._hot: tuple = (
            self._ac_iter,
            self._pat_anchor_dispatch,
            self._no_anchor_patterns,
            self._rule_data,
            self._rule_excs,
            self._has_high_rules,
            self._fast_records,
            _POSITIVE_VERBS_SET,
            self._ac_iter is not None,
            isinstance(self._fast_records, _NoopRecorder),
            None,
        )
        if _HAS_RUST:
            _rust_anchor_dispatch = [
                (anchor, [(ri, pat.pattern) for ri, pat in pats])
                for anchor, pats in self._pat_anchor_dispatch
            ]
            _rust_no_anchor = [(ri, pat.pattern) for ri, pat in self._no_anchor_patterns]
            _rust_kw = {kw: list(idxs) for kw, idxs in self._kw_to_idxs.items()}
            _rust_rules = [
                (rid, rtxt, rsev_val, rcat, bool(is_crit))
                for rid, rtxt, _, rsev_val, rcat, is_crit, _ in self._rule_data
            ]
            _rust_ctx_rules = [
                (
                    r.id,
                    r.text,
                    r.severity.value,
                    r.category,
                    [k.lower() for k in r.keywords],
                    r.patterns,
                    r.enabled,
                )
                for r in self._active_rules
            ]
            self._rust_validator: Any = _rust.GovernanceValidator(
                _rust_kw,
                _rust_anchor_dispatch,
                _rust_no_anchor,
                _rust_rules,
                list(_POSITIVE_VERBS_SET),
                self.strict,
                _rust_ctx_rules,
                self._const_hash,
            )
        else:
            self._rust_validator = None
        if self._rust_validator is not None:
            _h = self._hot
            self._hot = (
                _h[0],
                _h[1],
                _h[2],
                _h[3],
                _h[4],
                _h[5],
                _h[6],
                _h[7],
                _h[8],
                _h[9],
                self._rust_validator,
            )
        if warmup and self._rust_validator is not None:
            _real_hot = self._hot
            _real_audit = self.audit_log
            _real_custom_validators = self.custom_validators
            try:
                self.audit_log = _FastAuditLog(constitution.hash)
                self.custom_validators = []
                _temp_hot = list(_real_hot)
                _temp_hot[6] = _NoopRecorder()
                self._hot = tuple(_temp_hot)

                _no_ctx_warmup = (
                    "run safety test",
                    "deploy model without safety review",
                    "keep decision secret from users",
                    "no appeal for rejected applicants",
                    "without appeal rights for users",
                    "apply age-based insurance pricing",
                    "share third-party analytics data",
                    "classify decisions as trade secrets",
                    "bypass content filtering system",
                    "implement differential privacy",
                    (
                        "AI coding agent executed terraform destroy on production infrastructure "
                        "without human approval"
                    ),
                    (
                        "analyze production AI system resilience through comprehensive chaos "
                        "engineering tests"
                    ),
                    (
                        "evaluate model performance metrics against fairness benchmarks for "
                        "quarterly compliance report"
                    ),
                )
                for _ in range(3):
                    for _wa in _no_ctx_warmup:
                        with suppress(ConstitutionalViolationError):
                            self.validate(_wa)
                _wctx_calls = (
                    (
                        "prepare analytics dashboard",
                        {"action_detail": "export personal data without consent"},
                    ),
                    (
                        "update service configuration",
                        {"action_description": "disable safety monitoring"},
                    ),
                    (
                        "run compliance check",
                        {"action_description": "review safety controls for completeness"},
                    ),
                    (
                        "analyze feedback trends",
                        {"action_detail": "configure workflow without appeal for denied customers"},
                    ),
                    (
                        "schedule model retraining",
                        {"action_description": "hide AI involvement in customer credit denial"},
                    ),
                    (
                        "assess patient record handling controls for compliance gaps",
                        {
                            "action_description": (
                                "assess clinical workflow safeguards for improvement planning"
                            )
                        },
                    ),
                )
                for _ in range(4):
                    for _wctx_a, _wctx_c in _wctx_calls:
                        with suppress(ConstitutionalViolationError):
                            self.validate(_wctx_a, context=_wctx_c)
                _meta_ctx = {"source": "autoresearch", "rule": "SAFETY-003"}
                _empty_ctx2: dict = {}
                _meta_warmup = (
                    (
                        "AI coding agent executed terraform destroy on production"
                        " infrastructure without human approval",
                        _meta_ctx,
                    ),
                    (
                        "autonomous AI agent deleted production environment"
                        " without human oversight",
                        _meta_ctx,
                    ),
                    ("run clinical decision support safety audit on cardiology model", _meta_ctx),
                    ("audit employment screening model for demographic fairness", _empty_ctx2),
                    ("deploy hiring model without bias audit", _empty_ctx2),
                    ("implement bias audit framework for hiring models", _empty_ctx2),
                )
                for _ in range(3):
                    for _wm_a, _wm_c in _meta_warmup:
                        with suppress(ConstitutionalViolationError):
                            self.validate(_wm_a, context=_wm_c)
            finally:
                self._hot = _real_hot
                self.audit_log = _real_audit
                self.custom_validators = _real_custom_validators
        import gc as _gc  # noqa: PLC0415

        _gc.collect()
        if freeze_gc:
            _gc.freeze()
        if disable_gc:
            _gc.disable()

    def _new_fast_allow_result(self) -> ValidationResult:
        """Return an isolated fast-path allow result."""
        return ValidationResult(
            True,
            self._const_hash,
            [],
            self._rules_count,
            0.0,
            "",
            "",
            "",
            _ANON,
        )

    def _new_fast_result(
        self,
        *,
        valid: bool,
        violations: list[Violation],
        action: str,
        warnings: list[Violation] | None = None,
        action_taken: ViolationAction | None = None,
        enforcement: EnforcementResolution | None = None,
    ) -> ValidationResult:
        """Return an isolated fast-path result.

        Fast-mode validation used to reuse mutable ValidationResult instances.
        That leaked state across repeated or concurrent validations because
        callers observed the same object reference. Returning a fresh object
        preserves fast-mode semantics without cross-request aliasing.
        """
        return ValidationResult(
            valid,
            self._const_hash,
            list(violations),
            self._rules_count,
            0.0,
            "",
            "",
            action[:500],
            _ANON,
            warnings if warnings is not None else [],
            action_taken,
            [] if enforcement is None else enforcement.notifications,
            [] if enforcement is None else enforcement.review_requests,
            [] if enforcement is None else enforcement.escalations,
            [] if enforcement is None else enforcement.incident_alerts,
        )

    def _workflow_action_for_violation(
        self,
        violation: Violation,
    ) -> ViolationAction:
        """Resolve the workflow action for a matched violation."""
        workflow_action = self._rule_id_to_wa.get(violation.rule_id)
        if workflow_action is not None:
            return workflow_action
        return ViolationAction.BLOCK if violation.severity.blocks() else ViolationAction.WARN

    def _resolve_enforcement(
        self,
        violations: list[Violation],
        *,
        action_text: str,
    ) -> EnforcementResolution:
        """Resolve matched violations into runtime enforcement artifacts."""
        return resolve_enforcement(
            violations,
            action_text=action_text,
            workflow_action_for_violation=self._workflow_action_for_violation,
        )

    def _raise_for_enforcement(
        self,
        enforcement: EnforcementResolution,
        *,
        strict: bool,
        action_text: str,
    ) -> None:
        """Raise the appropriate exception for halting or strict blocking outcomes."""
        if enforcement.primary_action is None or enforcement.primary_violation is None:
            return
        violation = enforcement.primary_violation
        if enforcement.primary_action is ViolationAction.HALT:
            raise ConstitutionalViolationError(
                f"Constitutional HALT by rule {violation.rule_id}: {violation.rule_text}",
                rule_id=violation.rule_id,
                severity=violation.severity.value,
                action=action_text[:200],
                enforcement_action=enforcement.primary_action,
            )
        if strict and enforcement.blocking_violations:
            raise ConstitutionalViolationError(
                f"Action blocked by rule {violation.rule_id}: {violation.rule_text}",
                rule_id=violation.rule_id,
                severity=violation.severity.value,
                action=action_text[:200],
                enforcement_action=enforcement.primary_action,
            )

    @staticmethod
    def _build_rule_evaluations(
        rules: list[Rule],
        *,
        matched_rule_ids: set[str],
        applicable_rule_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Build rule-evaluation records for audit output."""
        evaluations: list[dict[str, Any]] = []
        for rule in rules:
            evaluated = True if applicable_rule_ids is None else rule.id in applicable_rule_ids
            evaluations.append(
                {
                    "rule_id": rule.id,
                    "severity": rule.severity.value,
                    "evaluated": evaluated,
                    "matched": rule.id in matched_rule_ids,
                    "reason": (
                        "violation"
                        if rule.id in matched_rule_ids
                        else "no_match"
                        if evaluated
                        else "inactive"
                    ),
                }
            )
        return evaluations

    def _record_validation_audit(
        self,
        *,
        request_id: str,
        agent_id: str,
        action: str,
        valid: bool,
        matched_violations: list[Violation],
        latency_ms: float,
        timestamp: str,
        rule_evaluations: list[dict[str, Any]],
        enforcement: EnforcementResolution | None = None,
        audit_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a validation audit entry including enforcement metadata."""
        metadata: dict[str, Any] = {"rule_evaluations": rule_evaluations}
        if enforcement is not None:
            metadata["enforcement"] = enforcement.audit_metadata()
        if audit_metadata:
            metadata["runtime_governance"] = audit_metadata
        self.audit_log.record(
            AuditEntry(
                id=str(request_id),
                type="validation",
                agent_id=agent_id,
                action=action,
                valid=valid,
                violations=[violation.rule_id for violation in matched_violations],
                constitutional_hash=self._const_hash,
                latency_ms=latency_ms,
                timestamp=timestamp,
                metadata=metadata,
            )
        )

    def _post_dispatch_result(
        self,
        result: ValidationResult,
        action_text: str = "",
        *,
        strict: bool | None = None,
    ) -> ValidationResult:
        """Re-categorise violations by workflow_action on a result returned by a fast path.

        Mutates *result* in-place: moves WARN violations to ``result.warnings``,
        keeps blocking violations in ``result.violations``, and sets ``action_taken``.
        Raises :class:`ConstitutionalViolationError` for HALT violations.
        """
        if not result.violations:
            return result
        enforcement = self._resolve_enforcement(result.violations, action_text=action_text[:200])
        self._raise_for_enforcement(
            enforcement,
            strict=self.strict if strict is None else strict,
            action_text=action_text,
        )
        result.violations = enforcement.blocking_violations
        result.warnings = enforcement.warning_violations
        result.action_taken = enforcement.action_taken
        result.notifications = enforcement.notifications
        result.review_requests = enforcement.review_requests
        result.escalations = enforcement.escalations
        result.incident_alerts = enforcement.incident_alerts
        return result

    def _runtime_active_rules(self, context: dict[str, Any] | None) -> list[Rule]:
        """Resolve rules that are currently enforceable for the given runtime context."""
        ctx = context or {}
        evaluation_time = self._resolve_runtime_evaluation_time(ctx)
        return [
            rule
            for rule in self.constitution.rules
            if rule.enabled
            and not rule.deprecated
            and rule.condition_matches(ctx)
            and rule.is_valid_at(evaluation_time)
        ]

    @staticmethod
    def _resolve_runtime_evaluation_time(context: dict[str, Any]) -> str:
        """Resolve the timestamp used for temporal rule activation."""
        for key in ("timestamp", "evaluation_time", "valid_at", "at"):
            value = context.get(key)
            if isinstance(value, str) and value:
                return value
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

    def _validate_with_runtime_rule_filtering(
        self,
        action: str,
        *,
        agent_id: str,
        context: dict[str, Any] | None,
        audit_metadata: dict[str, Any] | None = None,
        strict: bool | None = None,
    ) -> ValidationResult:
        """Validate using per-call rule activation semantics.

        This path is intentionally slower than the hot path, but it preserves correct
        behavior for constitutions that use context-gated, deprecated, or time-bounded rules.
        """
        start = time.perf_counter()
        applicable_rules = self._runtime_active_rules(context)
        text_lower = action.lower()
        has_neg = bool(_NEGATIVE_VERBS_RE.search(text_lower))
        has_pos = (not has_neg) and any(w in _POSITIVE_VERBS_SET for w in text_lower.split()[:4])
        action_trimmed = action[:500]
        action_200 = action[:200]
        violations: list[Violation] = []

        for rule in applicable_rules:
            if rule.matches_with_signals(text_lower, has_neg, has_pos):
                violations.append(
                    Violation(
                        rule_id=rule.id,
                        rule_text=rule.text,
                        severity=rule.severity,
                        matched_content=action_200,
                        category=rule.category,
                    )
                )

        if context and ("action_detail" in context or "action_description" in context):
            for key, value in context.items():
                if key not in ("action_detail", "action_description") or not isinstance(value, str):
                    continue
                value_lower = value.lower()
                value_has_neg = bool(_NEGATIVE_VERBS_RE.search(value_lower))
                value_has_pos = (not value_has_neg) and any(
                    word in _POSITIVE_VERBS_SET for word in value_lower.split()[:4]
                )
                for rule in applicable_rules:
                    if rule.matches_with_signals(value_lower, value_has_neg, value_has_pos):
                        violations.append(
                            Violation(
                                rule_id=rule.id,
                                rule_text=rule.text,
                                severity=rule.severity,
                                matched_content=f"context[{key}]: {value[:100]}",
                                category=rule.category,
                            )
                        )

        # M7: always run custom validators when present so their findings reach
        # the audit trail even when a CRITICAL string rule already matched. The
        # CRITICAL short-circuit is an enforcement concern (resolved below), not
        # a reason to omit findings from the forensic record.
        if self.custom_validators:
            ctx = context or {}
            for validator in self.custom_validators:
                try:
                    violations.extend(validator(action, ctx))
                except Exception as exc:
                    violations.append(
                        Violation(
                            "CUSTOM-ERROR",
                            f"Custom validator failed: {exc}",
                            Severity.HIGH,
                            action_200,
                            "validator-error",
                        )
                    )

        unique_violations = violations if len(violations) <= 1 else _dedup_violations(violations)

        enforcement = self._resolve_enforcement(unique_violations, action_text=action_200)
        valid = not bool(enforcement.blocking_violations)

        latency_ms = (time.perf_counter() - start) * 1000
        request_id = str(next(_request_counter))
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        all_matched = enforcement.blocking_violations + enforcement.warning_violations
        result = ValidationResult(
            valid=valid,
            constitutional_hash=self._const_hash,
            violations=enforcement.blocking_violations,
            rules_checked=len(applicable_rules),
            latency_ms=latency_ms,
            request_id=request_id,
            timestamp=timestamp,
            action=action_trimmed,
            agent_id=agent_id,
            warnings=enforcement.warning_violations,
            action_taken=enforcement.action_taken,
            notifications=enforcement.notifications,
            review_requests=enforcement.review_requests,
            escalations=enforcement.escalations,
            incident_alerts=enforcement.incident_alerts,
        )

        if self._fast_records is not None:
            self._fast_records.append(None)
        else:
            self._record_validation_audit(
                request_id=request_id,
                agent_id=agent_id,
                action=action_trimmed,
                valid=valid,
                matched_violations=all_matched,
                latency_ms=latency_ms,
                timestamp=timestamp,
                rule_evaluations=self._build_rule_evaluations(
                    self.constitution.rules,
                    matched_rule_ids={v.rule_id for v in all_matched},
                    applicable_rule_ids={rule.id for rule in applicable_rules},
                ),
                enforcement=enforcement,
                audit_metadata=audit_metadata,
            )

        self._raise_for_enforcement(
            enforcement,
            strict=self.strict if strict is None else strict,
            action_text=action_200,
        )
        return result

    def _validate_python_regex(
        self,
        action: str,
        strict: bool,
        text_lower: str,
        positive_verb_mode: bool,
        violations: list[Violation] | None,
    ) -> list[Violation] | None:
        action_200 = action[:200]
        if positive_verb_mode:
            kw_matches = self._neg_findall(text_lower)
            if kw_matches:
                fired = 0
                for kw in kw_matches:
                    for rule_idx, _ in self._kw_to_idxs.get(kw, []):
                        _bit = 1 << rule_idx
                        if fired & _bit:
                            continue
                        fired |= _bit
                        rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                        if strict and is_crit:
                            _e_src = self._rule_excs[rule_idx]
                            raise ConstitutionalViolationError(
                                str(_e_src),
                                rule_id=_e_src.rule_id,
                                severity=_e_src.severity,
                                action=action_200,
                            )
                        if violations is None:
                            violations = []
                        violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
                for rule_idx, pat in self._pattern_rule_idxs:
                    if not (fired & (1 << rule_idx)) and pat.search(text_lower):
                        fired |= 1 << rule_idx
                        rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                        if strict and is_crit:
                            _e_src = self._rule_excs[rule_idx]
                            raise ConstitutionalViolationError(
                                str(_e_src),
                                rule_id=_e_src.rule_id,
                                severity=_e_src.severity,
                                action=action_200,
                            )
                        if violations is None:
                            violations = []
                        violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
            elif self._pattern_rule_idxs:
                # F4: no-anchor patterns (secret regexes with no literal anchor
                # word, e.g. ``sk-...`` keys or SSNs) must ALWAYS be evaluated.
                # Gating the whole pattern list behind the anchor search dropped
                # them whenever the text had no anchor word — a fail-open the
                # Aho-Corasick backend never had. Fall back to the no-anchor
                # subset when the anchor search misses.
                _pats = (
                    self._pattern_rule_idxs
                    if (self._pat_anchor_search is None or self._pat_anchor_search(text_lower))
                    else self._no_anchor_patterns
                )
                for rule_idx, pat in _pats:
                    if pat.search(text_lower):
                            rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                            if strict and is_crit:
                                _e_src = self._rule_excs[rule_idx]
                                raise ConstitutionalViolationError(
                                    str(_e_src),
                                    rule_id=_e_src.rule_id,
                                    severity=_e_src.severity,
                                    action=action_200,
                                )
                            if violations is None:
                                violations = []
                            violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
            return violations
        elif self._combined_findall is not None:
            _m = self._combined_search(text_lower)
            if _m:
                fired = 0
                kw0 = _m.group(0)
                for rule_idx, _ in self._kw_to_idxs.get(kw0, []):
                    fired |= 1 << rule_idx
                    rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                    if strict and is_crit:
                        _e_src = self._rule_excs[rule_idx]
                        raise ConstitutionalViolationError(
                            str(_e_src),
                            rule_id=_e_src.rule_id,
                            severity=_e_src.severity,
                            action=action_200,
                        )
                    if violations is None:
                        violations = []
                    violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
                if self._combined_search(text_lower, _m.end()) is not None:
                    for kw in self._combined_findall(text_lower):
                        for rule_idx, _ in self._kw_to_idxs.get(kw, []):
                            _bit = 1 << rule_idx
                            if fired & _bit:
                                continue
                            fired |= _bit
                            rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                            if strict and is_crit:
                                _e_src = self._rule_excs[rule_idx]
                                raise ConstitutionalViolationError(
                                    str(_e_src),
                                    rule_id=_e_src.rule_id,
                                    severity=_e_src.severity,
                                    action=action_200,
                                )
                            if violations is None:
                                violations = []
                            violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
                # F4: always evaluate no-anchor patterns even when no anchor word
                # is present (mirrors the Aho-Corasick backend).
                _pats = (
                    self._pattern_rule_idxs
                    if (self._pat_anchor_search is None or self._pat_anchor_search(text_lower))
                    else self._no_anchor_patterns
                )
                for rule_idx, pat in _pats:
                    if not (fired & (1 << rule_idx)) and pat.search(text_lower):
                            fired |= 1 << rule_idx
                            rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                            if strict and is_crit:
                                _e_src = self._rule_excs[rule_idx]
                                raise ConstitutionalViolationError(
                                    str(_e_src),
                                    rule_id=_e_src.rule_id,
                                    severity=_e_src.severity,
                                    action=action_200,
                                )
                            if violations is None:
                                violations = []
                            violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
            elif self._pattern_rule_idxs:
                # F4: no-anchor patterns (secret regexes with no literal anchor
                # word, e.g. ``sk-...`` keys or SSNs) must ALWAYS be evaluated.
                # Gating the whole pattern list behind the anchor search dropped
                # them whenever the text had no anchor word — a fail-open the
                # Aho-Corasick backend never had. Fall back to the no-anchor
                # subset when the anchor search misses.
                _pats = (
                    self._pattern_rule_idxs
                    if (self._pat_anchor_search is None or self._pat_anchor_search(text_lower))
                    else self._no_anchor_patterns
                )
                for rule_idx, pat in _pats:
                    if pat.search(text_lower):
                            rid, rtxt, rsev, _, rcat, is_crit, _ = self._rule_data[rule_idx]
                            if strict and is_crit:
                                _e_src = self._rule_excs[rule_idx]
                                raise ConstitutionalViolationError(
                                    str(_e_src),
                                    rule_id=_e_src.rule_id,
                                    severity=_e_src.severity,
                                    action=action_200,
                                )
                            if violations is None:
                                violations = []
                            violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
            return violations
        return violations

    def validate(
        self,
        action: str,
        *,
        agent_id: str = "anonymous",
        context: dict[str, Any] | None = None,
        audit_metadata: dict[str, Any] | None = None,
        strict: bool | None = None,
    ) -> ValidationResult:
        """Validate an action against the constitution.

        Args:
            strict: Per-call override for strict mode. When ``None`` (default),
                the engine's instance-level ``self.strict`` is used. Passing an
                explicit ``True``/``False`` overrides strictness for this call
                only, without mutating ``self.strict``. Prefer this over
                ``engine.strict = …`` or ``with engine.non_strict()`` when the
                engine is shared across threads or integrations.
        """
        if self._requires_runtime_rule_filtering:
            return self._validate_with_runtime_rule_filtering(
                action,
                agent_id=agent_id,
                context=context,
                audit_metadata=audit_metadata,
                strict=strict,
            )
        strict = self.strict if strict is None else strict
        (
            _ac_iter,
            _anchor_dispatch,
            _no_anchor_pats,
            _rule_data,
            _rule_excs,
            _has_high,
            _fast_records,
            _pos_verbs,
            _has_ac,
            _is_noop,
            _rv,
        ) = self._hot
        if (
            _rv is not None
            and _fast_records is not None
            and strict
            and not audit_metadata
            and not self.custom_validators
        ):
            # audit_metadata guard: same as strict=False path — when audit_metadata is
            # present, fall through to the full Python path which calls
            # _record_validation_audit with the metadata.  Omitting this guard would
            # silently drop audit_metadata in fast (aggregate-only) mode.
            # custom_validators guard (M7): a registered custom validator must always
            # run and reach the audit trail even under a CRITICAL string-rule match.
            # The Rust fast path short-circuits before custom validators, so when any
            # are present we fall through to the Python path, which defers the raise.
            _action_lower = action if action.islower() else action.lower()
            _decision, _data = _rv.validate_hot(_action_lower)
            _has_gov_ctx = context is not None and (
                "action_description" in context or "action_detail" in context
            )
            if _has_gov_ctx:
                _result = self._validate_rust_gov_context(
                    action,
                    _decision,
                    _data,
                    context,
                    _rule_excs,
                    _fast_records,
                )
                if _result is not None:
                    return self._post_dispatch_result(_result, action, strict=strict)
            else:
                _result = self._validate_rust_no_context(
                    action,
                    _decision,
                    _data,
                    _rule_excs,
                    _fast_records,
                    strict=True,
                )
                if _result is not None:
                    return self._post_dispatch_result(_result, action, strict=strict)
        elif (
            _rv is not None
            and _fast_records is not None
            and context is None
            and not audit_metadata  # True for both None and {} — empty dict treated as "no metadata"
            and not self.custom_validators
        ):
            # strict=False Rust fast path: return violations instead of raising
            # Only used when no context/audit_metadata provided and no custom validators (benchmark mode)
            _action_lower = action if action.islower() else action.lower()
            _decision, _data = _rv.validate_hot(_action_lower)
            _result = self._validate_rust_no_context(
                action,
                _decision,
                _data,
                _rule_excs,
                _fast_records,
                strict=False,
            )
            if _result is not None:
                return self._post_dispatch_result(_result, action, strict=strict)
        elif (
            _rv is not None
            and _fast_records is not None
            and context
            and strict
            and not self.custom_validators  # M7: see custom_validators guard above
        ):
            _ctx_pairs = [
                (k, v)
                for k, v in context.items()
                if isinstance(v, str) and k in ("action_detail", "action_description")
            ]
            if not _ctx_pairs:
                _decision, _data = _rv.validate_hot(action.lower())
                _result = self._validate_rust_metadata_context(
                    action,
                    _decision,
                    _data,
                    _rule_excs,
                    _fast_records,
                    _is_noop,
                )
                if _result is not None:
                    return self._post_dispatch_result(_result, action, strict=strict)
            else:
                _result = self._validate_rust_full(
                    action,
                    strict,
                    _ctx_pairs,
                    _rule_excs,
                    _fast_records,
                )
                if _result is not None:
                    return self._post_dispatch_result(_result, action, strict=strict)
        start = time.perf_counter()
        violations = None
        action_trimmed = action[:500]
        action_200 = action[:200]

        text_lower = action.lower()
        _first_word, _, _ = text_lower.partition(" ")
        _has_neg = bool(_NEGATIVE_VERBS_RE.search(text_lower))
        # M7: when custom validators are registered, do not let the matcher
        # short-circuit-raise on a CRITICAL string rule. Accumulate the violation
        # instead so the custom-validator block (below) and the audit write both
        # run; the deferred raise happens in _raise_for_enforcement, which blocks
        # identically under strict.
        #
        # #66: the same short-circuit drops the per-decision audit entry in FULL
        # audit mode. The matcher's CRITICAL early-raise fires before the audit
        # write below (the HIGH/BLOCK path defers the raise and is recorded, but
        # CRITICAL never reaches it), so a blocked CRITICAL decision vanishes from
        # the tamper-evident trail — exactly the fail-closed path compliance relies
        # on. Suppress the short-circuit whenever a per-entry audit log is active
        # (``_fast_records is None`` == full mode) so the audit write runs first and
        # the deferred raise still blocks identically under strict. Fast/aggregate
        # mode (``_fast_records is not None``) keeps the short-circuit, so the hot
        # benchmark path is unchanged.
        matcher_strict = strict and not self.custom_validators and _fast_records is not None
        if _has_ac and _first_word in _pos_verbs and not _has_neg:
            violations = self._validate_python_ac(
                action,
                matcher_strict,
                text_lower,
                True,
                violations,
            )
        elif _has_ac:
            violations = self._validate_python_ac(
                action,
                matcher_strict,
                text_lower,
                False,
                violations,
            )
        elif _first_word in _POSITIVE_VERBS_SET and self._neg_findall is not None and not _has_neg:
            violations = self._validate_python_regex(
                action,
                matcher_strict,
                text_lower,
                True,
                violations,
            )
        elif self._combined_findall is not None:
            violations = self._validate_python_regex(
                action,
                matcher_strict,
                text_lower,
                False,
                violations,
            )

        if context and ("action_detail" in context or "action_description" in context):
            for key, value in context.items():
                if key in ("action_detail", "action_description") and isinstance(value, str):
                    val_lower = value.lower()
                    val_neg = bool(_NEGATIVE_VERBS_RE.search(val_lower))
                    val_pos = (not val_neg) and any(
                        w in _POSITIVE_VERBS_SET for w in val_lower.split()[:4]
                    )
                    for rule in self._active_rules:
                        if rule.matches_with_signals(val_lower, val_neg, val_pos):
                            if violations is None:
                                violations = []
                            violations.append(
                                Violation(
                                    rule_id=rule.id,
                                    rule_text=rule.text,
                                    severity=rule.severity,
                                    matched_content=f"context[{key}]: {value[:100]}",
                                    category=rule.category,
                                )
                            )

        # M7: always run custom validators when present so their findings reach
        # the audit trail even when a CRITICAL string rule already matched. The
        # CRITICAL short-circuit is an enforcement concern (resolved below), not
        # a reason to omit findings from the forensic record.
        if self.custom_validators:
            ctx = context or {}
            for validator in self.custom_validators:
                try:
                    custom_violations = validator(action, ctx)
                    if violations is None:
                        violations = []
                    violations.extend(custom_violations)
                except Exception as e:
                    if violations is None:
                        violations = []
                    violations.append(
                        Violation(
                            "CUSTOM-ERROR",
                            f"Custom validator failed: {e}",
                            # Fail-closed: a validator that crashes did not clear the
                            # action, so under strict it must block (HIGH), not warn.
                            # A security validator (e.g. the AST analyzer) silently
                            # downgraded to a non-blocking MEDIUM here let the action
                            # proceed ungoverned — a fail-open bypass, and inconsistent
                            # with the runtime-rule-filtering path which already blocks.
                            Severity.HIGH,
                            action_200,
                            "validator-error",
                        )
                    )

        if violations is None:
            if _fast_records is not None:
                _fast_records.append(None)
                return self._new_fast_allow_result()
            request_id = str(next(_request_counter))
            latency_ms = (time.perf_counter() - start) * 1000
            now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            result = ValidationResult(
                True,
                self._const_hash,
                [],
                self._rules_count,
                latency_ms,
                request_id,
                now_ts,
                action_trimmed,
                agent_id,
            )
            self._record_validation_audit(
                request_id=str(request_id),
                agent_id=agent_id,
                action=action_trimmed,
                valid=True,
                matched_violations=[],
                latency_ms=latency_ms,
                timestamp=now_ts,
                rule_evaluations=self._build_rule_evaluations(
                    self.constitution.rules,
                    matched_rule_ids=set(),
                ),
                audit_metadata=audit_metadata,
            )
            return result

        unique_violations = violations if len(violations) == 1 else _dedup_violations(violations)

        enforcement = self._resolve_enforcement(unique_violations, action_text=action_200)
        valid = not bool(enforcement.blocking_violations)

        if _fast_records is not None:
            self._raise_for_enforcement(
                enforcement,
                strict=strict,
                action_text=action_200,
            )
            _fast_records.append(None)
            return self._new_fast_result(
                valid=valid,
                violations=enforcement.blocking_violations,
                action=action,
                warnings=enforcement.warning_violations,
                action_taken=enforcement.action_taken,
                enforcement=enforcement,
            )

        request_id = str(next(_request_counter))
        latency_ms = (time.perf_counter() - start) * 1000

        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result = ValidationResult(
            valid=valid,
            constitutional_hash=self._const_hash,
            violations=enforcement.blocking_violations,
            rules_checked=self._rules_count,
            latency_ms=latency_ms,
            request_id=request_id,
            timestamp=now_ts,
            action=action_trimmed,
            agent_id=agent_id,
            warnings=enforcement.warning_violations,
            action_taken=enforcement.action_taken,
            notifications=enforcement.notifications,
            review_requests=enforcement.review_requests,
            escalations=enforcement.escalations,
            incident_alerts=enforcement.incident_alerts,
        )

        all_matched = enforcement.blocking_violations + enforcement.warning_violations
        self._record_validation_audit(
            request_id=str(request_id),
            agent_id=agent_id,
            action=action_trimmed,
            valid=valid,
            matched_violations=all_matched,
            latency_ms=result.latency_ms,
            timestamp=now_ts,
            rule_evaluations=self._build_rule_evaluations(
                self.constitution.rules,
                matched_rule_ids={v.rule_id for v in all_matched},
            ),
            enforcement=enforcement,
            audit_metadata=audit_metadata,
        )
        self._raise_for_enforcement(
            enforcement,
            strict=strict,
            action_text=action_200,
        )
        return result

    def add_validator(self, validator: CustomValidator) -> None:
        """Register a custom validator function."""
        self.custom_validators.append(validator)

    @contextmanager
    def non_strict(self):
        """Context manager to temporarily disable strict mode.

        Restores the previous strict setting on exit, even if an exception is raised.
        Use this instead of directly mutating ``engine.strict`` to avoid leaving the
        engine in a non-strict state after errors.

        Example::

            with engine.non_strict():
                # engine.strict is False here
                result = engine.validate(untrusted_input)
            # engine.strict is automatically restored here

        .. warning:: **Not safe for concurrent use on a shared engine instance.**
            This mutates ``self.strict`` on the shared object. If two concurrent
            callers both enter ``non_strict()`` on the same engine, one caller
            can restore ``strict=True`` while the other is still inside the block,
            causing it to validate with strict mode active. For concurrent
            deployments (e.g., MCP server + Telegram webhook sharing one engine),
            prefer ``validate(strict=False)`` (available since v2.10.0) or give
            each handler its own engine instance.
        """
        prev = self.strict
        self.strict = False
        try:
            yield self
        finally:
            self.strict = prev

    @property
    def audit_mode(self) -> str:
        """Current audit mode: 'fast' (aggregate-only) or 'full' (durable log)."""
        return self._audit_mode

    @property
    def stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        if isinstance(self._fast_records, _NoopRecorder):
            total = len(self._fast_records)
            return {
                "total_validations": total,
                "compliance_rate": None,
                "rules_count": len(self.constitution.rules),
                "constitutional_hash": self._const_hash,
                "avg_latency_ms": None,
                "audit_mode": self.audit_mode,
                "audit_entry_count": 0,
                "audit_metrics_complete": False,
            }
        entries = self.audit_log.entries
        total = len(entries)
        valid_count = sum(1 for e in entries if e.valid)
        return {
            "total_validations": total,
            "compliance_rate": valid_count / total if total > 0 else 1.0,
            "rules_count": len(self.constitution.rules),
            "constitutional_hash": self._const_hash,
            "avg_latency_ms": (sum(e.latency_ms for e in entries) / total if total > 0 else 0.0),
            "audit_mode": self.audit_mode,
            "audit_entry_count": total,
            "audit_metrics_complete": True,
        }


__all__ = [
    "CustomValidator",
    "GovernanceEngine",
    "Severity",
    "ValidationResult",
    "Violation",
    "_ANON",
    "_FastAuditLog",
    "_NoopRecorder",
    "_dedup_violations",
    "_request_counter",
]
