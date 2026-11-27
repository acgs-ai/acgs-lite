"""Matcher mixin and optional acceleration imports for GovernanceEngine."""

from __future__ import annotations

from typing import Any

from acgs_lite.constitution import Severity
from acgs_lite.constitution.analytics import _POSITIVE_VERBS_SET
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.errors import ConstitutionalViolationError

from .models import ValidationResult, Violation
from .rust import _HAS_AHO, _HAS_RUST, _RUST_ALLOW, _RUST_DENY, _RUST_DENY_CRITICAL

_ac_mod: Any = None
if _HAS_AHO:
    import ahocorasick as _ac_mod  # type: ignore[no-redef]

_rust_mod: Any = None
if _HAS_RUST:
    import acgs_lite_rust as _rust_mod  # type: ignore[no-redef]

_ac = _ac_mod
_rust = _rust_mod


class GovernanceMatcherMixin:
    """Validation helpers shared by GovernanceEngine."""

    _ac_iter: Any
    _no_anchor_patterns: list[tuple[int, Any]]
    _pat_anchor_dispatch: tuple[Any, ...]
    _rule_data: list[tuple[Any, ...]]
    _rule_excs: list[Any]
    _rule_id_to_exc_idx: dict[str, int]
    _rule_id_to_wa: dict[str, ViolationAction]
    _rust_validator: Any
    _rust_hot_owner: Any
    _rust_hot_fn: Any
    strict: bool

    def _new_fast_allow_result(self) -> ValidationResult:
        raise NotImplementedError

    def _new_fast_result(
        self,
        *,
        valid: bool,
        violations: list[Violation],
        action: str,
    ) -> ValidationResult:
        raise NotImplementedError

    def _decode_rust_bitmask(
        self,
        bitmask: int,
        action_200: str,
    ) -> tuple[list[Violation], Violation | None, bool]:
        """Decode a fired rule bitmask into Violations, first plain-BLOCK violation, and deferred flag.

        ``has_deferred`` is True when any matched rule carries an elevated workflow
        action (``BLOCK_AND_NOTIFY``, ``REQUIRE_HUMAN_REVIEW``, ``ESCALATE``, or
        ``HALT``) that must be resolved by ``_post_dispatch_result`` rather than
        early-raising with default ``ViolationAction.BLOCK``.
        """
        vlist: list[Violation] = []
        blocking_violation: Violation | None = None
        has_deferred = False
        rule_data = self._rule_data
        n_rules = len(rule_data)
        wa_lookup = self._rule_id_to_wa
        if bitmask < 0:
            # Guard against signed 64-bit sign extension (bit 63 in Rust i64)
            # which would otherwise loop forever in Python two's-complement math.
            bitmask &= (1 << 64) - 1
        while bitmask:
            idx = (bitmask & -bitmask).bit_length() - 1
            bitmask &= bitmask - 1
            if idx >= n_rules:
                continue
            rd = rule_data[idx]
            violation = Violation(rd[0], rd[1], rd[2], action_200, rd[4])
            vlist.append(violation)
            vwa = wa_lookup.get(rd[0])
            if vwa is None:
                vwa = ViolationAction.BLOCK if violation.severity.blocks() else ViolationAction.WARN
            if vwa not in (ViolationAction.WARN, ViolationAction.BLOCK):
                has_deferred = True
            elif blocking_violation is None and vwa is ViolationAction.BLOCK:
                blocking_violation = violation
        return vlist, blocking_violation, has_deferred

    def _validate_rust_no_context(
        self,
        action: str,
        decision: int,
        data: int,
        rule_excs: list[Any],
        fast_records: Any,
        strict: bool,
    ) -> ValidationResult | None:
        if decision == _RUST_ALLOW:
            fast_records.append(None)
            return self._new_fast_allow_result()
        elif decision == _RUST_DENY_CRITICAL:
            if not (0 <= data < len(rule_excs)):
                fast_records.append(None)
                if strict:
                    raise ConstitutionalViolationError(
                        "Critical rule violation (index out of range)",
                        rule_id="UNKNOWN",
                        severity="critical",
                        action=action[:200],
                    )
                # strict=False: return a blocking result with unknown rule
                return self._new_fast_result(
                    valid=False,
                    violations=[
                        Violation(
                            "UNKNOWN",
                            "Critical rule violation",
                            Severity.CRITICAL,
                            action[:200],
                            "",
                        )
                    ],
                    action=action,
                )
            _e_src = rule_excs[data]
            fast_records.append(None)
            if strict:
                raise ConstitutionalViolationError(
                    str(_e_src),
                    rule_id=_e_src.rule_id,
                    severity=_e_src.severity,
                    action=action[:200],
                )
            # strict=False: build Violation from rule_data and return result
            _rd = self._rule_data[data]
            _v = Violation(_rd[0], _rd[1], _rd[2], action[:200], _rd[4])
            return self._new_fast_result(valid=False, violations=[_v], action=action)
        elif decision == _RUST_DENY:
            _a200 = action[:200]
            _vlist, _bv, _has_halt = self._decode_rust_bitmask(data, _a200)
            fast_records.append(None)
            # Only raise early in strict mode when no HALT rule matched (HALT takes precedence).
            if _bv is not None and strict and not _has_halt:
                raise ConstitutionalViolationError(
                    f"Action blocked by rule {_bv.rule_id}: {_bv.rule_text}",
                    rule_id=_bv.rule_id,
                    severity=_bv.severity.value,
                    action=_a200,
                )
            _has_blocking = _bv is not None or _has_halt
            return self._new_fast_result(valid=not _has_blocking, violations=_vlist, action=action)
        return None

    def _validate_rust_gov_context(
        self,
        action: str,
        decision: int,
        data: int,
        context: dict[str, Any],
        rule_excs: list[Any],
        fast_records: Any,
        *,
        strict: bool | None = None,
    ) -> ValidationResult | None:
        effective_strict = self.strict if strict is None else strict
        # Preserve the fail-closed contract on CRITICAL matches when ``strict`` is omitted
        # (``strict=None``) so callers relying on the historical strict-only fast-path
        # behavior still raise, while honoring an explicit ``strict=False`` override.
        raise_on_critical = strict is not False
        _merged_bm = 0
        _has_critical = False
        _crit_idx = -1
        _unknown_critical = False
        _n_rules = len(self._rule_data)
        if decision == _RUST_DENY_CRITICAL:
            _crit_idx = data
            _has_critical = True
        elif decision == _RUST_DENY:
            _merged_bm = data
        _ctx_det = context.get("action_detail")
        _ctx_desc = context.get("action_description")
        _ctx_hot_fn: Any = None
        for _cv in (_ctx_det, _ctx_desc):
            if _cv is not None and isinstance(_cv, str):
                _cv_lower = _cv if _cv.islower() else _cv.lower()
                # Rust validate_hot* only checks word 0 (space-delimited) for positive
                # verbs, whereas Python context matching checks split()[:4]. Fall
                # through to Python when a positive verb appears in words 1..3 or
                # after leading/non-space whitespace.
                _cv_words = _cv_lower.split()[:4]
                if (
                    _cv_words
                    and _cv_lower.partition(" ")[0] not in _POSITIVE_VERBS_SET
                    and any(w in _POSITIVE_VERBS_SET for w in _cv_words)
                ):
                    return None
                if _ctx_hot_fn is None:
                    _rv = self._rust_validator
                    if _rv is getattr(self, "_rust_hot_owner", None):
                        _ctx_hot_fn = self._rust_hot_fn
                    else:
                        _cand = getattr(_rv, "validate_hot_u128", None)
                        _ctx_hot_fn = _cand if callable(_cand) else _rv.validate_hot
                _ctx_dec, _ctx_data = _ctx_hot_fn(_cv_lower)
                if _ctx_dec == _RUST_DENY_CRITICAL:
                    if not _has_critical:
                        _crit_idx = _ctx_data
                        _has_critical = True
                    elif 0 <= _ctx_data < _n_rules:
                        _merged_bm |= 1 << _ctx_data
                    else:
                        _unknown_critical = True
                elif _ctx_dec == _RUST_DENY:
                    _merged_bm |= _ctx_data
        if _has_critical:
            if raise_on_critical:
                if not (0 <= _crit_idx < len(rule_excs)):
                    fast_records.append(None)
                    raise ConstitutionalViolationError(
                        "Critical rule violation (index out of range)",
                        rule_id="UNKNOWN",
                        severity="critical",
                        action=action[:200],
                    )
                _e_src = rule_excs[_crit_idx]
                fast_records.append(None)
                raise ConstitutionalViolationError(
                    str(_e_src),
                    rule_id=_e_src.rule_id,
                    severity=_e_src.severity,
                    action=action[:200],
                )
            if 0 <= _crit_idx < _n_rules:
                _merged_bm |= 1 << _crit_idx
            else:
                _unknown_critical = True
        if _merged_bm or _unknown_critical:
            _a200 = action[:200]
            _vlist, _bv_ctx, _has_halt = self._decode_rust_bitmask(_merged_bm, _a200)
            if _unknown_critical:
                _unk = Violation(
                    "UNKNOWN",
                    "Critical rule violation",
                    Severity.CRITICAL,
                    _a200,
                    "",
                )
                _vlist.append(_unk)
                if _bv_ctx is None:
                    _bv_ctx = _unk
            if _bv_ctx is not None and effective_strict and not _has_halt:
                raise ConstitutionalViolationError(
                    f"Action blocked by rule {_bv_ctx.rule_id}: {_bv_ctx.rule_text}",
                    rule_id=_bv_ctx.rule_id,
                    severity=_bv_ctx.severity.value,
                    action=_a200,
                )
            fast_records.append(None)
            _has_blocking = _bv_ctx is not None or _has_halt
            return self._new_fast_result(valid=not _has_blocking, violations=_vlist, action=action)
        fast_records.append(None)
        return self._new_fast_allow_result()

    def _validate_rust_metadata_context(
        self,
        action: str,
        decision: int,
        data: int,
        rule_excs: list[Any],
        fast_records: Any,
        is_noop: bool,
    ) -> ValidationResult | None:
        if decision == _RUST_ALLOW:
            if is_noop:
                fast_records.append(None)
            return self._new_fast_allow_result()
        elif decision == _RUST_DENY_CRITICAL:
            if not (0 <= data < len(rule_excs)):
                if is_noop:
                    fast_records.append(None)
                raise ConstitutionalViolationError(
                    "Critical rule violation (index out of range)",
                    rule_id="UNKNOWN",
                    severity="critical",
                    action=action[:200],
                )
            _e_src = rule_excs[data]
            if is_noop:
                fast_records.append(None)
            raise ConstitutionalViolationError(
                str(_e_src),
                rule_id=_e_src.rule_id,
                severity=_e_src.severity,
                action=action[:200],
            )
        elif decision == _RUST_DENY:
            _a200 = action[:200]
            _vlist, _bv_meta, _has_deferred = self._decode_rust_bitmask(data, _a200)
            if is_noop:
                fast_records.append(None)
            # strict=True is guaranteed at this call site (outer validate() guard).
            if _bv_meta is not None and not _has_deferred:
                raise ConstitutionalViolationError(
                    f"Action blocked by rule {_bv_meta.rule_id}: {_bv_meta.rule_text}",
                    rule_id=_bv_meta.rule_id,
                    severity=_bv_meta.severity.value,
                    action=_a200,
                )
            _has_blocking = _bv_meta is not None or _has_deferred
            return self._new_fast_result(valid=not _has_blocking, violations=_vlist, action=action)
        return None

    def _validate_rust_full(
        self,
        action: str,
        strict: bool,
        ctx_pairs: list[tuple[str, str]],
        rule_excs: list[Any],
        fast_records: Any,
    ) -> ValidationResult | None:
        _decision, _violations, _blocking = self._rust_validator.validate_full(
            action.lower(), ctx_pairs
        )
        if _decision == _RUST_ALLOW:
            if fast_records is not None:
                fast_records.append(None)
                return self._new_fast_allow_result()
        elif _decision == _RUST_DENY_CRITICAL:
            _vt_id = _violations[0][0]
            _idx = self._rule_id_to_exc_idx.get(_vt_id)
            if _idx is None:
                _vt_id, _vt_text, _vt_sev, _, _ = _violations[0]
                raise ConstitutionalViolationError(
                    f"Action blocked by rule {_vt_id}: {_vt_text}",
                    rule_id=_vt_id,
                    severity=_vt_sev,
                    action=action[:200],
                )
            _e_src = rule_excs[_idx]
            raise ConstitutionalViolationError(
                str(_e_src),
                rule_id=_e_src.rule_id,
                severity=_e_src.severity,
                action=action[:200],
            )
        elif _decision == _RUST_DENY:
            _a200 = action[:200]
            _SEV = Severity
            _vlist = [
                Violation(rid, rtxt, _SEV(sev), _a200, cat)
                for rid, rtxt, sev, _, cat in _violations
            ]
            _wa_lkup = self._rule_id_to_wa
            _has_deferred = False
            _bv: Violation | None = None
            for _v in _vlist:
                _vwa = _wa_lkup.get(_v.rule_id)
                if _vwa is None:
                    _vwa = ViolationAction.BLOCK if _v.severity.blocks() else ViolationAction.WARN
                if _vwa not in (ViolationAction.WARN, ViolationAction.BLOCK):
                    _has_deferred = True
                elif _bv is None and _vwa is ViolationAction.BLOCK:
                    _bv = _v
            if _bv is None and _blocking and not _has_deferred:
                _bv = next(
                    (
                        v
                        for v in _vlist
                        if _wa_lkup.get(v.rule_id, ViolationAction.BLOCK) is ViolationAction.BLOCK
                    ),
                    None,
                )
            if _bv is not None and strict and not _has_deferred:
                _exc_idx = self._rule_id_to_exc_idx.get(_bv.rule_id, -1)
                if _exc_idx >= 0:
                    _e_src = rule_excs[_exc_idx]
                    raise ConstitutionalViolationError(
                        str(_e_src),
                        rule_id=_e_src.rule_id,
                        severity=_e_src.severity,
                        action=_a200,
                    )
                raise ConstitutionalViolationError(
                    f"Action blocked by rule {_bv.rule_id}: {_bv.rule_text}",
                    rule_id=_bv.rule_id,
                    severity=_bv.severity.value,
                    action=_a200,
                )
            if fast_records is not None:
                fast_records.append(None)
                return self._new_fast_result(
                    valid=not (_bv is not None or _has_deferred),
                    violations=_vlist,
                    action=action,
                )
        return None

    def _validate_python_ac(
        self,
        action: str,
        strict: bool,
        text_lower: str,
        positive_verb_mode: bool,
        violations: list[Violation] | None,
    ) -> list[Violation] | None:
        action_200 = action[:200]
        fired = 0
        hit_anchors = 0
        rule_data = self._rule_data
        rule_excs = self._rule_excs

        for _end_idx, payload in self._ac_iter(text_lower):
            ptype = payload[0]
            if ptype == 1:
                hit_anchors |= 1 << payload[1]
                continue
            if ptype == 2:
                hit_anchors |= 1 << payload[2]
            for rule_idx, kw_has_neg in payload[1]:
                if positive_verb_mode and not kw_has_neg:
                    continue
                bit = 1 << rule_idx
                if fired & bit:
                    continue
                fired |= bit
                rid, rtxt, rsev, _, rcat, is_crit, _ = rule_data[rule_idx]
                if strict and is_crit:
                    e_src = rule_excs[rule_idx]
                    raise ConstitutionalViolationError(
                        str(e_src),
                        rule_id=e_src.rule_id,
                        severity=e_src.severity,
                        action=action_200,
                    )
                if violations is None:
                    violations = []
                violations.append(Violation(rid, rtxt, rsev, action_200, rcat))

        if hit_anchors or self._no_anchor_patterns:
            if hit_anchors:
                tmp_a = hit_anchors
                pat_dispatch = self._pat_anchor_dispatch
                while tmp_a:
                    lsb_a = tmp_a & -tmp_a
                    ai = lsb_a.bit_length() - 1
                    tmp_a ^= lsb_a
                    for rule_idx, pat in pat_dispatch[ai][1]:
                        bit = 1 << rule_idx
                        if not (fired & bit) and pat.search(text_lower):
                            fired |= bit
                            rid, rtxt, rsev, _, rcat, is_crit, _ = rule_data[rule_idx]
                            if strict and is_crit:
                                e_src = rule_excs[rule_idx]
                                raise ConstitutionalViolationError(
                                    str(e_src),
                                    rule_id=e_src.rule_id,
                                    severity=e_src.severity,
                                    action=action_200,
                                )
                            if violations is None:
                                violations = []
                            violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
            for rule_idx, pat in self._no_anchor_patterns:
                bit = 1 << rule_idx
                if not (fired & bit) and pat.search(text_lower):
                    fired |= bit
                    rid, rtxt, rsev, _, rcat, is_crit, _ = rule_data[rule_idx]
                    if strict and is_crit:
                        e_src = rule_excs[rule_idx]
                        raise ConstitutionalViolationError(
                            str(e_src),
                            rule_id=e_src.rule_id,
                            severity=e_src.severity,
                            action=action_200,
                        )
                    if violations is None:
                        violations = []
                    violations.append(Violation(rid, rtxt, rsev, action_200, rcat))
        return violations


__all__ = [
    "GovernanceMatcherMixin",
    "_HAS_AHO",
    "_HAS_RUST",
    "_RUST_ALLOW",
    "_RUST_DENY",
    "_RUST_DENY_CRITICAL",
    "_ac",
    "_rust",
]
