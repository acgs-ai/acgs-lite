"""Matcher mixin and optional acceleration imports for GovernanceEngine."""

from __future__ import annotations

from typing import Any

from acgs_lite.constitution import Severity
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
            _bm = data
            _a200 = action[:200]
            _vlist: list[Violation] = []
            _bv: Violation | None = None
            _has_halt = False
            _wa_lkup = self._rule_id_to_wa
            while _bm:
                _idx = (_bm & -_bm).bit_length() - 1
                _bm &= _bm - 1
                _rd = self._rule_data[_idx]
                _v = Violation(_rd[0], _rd[1], _rd[2], _a200, _rd[4])
                _vlist.append(_v)
                # Exclude WARN and HALT from the immediate-raise path;
                # HALT is handled by _post_dispatch_result with correct enforcement_action.
                _vwa = _wa_lkup.get(_rd[0], ViolationAction.BLOCK)
                if _vwa is ViolationAction.HALT:
                    _has_halt = True
                elif _bv is None and _v.severity.blocks() and _vwa is not ViolationAction.WARN:
                    _bv = _v
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
        for _cv in (_ctx_det, _ctx_desc):
            if _cv is not None and isinstance(_cv, str):
                _ctx_dec, _ctx_data = self._rust_validator.validate_hot(
                    _cv if _cv.islower() else _cv.lower()
                )
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
            _vlist: list[Violation] = []
            _bv_ctx: Violation | None = None
            _has_halt = False
            while _merged_bm:
                _idx = (_merged_bm & -_merged_bm).bit_length() - 1
                _merged_bm &= _merged_bm - 1
                _rd = self._rule_data[_idx]
                _v = Violation(_rd[0], _rd[1], _rd[2], _a200, _rd[4])
                _vlist.append(_v)
                _vwa_ctx = self._rule_id_to_wa.get(_rd[0], ViolationAction.BLOCK)
                if _vwa_ctx is ViolationAction.HALT:
                    _has_halt = True
                elif (
                    _bv_ctx is None
                    and _v.severity.blocks()
                    and _vwa_ctx is not ViolationAction.WARN
                ):
                    _bv_ctx = _v
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
            _bm = data
            _a200 = action[:200]
            _vlist: list[Violation] = []
            _bv_meta: Violation | None = None
            _has_halt = False
            while _bm:
                _idx = (_bm & -_bm).bit_length() - 1
                _bm &= _bm - 1
                _rd = self._rule_data[_idx]
                _v = Violation(_rd[0], _rd[1], _rd[2], _a200, _rd[4])
                _vlist.append(_v)
                _vwa_meta = self._rule_id_to_wa.get(_rd[0], ViolationAction.BLOCK)
                if _vwa_meta is ViolationAction.HALT:
                    _has_halt = True
                elif (
                    _bv_meta is None
                    and _v.severity.blocks()
                    and _vwa_meta is not ViolationAction.WARN
                ):
                    _bv_meta = _v
            if is_noop:
                fast_records.append(None)
            # strict=True is guaranteed at this call site (outer validate() guard).
            if _bv_meta is not None and not _has_halt:
                raise ConstitutionalViolationError(
                    f"Action blocked by rule {_bv_meta.rule_id}: {_bv_meta.rule_text}",
                    rule_id=_bv_meta.rule_id,
                    severity=_bv_meta.severity.value,
                    action=_a200,
                )
            return self._new_fast_result(valid=not _has_halt, violations=_vlist, action=action)
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
            _has_halt = False
            _bv: Violation | None = None
            for _v in _vlist:
                _vwa = _wa_lkup.get(_v.rule_id, ViolationAction.BLOCK)
                if _vwa is ViolationAction.HALT:
                    _has_halt = True
                elif _bv is None and _v.severity.blocks() and _vwa is not ViolationAction.WARN:
                    _bv = _v
            if _bv is None and _blocking:
                _bv = next(
                    (
                        v
                        for v in _vlist
                        if _wa_lkup.get(v.rule_id, ViolationAction.BLOCK)
                        not in (ViolationAction.WARN, ViolationAction.HALT)
                    ),
                    None,
                )
            if _bv is not None and strict and not _has_halt:
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
                    valid=not (_bv is not None or _has_halt),
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
        if positive_verb_mode:
            fired = 0
            _hit_anchors = 0
            for _end_idx, _payload in self._ac_iter(text_lower):
                _ptype = _payload[0]
                if _ptype == 0:
                    for rule_idx, kw_has_neg in _payload[1]:
                        if not kw_has_neg:
                            continue
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
                elif _ptype == 1:
                    _hit_anchors |= 1 << _payload[1]
                else:
                    _hit_anchors |= 1 << _payload[2]
                    for rule_idx, kw_has_neg in _payload[1]:
                        if not kw_has_neg:
                            continue
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
            if _hit_anchors or self._no_anchor_patterns:
                if _hit_anchors:
                    _tmp_a = _hit_anchors
                    while _tmp_a:
                        _lsb_a = _tmp_a & -_tmp_a
                        _ai = _lsb_a.bit_length() - 1
                        _tmp_a ^= _lsb_a
                        for rule_idx, pat in self._pat_anchor_dispatch[_ai][1]:
                            _bit = 1 << rule_idx
                            if not (fired & _bit) and pat.search(text_lower):
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
                for rule_idx, pat in self._no_anchor_patterns:
                    _bit = 1 << rule_idx
                    if not (fired & _bit) and pat.search(text_lower):
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
            return violations
        fired = 0
        _hit_anchors = 0
        for _end_idx, _payload in self._ac_iter(text_lower):
            _ptype = _payload[0]
            if _ptype == 0:
                for rule_idx, _kw_has_neg in _payload[1]:
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
            elif _ptype == 1:
                _hit_anchors |= 1 << _payload[1]
            else:
                _hit_anchors |= 1 << _payload[2]
                for rule_idx, _kw_has_neg in _payload[1]:
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
        if _hit_anchors or self._no_anchor_patterns:
            if _hit_anchors:
                _tmp_a = _hit_anchors
                while _tmp_a:
                    _lsb_a = _tmp_a & -_tmp_a
                    _ai = _lsb_a.bit_length() - 1
                    _tmp_a ^= _lsb_a
                    for rule_idx, pat in self._pat_anchor_dispatch[_ai][1]:
                        _bit = 1 << rule_idx
                        if not (fired & _bit) and pat.search(text_lower):
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
            for rule_idx, pat in self._no_anchor_patterns:
                _bit = 1 << rule_idx
                if not (fired & _bit) and pat.search(text_lower):
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
