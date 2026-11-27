"""Tests for GovernanceEngine feature detection and wiring of Rust validate_hot_u128."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import core as engine_core
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.engine.matcher import _HAS_RUST, _RUST_ALLOW, _RUST_DENY, _RUST_DENY_CRITICAL, _rust
from acgs_lite.errors import ConstitutionalViolationError


def _make_rules(count: int, *, critical_indices: set[int] | None = None) -> list[Rule]:
    crits = critical_indices or set()
    return [
        Rule(
            id=f"R-{i:03d}",
            text=f"Block rule {i}",
            severity=Severity.CRITICAL if i in crits else Severity.HIGH,
            keywords=[f"kw{i:03d}"],
        )
        for i in range(count)
    ]


class _LegacyWheelValidator:
    """Simulates a pre-u128 acgs_lite_rust wheel exposing only 64-bit validate_hot."""

    def __init__(self, kw_map: dict[str, list[tuple[int, bool]]], *_args: Any) -> None:
        self._kw_map = kw_map
        self.hot_calls: list[str] = []

    def validate_hot(self, text: str) -> tuple[int, int]:
        self.hot_calls.append(text)
        mask = 0
        for kw, entries in self._kw_map.items():
            if kw in text:
                for idx, _ in entries:
                    mask |= 1 << idx
        return (_RUST_DENY, mask) if mask else (_RUST_ALLOW, 0)


class _U128WheelValidator:
    """Simulates an acgs_lite_rust wheel exposing 128-bit validate_hot_u128."""

    def __init__(
        self,
        kw_map: dict[str, list[tuple[int, bool]]],
        _anchor: Any,
        _no_anchor: Any,
        rule_data: list[tuple[str, str, str, str, bool]],
        _pos_verbs: list[str],
        strict: bool,
        *_rest: Any,
    ) -> None:
        self._kw_map = kw_map
        self._rule_data = rule_data
        self._strict = strict
        self.u128_calls: list[str] = []
        self.legacy_calls: list[str] = []

    def validate_hot(self, text: str) -> tuple[int, int]:
        self.legacy_calls.append(text)
        raise AssertionError("validate_hot must not be called when validate_hot_u128 exists")

    def validate_hot_u128(self, text: str) -> tuple[int, int]:
        self.u128_calls.append(text)
        mask = 0
        for kw, entries in self._kw_map.items():
            if kw in text:
                for idx, _ in entries:
                    if self._strict and self._rule_data[idx][4]:
                        return (_RUST_DENY_CRITICAL, idx)
                    mask |= 1 << idx
        return (_RUST_DENY, mask) if mask else (_RUST_ALLOW, 0)


class TestRustU128FeatureDetection:
    def test_legacy_wheel_caps_rust_at_63_rules_and_uses_validate_hot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_mod = SimpleNamespace(GovernanceValidator=_LegacyWheelValidator)
        monkeypatch.setattr(engine_core, "_HAS_RUST", True)
        monkeypatch.setattr(engine_core, "_rust", fake_mod)

        eng63 = GovernanceEngine(
            Constitution(name="legacy-63", rules=_make_rules(63)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert isinstance(eng63._rust_validator, _LegacyWheelValidator)
        res = eng63.validate("trigger kw000 and kw062")
        assert res.valid is False
        assert {v.rule_id for v in res.violations} == {"R-000", "R-062"}
        assert eng63._rust_validator.hot_calls == ["trigger kw000 and kw062"]

        eng64 = GovernanceEngine(
            Constitution(name="legacy-64", rules=_make_rules(64)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert eng64._rust_validator is None
        res64 = eng64.validate("trigger kw063")
        assert res64.valid is False
        assert [v.rule_id for v in res64.violations] == ["R-063"]

    def test_u128_wheel_enables_up_to_127_rules_and_falls_back_at_128(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_mod = SimpleNamespace(GovernanceValidator=_U128WheelValidator)
        monkeypatch.setattr(engine_core, "_HAS_RUST", True)
        monkeypatch.setattr(engine_core, "_rust", fake_mod)

        eng127 = GovernanceEngine(
            Constitution(name="u128-127", rules=_make_rules(127)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert isinstance(eng127._rust_validator, _U128WheelValidator)
        res = eng127.validate("trigger kw000 kw062 kw063 kw064 kw126")
        assert res.valid is False
        assert {v.rule_id for v in res.violations} == {
            "R-000",
            "R-062",
            "R-063",
            "R-064",
            "R-126",
        }
        assert eng127._rust_validator.u128_calls == ["trigger kw000 kw062 kw063 kw064 kw126"]
        assert eng127._rust_validator.legacy_calls == []

        eng128 = GovernanceEngine(
            Constitution(name="u128-128", rules=_make_rules(128)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert eng128._rust_validator is None
        res128 = eng128.validate("trigger kw127")
        assert res128.valid is False
        assert [v.rule_id for v in res128.violations] == ["R-127"]

    def test_u128_wheel_strict_and_context_paths_use_validate_hot_u128(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_mod = SimpleNamespace(GovernanceValidator=_U128WheelValidator)
        monkeypatch.setattr(engine_core, "_HAS_RUST", True)
        monkeypatch.setattr(engine_core, "_rust", fake_mod)

        eng = GovernanceEngine(
            Constitution(name="u128-strict", rules=_make_rules(127, critical_indices={126})),
            strict=True,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert isinstance(eng._rust_validator, _U128WheelValidator)

        # Strict action hitting high rule at bit 64 (above i64 range).
        with pytest.raises(ConstitutionalViolationError) as exc_high:
            eng.validate("trigger kw064")
        assert exc_high.value.rule_id == "R-064"

        # Strict action hitting critical rule at index 126.
        with pytest.raises(ConstitutionalViolationError) as exc_crit:
            eng.validate("trigger kw126")
        assert exc_crit.value.rule_id == "R-126"
        assert exc_crit.value.severity == "critical"

        # Strict context (action_detail + action_description) hitting rules 64 and 126.
        with pytest.raises(ConstitutionalViolationError) as exc_ctx:
            eng.validate(
                "clean action",
                context={"action_detail": "detail kw064", "action_description": "desc kw126"},
            )
        assert exc_ctx.value.rule_id == "R-126"
        assert eng._rust_validator.legacy_calls == []
        assert "detail kw064" in eng._rust_validator.u128_calls
        assert "desc kw126" in eng._rust_validator.u128_calls

    def test_defensive_fallback_if_instance_lacks_validate_hot_u128_above_63_rules(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _LyingFactory:
            @staticmethod
            def validate_hot_u128(_text: str) -> tuple[int, int]:
                return (_RUST_ALLOW, 0)

            def __new__(cls, *args: Any, **kwargs: Any) -> Any:
                return _LegacyWheelValidator(args[0])

        fake_mod = SimpleNamespace(GovernanceValidator=_LyingFactory)
        monkeypatch.setattr(engine_core, "_HAS_RUST", True)
        monkeypatch.setattr(engine_core, "_rust", fake_mod)

        eng = GovernanceEngine(
            Constitution(name="defensive-64", rules=_make_rules(64)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert eng._rust_validator is None
        res = eng.validate("trigger kw063")
        assert res.valid is False
        assert [v.rule_id for v in res.violations] == ["R-063"]

    @pytest.mark.parametrize("bad_attr", [None, object(), "not-callable"])
    def test_non_callable_validate_hot_u128_never_fails_open_above_63_rules(
        self, monkeypatch: pytest.MonkeyPatch, bad_attr: Any
    ) -> None:
        class _BrokenAttrValidator(_LegacyWheelValidator):
            validate_hot_u128 = bad_attr

            def validate_hot(self, text: str) -> tuple[int, int]:
                # Simulate i64 truncation: bits >= 64 dropped.
                dec, mask = super().validate_hot(text)
                truncated = mask & ((1 << 64) - 1)
                return (dec, truncated) if truncated else (_RUST_ALLOW, 0)

        fake_mod = SimpleNamespace(GovernanceValidator=_BrokenAttrValidator)
        monkeypatch.setattr(engine_core, "_HAS_RUST", True)
        monkeypatch.setattr(engine_core, "_rust", fake_mod)

        eng70 = GovernanceEngine(
            Constitution(name="broken-attr-70", rules=_make_rules(70)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert eng70._rust_validator is None
        res = eng70.validate("trigger kw065")
        assert res.valid is False
        assert [v.rule_id for v in res.violations] == ["R-065"]

        # <= 63 rules still safely falls back to callable validate_hot without TypeError.
        eng10 = GovernanceEngine(
            Constitution(name="broken-attr-10", rules=_make_rules(10)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert isinstance(eng10._rust_validator, _BrokenAttrValidator)
        res10 = eng10.validate("trigger kw009")
        assert res10.valid is False
        assert [v.rule_id for v in res10.violations] == ["R-009"]

    def test_hot_slot_swap_invalidates_cached_rust_hot_fn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_mod = SimpleNamespace(GovernanceValidator=_U128WheelValidator)
        monkeypatch.setattr(engine_core, "_HAS_RUST", True)
        monkeypatch.setattr(engine_core, "_rust", fake_mod)

        eng = GovernanceEngine(
            Constitution(name="swap-hot", rules=_make_rules(5)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert eng._rust_hot_owner is eng._rust_validator
        assert eng.validate("trigger kw001").valid is False
        assert eng._rust_validator.u128_calls == ["trigger kw001"]

        # Swap _hot[10] to a legacy validate_hot-only mock without updating _rust_validator.
        swapped = _LegacyWheelValidator({"swapped_kw": [(2, False)]})
        hot = list(eng._hot)
        hot[10] = swapped
        eng._hot = tuple(hot)

        res = eng.validate("hit swapped_kw")
        assert res.valid is False
        assert [v.rule_id for v in res.violations] == ["R-002"]
        assert swapped.hot_calls == ["hit swapped_kw"]

    def test_live_rust_wheel_supports_127_rules_end_to_end(self) -> None:
        if (
            not _HAS_RUST
            or _rust is None
            or not callable(getattr(_rust.GovernanceValidator, "validate_hot_u128", None))
        ):
            pytest.skip("acgs_lite_rust with validate_hot_u128 not installed")

        # 127 rules: rules 0..125 HIGH, rule 126 CRITICAL.
        const127 = Constitution(name="live-127", rules=_make_rules(127, critical_indices={126}))
        eng_non_strict = GovernanceEngine(
            const127, strict=False, audit_mode="fast", warmup=False, freeze_gc=False
        )
        assert eng_non_strict._rust_validator is not None

        multi = eng_non_strict.validate("trigger kw000 kw062 kw063 kw064 kw125 kw126")
        assert multi.valid is False
        assert {v.rule_id for v in multi.violations} == {
            "R-000",
            "R-062",
            "R-063",
            "R-064",
            "R-125",
            "R-126",
        }
        assert eng_non_strict.validate("completely clean action").valid is True

        eng_strict = GovernanceEngine(
            const127, strict=True, audit_mode="fast", warmup=False, freeze_gc=False
        )
        assert eng_strict._rust_validator is not None
        with pytest.raises(ConstitutionalViolationError) as exc_hi:
            eng_strict.validate("trigger kw064")
        assert exc_hi.value.rule_id == "R-064"
        with pytest.raises(ConstitutionalViolationError) as exc_crit:
            eng_strict.validate("trigger kw126")
        assert exc_crit.value.rule_id == "R-126"
        with pytest.raises(ConstitutionalViolationError) as exc_ctx:
            eng_strict.validate("clean action", context={"action_detail": "detail kw064"})
        assert exc_ctx.value.rule_id == "R-064"

        # 128 rules: safely falls back to Python.
        eng128 = GovernanceEngine(
            Constitution(name="live-128", rules=_make_rules(128)),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert eng128._rust_validator is None
        res128 = eng128.validate("trigger kw127")
        assert res128.valid is False
        assert [v.rule_id for v in res128.violations] == ["R-127"]

        # <= 127 rules with > 127 distinct regex anchors: Rust raises ValueError
        # (TooManyAnchors) and GovernanceEngine falls back cleanly to Python.
        anchor_rules = [
            Rule(
                id=f"ANC-{i:03d}",
                text=f"Block anchored patterns {i}",
                severity=Severity.HIGH,
                patterns=[rf"anch{i:03d}a_[0-9]+", rf"anch{i:03d}b_[0-9]+"],
            )
            for i in range(64)  # 64 rules, 128 distinct anchors
        ]
        eng_many_anchors = GovernanceEngine(
            Constitution(name="live-128-anchors", rules=anchor_rules),
            strict=False,
            audit_mode="fast",
            warmup=False,
            freeze_gc=False,
        )
        assert len(eng_many_anchors._pat_anchor_dispatch) > 127
        assert eng_many_anchors._rust_validator is None
        res_anchor = eng_many_anchors.validate("payload anch063b_999")
        assert res_anchor.valid is False
        assert [v.rule_id for v in res_anchor.violations] == ["ANC-063"]
