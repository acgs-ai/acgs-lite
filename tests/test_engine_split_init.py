"""Tests for engine init flags: warmup and freeze_gc (engine-split-init)."""

from __future__ import annotations

import gc
import time
from unittest.mock import patch

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine.core import GovernanceEngine


def _tiny_constitution() -> Constitution:
    return Constitution(
        name="tiny",
        hash="tinyhash",
        rules=[
            Rule(
                id="R1",
                text="block harmful",
                severity=Severity.CRITICAL,
                patterns=("harm",),
            ),
        ],
    )


class TestWarmupFlag:
    def test_warmup_true_runs_validate(self) -> None:
        const = _tiny_constitution()
        with patch.object(GovernanceEngine, "validate", autospec=True) as mock_validate:
            GovernanceEngine(const, warmup=True, freeze_gc=False)
            # Warmup only fires when Rust hot-path is available.
            engine_for_check = GovernanceEngine(const, warmup=False, freeze_gc=False)
            if engine_for_check._rust_validator is not None:
                assert mock_validate.call_count > 0

    def test_warmup_false_skips_validate(self) -> None:
        const = _tiny_constitution()
        with patch.object(GovernanceEngine, "validate", autospec=True) as mock_validate:
            GovernanceEngine(const, warmup=False, freeze_gc=False)
        assert mock_validate.call_count == 0

    def test_warmup_false_construction_is_faster(self) -> None:
        const = _tiny_constitution()
        engine = GovernanceEngine(const, warmup=False, freeze_gc=False)
        if engine._rust_validator is None:
            pytest.skip("Rust validator not available; warmup is a no-op anyway")

        # Cold construction without warmup should beat warm construction
        # by a comfortable margin. Use medians over a few runs.
        def _time(warmup: bool) -> float:
            samples = []
            for _ in range(3):
                t0 = time.perf_counter()
                GovernanceEngine(const, warmup=warmup, freeze_gc=False)
                samples.append(time.perf_counter() - t0)
            samples.sort()
            return samples[len(samples) // 2]

        no_warm = _time(False)
        warm = _time(True)
        # No warmup must not be slower than with warmup. Allow 20% slack.
        assert no_warm <= warm * 1.2 + 0.005


class TestFreezeGcFlag:
    def test_freeze_gc_false_does_not_freeze(self) -> None:
        const = _tiny_constitution()
        # Test the constructor's flag contract, independently of interpreter
        # internals changing the permanent generation during gc.collect().
        with patch("gc.freeze", wraps=gc.freeze) as freeze:
            GovernanceEngine(const, warmup=False, freeze_gc=False)
            freeze.assert_not_called()
            GovernanceEngine(const, warmup=False, freeze_gc=True)
            freeze.assert_called_once_with()
        gc.unfreeze()

    def test_freeze_gc_true_freezes_objects(self) -> None:
        const = _tiny_constitution()
        gc.unfreeze()
        before = gc.get_freeze_count()
        GovernanceEngine(const, warmup=False, freeze_gc=True)
        after = gc.get_freeze_count()
        assert after > before
        gc.unfreeze()


class TestBackwardCompatibleDefaults:
    def test_defaults_preserve_legacy_behavior(self) -> None:
        """Default constructor must still warmup and freeze_gc (no behavioral break)."""
        const = _tiny_constitution()
        gc.unfreeze()
        before = gc.get_freeze_count()
        GovernanceEngine(const)
        after = gc.get_freeze_count()
        assert after > before
        gc.unfreeze()
