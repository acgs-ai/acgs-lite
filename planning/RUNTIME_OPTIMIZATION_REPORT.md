# Runtime Optimization Report

Audit date: 2026-04-24  
Scope: `import acgs_lite` cold start, module load graph

---

## Baseline

| Metric | Value |
|--------|-------|
| Cold import time | **3563 ms** |
| Modules loaded | 92 |
| Python version | 3.14.3 |
| Platform | Linux x86_64 |

Measured with:
```python
import time, sys
sys.path.insert(0, 'src')
t0 = time.perf_counter()
import acgs_lite
t1 = time.perf_counter()
print(f'{(t1-t0)*1000:.1f}ms')
```

---

## Root Cause

**File:** `src/acgs_lite/scoring.py:25`

```python
# Before — executed at module import time
try:
    from transformers import pipeline   # ← pulls torch + sklearn + transformers
    TRANSFORMERS_AVAILABLE = True
except Exception:
    TRANSFORMERS_AVAILABLE = False
```

`from transformers import pipeline` at module level loads the full `transformers` library
including `torch` (~900ms) and `sklearn` (~370ms) on every `import acgs_lite` — even when
no ML scoring is needed.

**Import chain:**
```
acgs_lite.__init__
  → acgs_lite.scoring (line 176)
    → from transformers import pipeline (line 25)
      → torch (~900ms)
      → sklearn (~370ms)
      → transformers.utils (~200ms)
      → ... 23 other transformers submodules
```

This violated the project's own rule: *"Keep optional integrations lazy — import optional
SDKs only inside guarded code paths."* (`CLAUDE.md` CK-001, `.claude/rules/coding-style.md`)

---

## Files Inspected

| File | Finding |
|------|---------|
| `src/acgs_lite/scoring.py` | Eager `from transformers import pipeline` at module level |
| `src/acgs_lite/__init__.py:176` | `from acgs_lite.scoring import ...` — triggers scoring.py load |
| `src/acgs_lite/engine/core.py` | No heavy imports at module level — clean |
| `src/acgs_lite/constitution/` | No heavy imports at module level — clean |
| `src/acgs_lite/integrations/` | All heavy deps already guarded — clean |

---

## Fix Applied

**`src/acgs_lite/scoring.py`**

```python
# After — no import at module level
import importlib.util

# Fast probe: no actual load, just checks if package is findable
TRANSFORMERS_AVAILABLE: bool = importlib.util.find_spec("transformers") is not None
```

```python
# Lazy import deferred to first TransformerScorer.classifier access
@property
def classifier(self) -> Any:
    if self._classifier is None:
        try:
            from transformers import pipeline as _pipeline  # loaded once, on first use
        except Exception as exc:
            raise ImportError(
                "transformers and torch are required for TransformerScorer. "
                "Install with: pip install transformers torch"
            ) from exc
        ...
```

**Behavior preserved:**
- `TRANSFORMERS_AVAILABLE` is still `True` when transformers is installed, `False` otherwise
- `TransformerScorer.__init__` still raises `ImportError` immediately if transformers is absent
- `TransformerScorer.classifier` raises `ImportError` on first use if transformers is broken-installed
- `RuleBasedScorer` and `ConstitutionalImpactScorer` behavior unchanged

---

## Results

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Cold import time | 3563 ms | **218 ms** | **−3345 ms (−94%)** |
| Modules loaded | 92 | 92 | 0 (same count, different set at import time) |
| Test suite | 5477 passed | 5477 passed | 0 regressions |
| `TRANSFORMERS_AVAILABLE` | True | True | unchanged |
| `RuleBasedScorer().score("delete production database")` | 0.95 | 0.95 | unchanged |

---

## Remaining Performance Risks

| Risk | Severity | Notes |
|------|----------|-------|
| `acgs_lite.__init__` imports ~176 symbols eagerly | Low | Mostly lightweight; main cost was scoring.py (now fixed) |
| `TransformerScorer.classifier` first-use cost | Low-Medium | ~3.5s on first call (expected — model load) |
| `from acgs_lite_rust import ...` probe at scoring module level | Negligible | `find_spec` fast path already used |
| Constitution package (`__init__.py`) imports many submodules | Low | Measured at <50ms total; no heavy deps |

---

## Next Recommended Optimizations

1. **Profile `__init__.py` symbol surface** — 176+ public exports may be pulling in more than necessary. A `__getattr__`-based lazy public API would reduce startup further but requires API audit.
2. **Benchmark `engine/core.py` hot path** — the Rust fast path already benchmarks well; measure Python fallback against the Rust path to quantify the value of the Rust companion.
3. **Add import-time regression test** — assert `time_to_import(acgs_lite) < 500ms` in CI to prevent future regressions (no test currently guards import time).
