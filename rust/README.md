# ACGS-Lite Governance Engine (Rust Workspace)

## Overview

Optional high-performance Rust workspace for ACGS-Lite governance validation.
The pure-Rust core crate (`acgs-validator-core`) has zero FFI dependencies and
powers the PyO3 Python companion (`acgs_lite_rust`), the WASM binding
(`acgs-validator-wasm`), and the SpacetimeDB reducer module.

**Constitutional Hash:** `608508a9bd224290`

## Workspace Members

| Member | Crate | Purpose |
|--------|-------|---------|
| `core/` | `acgs-validator-core` | Pure-Rust Aho-Corasick + regex hot-path validator, context matching, and constitutional hashing |
| `pyo3/` | `acgs_lite_rust` | PyO3 abi3 Python companion wheel built with `maturin` |
| `wasm/` | `acgs-validator-wasm` | `wasm-bindgen` binding for edge runtimes (Cloudflare Workers) |
| `spacetime_governance/` | `acgs-spacetime-governance` | SpacetimeDB MACI governance tables and reducers |

### Core Modules (`rust/core/src/`)

| Module | Purpose |
|--------|---------|
| `validator.rs` | Core governance validation engine (`validate_hot`, `validate_hot_u128`, `validate_full`, `validate`) |
| `severity.rs` | Severity levels (`Critical`, `High`, `Medium`, `Low`) and decision codes (`ALLOW`, `DENY_CRITICAL`, `DENY`) |
| `verbs.rs` | Positive/negative verb and security-keyword detection (mirrors Python `constitution`) |
| `result.rs` | Validation result types (`Decision`, `Violation`, `ValidationResult`, `ViolationRecord`) |
| `context.rs` | `action_detail` / `action_description` context matching with UTF-8 safe truncation |
| `hash.rs` | Streaming SHA-256 constitutional hash computation |

## Build

Build the PyO3 companion wheel in release mode from the repository root:

```bash
maturin build --release --locked --manifest-path rust/pyo3/Cargo.toml --out dist/rust-wheels
pip install dist/rust-wheels/acgs_lite_rust-*.whl
```

## Testing & Linting

Run Rust unit tests and clippy checks from `rust/`:

```bash
cd rust
cargo test --locked -p acgs-validator-core
cargo clippy --locked -p acgs-validator-core -p acgs_lite_rust -p acgs-validator-wasm -- -D warnings
cargo fmt --check
```

Run Python integration tests against the installed wheel from the repository root:

```bash
python -m pytest tests/test_coverage_rust_ext.py tests/test_coverage_engine_extra.py -v
```

## Python Companion API

`acgs_lite.engine.GovernanceEngine` automatically uses `acgs_lite_rust` when installed
(for constitutions with up to 63 active rules on the legacy `i64` hot-path ABI). Direct usage:

```python
from acgs_lite_rust import ALLOW, DENY, DENY_CRITICAL, GovernanceValidator

# Decision code constants:
# ALLOW = 0          — action passes governance checks
# DENY_CRITICAL = 1  — critical violation under strict mode (data = rule_idx)
# DENY = 2           — one or more violations matched (data = fired rule bitmask)

validator = GovernanceValidator(
    kw_to_idxs={"bypass": [(0, True)]},
    anchor_dispatch_py=[],
    no_anchor_pats_py=[],
    rule_data_py=[("SEC-001", "Do not bypass controls", "high", "security", False)],
    positive_verbs_py=["run", "audit", "verify"],
    strict=True,
    context_rules_py=[],
    const_hash="608508a9bd224290",
)

decision, data = validator.validate_hot("bypass safety controls")
assert decision == DENY and data == 0b1
```

## Fallback Behavior

When `acgs_lite_rust` is not installed (or when a rule uses regex constructs unsupported
by Rust's `regex` crate such as look-around/backreferences, or when non-ASCII normalization
is required), `src/acgs_lite/engine/core.py` transparently falls back to the pure-Python
matcher.

## Build Configuration

- **PyO3 version**: `0.29` with `abi3-py38` stable ABI
- **Release profile**: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`
