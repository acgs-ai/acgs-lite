# ACGS-2 Governance Engine (Rust/PyO3)

## Overview

This is the high-performance governance validation engine for ACGS-2, implemented in Rust as a PyO3 native extension for IP protection and maximum throughput.

**Constitutional Hash:** `608508a9bd224290`

## Modules

| Module | Purpose |
|--------|---------|
| `validator.rs` | Core governance validation engine with hot/full validation paths |
| `severity.rs` | Severity levels (ALLOW, DENY, DENY_CRITICAL) and classification |
| `verbs.rs` | Verb-based rule matching and action verification |
| `result.rs` | Validation result types and response structures |
| `context.rs` | Constitutional context and scope handling |
| `hash.rs` | Constitutional hash verification (SHA256) |

## Build

Build the extension in release mode:

```bash
cd packages/acgs-lite/rust
maturin build --release
```

The compiled wheel is placed in `target/wheels/`.

## Installation

Install the compiled wheel:

```bash
pip install target/wheels/acgs_lite_rust-*.whl
```

Or during development with editable install:

```bash
pip install -e .
```

## Testing

Run Rust unit tests:

```bash
cd packages/acgs-lite/rust
cargo test
```

Run integration tests from Python:

```bash
python -m pytest tests/core/shared/test_governance_engine.py -v
```

## Python API

### GovernanceValidator

Main class for governance validation.

```python
from acgs_lite_rust import GovernanceValidator, ALLOW, DENY, DENY_CRITICAL

validator = GovernanceValidator()

# Fast path validation (hot)
result = validator.validate_hot(
    content="user message",
    context={"policy_id": "pol_123"}
)

# Full validation with all checks
result = validator.validate_full(
    content="user message",
    context={"policy_id": "pol_123", "user_role": "admin"}
)

# Result contains:
# - severity: ALLOW, DENY, or DENY_CRITICAL
# - matched_rules: list of rule IDs that matched
# - reasoning: explanation of decision
```

### Severity Constants

```python
from acgs_lite_rust import ALLOW, DENY, DENY_CRITICAL

# ALLOW (0) — Message passes governance checks
# DENY (1) — Message violates policy but recoverable
# DENY_CRITICAL (2) — Message violates critical governance rule
```

## Fallback Behavior

When the Rust extension is not available (build failure, Python version mismatch), the system falls back to the pure Python implementation in `packages/acgs-lite/src/acgs_lite/engine/core.py`. The Python fallback aims to maintain feature parity with the Rust version (see tests for covered surface).

## Performance

Indicative targets:
- Hot path (fast validation): <0.5ms P99
- Full path (complete validation): <2ms P99
- Throughput: >5000 validations/sec

## Development Notes

- **PyO3 version**: 0.23 with abi3 (stable ABI) for Python 3.8+
- **Optimization level**: 3 (O3) with LTO and single codegen unit
- **Panic mode**: abort (prevents unwinding into Python)
- **Note**: Candle ML dependencies currently disabled (exp81 rebuild pending)
