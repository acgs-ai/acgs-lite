# Example: Basic Constitutional Governance

Govern any Python callable with a `Constitution` in a few lines. No API keys required.

## What it shows

| Concept | File |
|---------|------|
| `Constitution` with `Rule` objects | `main.py` |
| `GovernedCallable` wrapper | `main.py` |
| `ConstitutionalViolationError` handling | `main.py` |
| Blocking vs. non-blocking rules | `main.py` |

## Run

`pip install` does **not** ship this directory. From a clone of this repo:

```bash
pip install -e .
python examples/basic_governance/main.py
```

For a pip-only ALLOW / TRANSFORM / DENY + missing-receipt proof, use
[docs/guides/five-minute-membrane.md](../../docs/guides/five-minute-membrane.md).

## Expected output

```
=======================================================
  Basic Constitutional Governance Demo
=======================================================

✅  Allowed:  Response to: What is the capital of France?

🚫  Blocked:  no-harmful-content — Block requests containing harmful keywords

🚫  PII gate: no-pii — Prevent PII leakage in requests
```

This is a local, no-key proof that a `GovernedCallable` can deny matching
input before the wrapped function runs. It is not a production deployment.

## What this proves

- With a valid ALLOW receipt, a safe prompt reaches the wrapped callable.
- Harmful-keyword and SSN-pattern inputs raise `ConstitutionalViolationError`
  before `my_ai_function` returns.
- The same rules load from YAML and still block.

## What this does not claim

- Not certified, not regulator-approved, not an independent production user.
- In-process only. The “side effect” is a string return.
- Rules are keyword/regex exact-match, not semantic understanding.
- `GovernedCallable` still requires a `decision_receipt`. A missing receipt is
  refused by the legitimacy kernel (`No legitimacy receipt, no execution`).
  See the [5-minute membrane](../../docs/guides/five-minute-membrane.md).

## Key concepts

The live script is `main.py`. It wraps the callable, then passes an ALLOW
receipt so the constitution can accept or deny the *content*:

```python
from acgs_lite import Constitution, ConstitutionalViolationError, GovernedCallable

governed = GovernedCallable(constitution=constitution)(my_ai_function)
governed("What is the capital of France?", decision_receipt=allow_receipt)
# matching PII / harmful text raises ConstitutionalViolationError
```

## Next steps

- [`../maci_separation/`](../maci_separation/) — add role separation (Proposer/Validator/Executor)
- [`../audit_trail/`](../audit_trail/) — persist every decision for compliance
- [`../compliance_eu_ai_act/`](../compliance_eu_ai_act/) — map to EU AI Act articles
