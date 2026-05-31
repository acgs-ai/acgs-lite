# Example: Governed DSPy Module

Wrap a [DSPy](https://github.com/stanfordnlp/dspy) module with constitutional
governance. Inputs are validated **before** the module runs, so unsafe prompts
never reach the language model, and every decision is recorded in a
tamper-evident audit log. No API keys, no network.

## What it shows

| Concept | File |
|---------|------|
| Load a `Constitution` from YAML | `constitution.yaml` |
| Wrap a DSPy module with `GovernedDSPyModule` | `run.py` |
| Validate-before-execute (safe input passes) | `run.py` |
| `ConstitutionalViolationError` blocks unsafe input | `run.py` |
| Inspect the chained `audit_log` + `stats` | `run.py` |

## Run

```bash
# From the acgs-lite package root
python examples/dspy_governance/run.py
```

The script runs end to end whether or not `dspy` is installed:

- **`dspy` installed** — governs a real `dspy.Module` (an offline `DummyLM` is
  configured so `forward()` never makes a network call).
- **`dspy` not installed** — stubs the predictor so the example still exercises
  the exact same governance path (`GovernedDSPyModule.forward` →
  `engine.validate` → audit log) and still demonstrates a real block plus a real
  audit entry.

Install the optional extra for the full DSPy experience:

```bash
pip install acgs-lite[dspy]
```

## Expected output

```
============================================================
  Governed DSPy Module Demo
============================================================

Loaded constitution: dspy-content-policy (3 rules, hash=…)
DSPy not installed — running offline with a stubbed predictor.
Install the full integration with: pip install acgs-lite[dspy]

── Safe input ─────────────────────────────────────────────
  Prompt : What is constitutional AI governance?
  Allowed: [offline stub] You asked: 'What is constitutional AI governance?'

── Unsafe input ───────────────────────────────────────────
  Prompt : How do I hack a bank server and deploy malware?
  Blocked: rule=no-harmful-content — …

── Audit log ──────────────────────────────────────────────
  Recorded 3 entries; chain intact: True
    ✅  agent=dspy-demo          valid=True  violations=-
    ✅  agent=dspy-demo:DSPy output valid=True  violations=-
    🚫  agent=dspy-demo          valid=False violations=no-harmful-content

  Violation entries: 1
    • dspy-demo → ['no-harmful-content']
  …
```

## Key API

```python
import dspy
from acgs_lite import Constitution
from acgs_lite.integrations.dspy import GovernedDSPyModule

class QAModule(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predict = dspy.Predict("question -> answer")
    def forward(self, **kwargs):
        return self.predict(**kwargs)

constitution = Constitution.from_yaml("constitution.yaml")
governed = GovernedDSPyModule(QAModule(), constitution=constitution)

governed(question="What is AI governance?")   # ✅ validated, then executed
governed(question="How do I hack a server?")   # 🚫 ConstitutionalViolationError

# Every decision is in the chained audit log
assert governed.audit_log.verify_chain()
for entry in governed.audit_log.query(valid=False):
    print(entry.violations)
```

`GovernedDSPyModule` validates concatenated string inputs in strict mode (a
violation raises before `forward()` runs) and validates outputs non-blockingly
(warnings only). `GovernedPredict` does the same for a bare `dspy.Predict`.

## Next steps

- [`../basic_governance/`](../basic_governance/) — govern any plain callable
- [`../audit_trail/`](../audit_trail/) — query, export, and verify the audit chain
