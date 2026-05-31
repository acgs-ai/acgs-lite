# Adapting smolagents patterns into ACGS-Lite

Research notes and design record for the smolagents integration shipped in
`acgs_lite.integrations.smolagents` and the supporting code analyzer in
`acgs_lite.engine.code_analysis`.

## Why smolagents is a good fit

ACGS-Lite and HuggingFace [`smolagents`](https://github.com/huggingface/smolagents)
are architectural opposites that compose cleanly:

| | smolagents | ACGS-Lite |
| --- | --- | --- |
| Role | Minimal agent **runtime** (~1k-LOC ReAct loop) | Policy **decision/enforcement** layer |
| Action language | Python **code** the agent writes and executes | n/a — wraps other frameworks |
| Governance | Almost none (sandbox only) | Constitution, MACI, tamper-evident audit |

smolagents' thesis — *agents act by writing code* — means the generated code is
exactly the artifact a constitutional layer wants to inspect **before** it runs.
And smolagents exposes three stable hooks that map almost 1:1 onto
`GovernanceEngine.validate()`:

| smolagents hook | Signature | ACGS mapping |
| --- | --- | --- |
| `executor=` (custom `PythonExecutor`) | `(code, …) -> result` | `validate(code, strict)` pre-execution |
| `final_answer_checks` | `(answer, memory) -> bool` | `validate(output, strict=False)` gate |
| `step_callbacks` | `(step, agent) -> None` | per-step audit logging |

## What we adapted

### Track B — AST code analysis (core)

`engine/code_analysis.py` ports the security model of smolagents'
`LocalPythonExecutor` into a reusable governance primitive,
`CodeActionValidator`. Where the engine's keyword/regex matcher reasons about
*strings*, this reasons about the **structure** of Python source:

- **Import control** — unauthorized imports (`CODE-IMPORT-FORBIDDEN`, HIGH) and
  high-risk imports like `os`/`subprocess`/`socket`/`pickle`
  (`CODE-IMPORT-CRITICAL`, CRITICAL); private-submodule access
  (`CODE-IMPORT-PRIVATE`, MEDIUM).
- **Dynamic execution** — `eval`/`exec`/`compile`/`__import__` (`CODE-EXEC`,
  CRITICAL).
- **Dangerous calls** — dotted targets like `os.system`, `subprocess.Popen`,
  `shutil.rmtree` (`CODE-DANGEROUS-CALL`, CRITICAL).
- **Sandbox-escape attributes** — `__subclasses__`, `__globals__`, `__bases__`,
  … (`CODE-DUNDER-ACCESS`, HIGH).
- **Introspection builtins** — `getattr`/`globals`/… (`CODE-INTROSPECTION`,
  MEDIUM, opt-out).

It emits plain `Violation` records, so it integrates two ways:

```python
validator = CodeActionValidator()
findings = validator.analyze(code)                 # direct

engine.add_validator(validator.as_engine_validator())
engine.validate(code, context={"action_type": "code"})   # one decision,
                                                          # one audit entry
```

The `as_engine_validator()` wrapper only parses an action as Python when
`context["action_type"] == "code"`, so ordinary natural-language validations are
never affected.

Design choices:

- **Unparseable input returns no findings** — a partial/non-Python snippet falls
  through to the engine's string rules rather than being blocked on a syntax
  error.
- **Everything is configurable** — authorized imports, critical imports, and
  dangerous calls are constructor arguments; `flag_medium_builtins=False`
  silences introspection noise.
- It **never executes code**.

### Track A — the smolagents adapter

`integrations/smolagents.py` wires the analyzer and the engine into smolagents:

- `SmolagentsGovernor(GovernedBase)` — owns one engine + audit log; registers
  the AST validator; produces all three hooks.
- `GovernedPythonExecutor` — wraps any `PythonExecutor`, validates each code
  action first (strict mode → raises and the inner executor never runs), and
  delegates everything else by `__getattr__` so it survives smolagents version
  changes.
- `SmolagentsGovernor.wrap(agent)` — attaches governance to an existing agent in
  place (executor + `final_answer_checks` + `step_callbacks`).
- `build_governed_code_agent(...)` — convenience constructor (the only path that
  imports smolagents).

smolagents is **not** imported at module load; the governor/executor are
duck-typed and unit-testable without it. Install with
`pip install acgs-lite[smolagents]`.

```python
from smolagents import CodeAgent, InferenceClientModel
from acgs_lite.integrations.smolagents import SmolagentsGovernor

governor = SmolagentsGovernor()
agent = CodeAgent(tools=[...], model=InferenceClientModel())
governor.wrap(agent)
agent.run("Analyse sales.csv and report the trend")
print(governor.stats)   # validations, compliance rate, audit-chain validity
```

## Deliberately not adapted

- **CodeAgent-vs-JSON thesis** — smolagents' product bet, irrelevant to a
  governance layer.
- **`managed_agents` multi-agent orchestration** — overlaps with frameworks ACGS
  already wraps; ACGS stays a layer, not a runtime.
- **A full `MemoryStep` audit schema in core** — the step callback reuses the
  existing `AuditLog`/`AuditEntry` instead. Adopting smolagents'
  `SystemPromptStep`/`TaskStep`/`PlanningStep`/`ActionStep` split as a richer
  agent-run audit schema remains a possible future enhancement.

## References

- smolagents repo: <https://github.com/huggingface/smolagents>
- Secure code execution (LocalPythonExecutor internals):
  <https://huggingface.co/docs/smolagents/en/tutorials/secure_code_execution>
- Agents API (hooks, executor injection):
  <https://huggingface.co/docs/smolagents/en/reference/agents>
