# Share a reproducible governance walkthrough

A useful walkthrough lets another developer reproduce a governance boundary and
understand its limits. It can be a local script, a test fixture, or an integration
report. You do not need a production deployment to contribute useful evidence.

## Start with one action

Choose one concrete operation: sending an email, writing a file, or calling a
mock account service. Use a harmless stub while demonstrating the boundary.
Explain who proposes the action, what policy applies, and which callable performs it.

Run an allowed input and a denied input. If the example uses receipt-enforced
execution, also exercise a missing or mismatched receipt. Count callable
invocations so the reader can distinguish "denial was logged" from "execution
was prevented."

The [5-minute membrane](../guides/five-minute-membrane.md) is a starting point.
The [testing guide](../testing-governance.md) covers broader validation.

## Report template

Copy this structure into a GitHub Discussion or a proposed example README:

```markdown
# <Action> governed with <integration>

## Goal and boundary
- Proposed action:
- Actual side-effect callable:
- Where authorization is checked:

## Environment
- Published package version OR repository commit:
- Python version and operating system:
- Installation command and optional dependencies:
- External services required (or stubbed):

## Reproduce
<Minimal code and exact commands, with synthetic inputs>

## Observed results
| Case | Expected | Observed | Callable invocation count |
| --- | --- | --- | --- |
| Allowed | Executes | <result> | <count> |
| Denied | Refused | <result> | <count> |
| Missing receipt, if applicable | Refused | <result> | <count> |

## Evidence and limits
- Local, CI, simulation, or deployment observation:
- Audit backend and chain verification result:
- What this proves:
- What this does not claim:
- Known failures or untested paths:
```

## Keep the evidence reproducible

Record the exact command output and exit status. If a model or network service is
required, identify it and distinguish that dependency from the local governance
check. When presenting timing, report the workload, environment, and measurement
method. Label simulated results explicitly.

Avoid putting customer prompts or complete production audit trails in the report.
Use a minimal synthetic fixture that still reproduces the behavior. If the result
reveals an authorization bypass, use [private security reporting](../security.md).

## Turn the report into a contribution

1. Open a [Discussion](https://github.com/acgs-ai/acgs-lite/discussions) for an
   experience report or question, or an [issue](https://github.com/acgs-ai/acgs-lite/issues)
   for a reproducible defect.
2. Link the relevant adapter and state whether you used the published package or source.
3. For a code contribution, follow [Contributing](../contributing.md), add a focused
   regression, and run the repository's required gates.
4. For a documentation contribution, verify the commands, relative links, and strict
   MkDocs build. Treat local rendering and website publication as separate checks.

Maintainers can review the evidence without inferring production readiness,
compliance certification, or independent adoption from a demo.
