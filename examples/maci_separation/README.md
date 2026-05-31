# Example: MACI Separation of Powers

MACI enforces constitutional separation of powers across AI agents.
No agent may validate its own output.

## Roles

| Role | Can | Cannot |
|------|-----|--------|
| **PROPOSER** | `propose`, `draft`, `suggest`, `amend` | `validate`, `execute`, `approve` |
| **VALIDATOR** | `validate`, `review`, `audit`, `verify` | `propose`, `execute`, `deploy` |
| **EXECUTOR** | `execute`, `deploy`, `apply`, `run` | `propose`, `validate` |
| **OBSERVER** | `read`, `query`, `export`, `observe` | anything that modifies state |

## Run

```bash
python packages/acgs-lite/examples/maci_separation/main.py
```

## Key API

```python
from acgs_lite import MACIEnforcer, MACIRole, MACIViolationError

enforcer = MACIEnforcer()

# Enforce role boundary — raises MACIViolationError on violation
enforcer.assign_role("agent-proposer", MACIRole.PROPOSER)
enforcer.check("agent-proposer", "propose")      # ✅
enforcer.check("agent-proposer", "validate")     # 🚫 raises MACIViolationError
```

## Design principle

```
[Agent A: PROPOSER] ──propose──▶ [Agent B: VALIDATOR] ──approve──▶ [Agent C: EXECUTOR]
                                                                           │
                    ◀───────────────── audit log ◀──────────────────────────
```

Agent B must be independent of Agent A. `MACIEnforcer` raises `MACIViolationError`
if the same role tries to both propose and validate.


## GovernedAgent integration

```python
from acgs_lite import GovernedAgent, MACIRole

agent = GovernedAgent(my_agent, maci_role=MACIRole.PROPOSER)
agent.run("draft change", governance_action="propose")  # ✅
agent.run("validate change", governance_action="validate")  # 🚫 MACIViolationError
```
