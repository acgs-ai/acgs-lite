# MACI Architecture

MACI (Monitor-Approve-Control-Inspect) enforces separation of powers for AI agents.
No agent can validate its own output.

## The Four Roles

```
PROPOSER          VALIDATOR          EXECUTOR          OBSERVER
(Agent)     -->   (ACGS Engine) -->  (System)    -->   (Audit Log)
                       |
Generates the    Validates against   Only triggers    Cryptographically
proposed action. immutable YAML      if Validator     chains every
Cannot execute.  constitution.       approves.        boundary check.
```

| Role | Responsibility | Cannot |
|---|---|---|
| **Proposer** | Generate proposed actions | Execute or validate own output |
| **Validator** | Check actions against constitution | Propose or execute |
| **Executor** | Carry out approved actions | Propose or validate |
| **Observer** | Record audit trail | Modify decisions |

## Why Self-Validation Prevention Matters

Without MACI, an agent can propose an action and approve it in the same step.
This is the AI equivalent of a judge ruling on their own case. MACI makes this
structurally impossible -- the Proposer role physically cannot call validation functions.

## Code Example

```python
from acgs import MACIEnforcer, MACIRole, Constitution

constitution = Constitution.from_yaml("rules.yaml")
enforcer = MACIEnforcer(constitution=constitution)

# Proposer submits an action
proposal = enforcer.propose(
    agent_id="agent-1",
    role=MACIRole.PROPOSER,
    action="approve loan application",
)

# Validator checks it (must be a different agent/role)
decision = enforcer.validate(
    agent_id="validator-1",
    role=MACIRole.VALIDATOR,
    proposal=proposal,
)

# Executor acts on the decision
if decision.approved:
    enforcer.execute(
        agent_id="executor-1",
        role=MACIRole.EXECUTOR,
        proposal=proposal,
    )
```

!!! danger "Self-validation is blocked"
    If an agent with `MACIRole.PROPOSER` attempts to call `validate()`,
    a `MACIViolationError` is raised.

## GovernedAgent with MACI

```python
from acgs import GovernedAgent, MACIRole, Constitution

constitution = Constitution.from_yaml("rules.yaml")
agent = GovernedAgent(
    my_agent,
    constitution=constitution,
    maci_role=MACIRole.PROPOSER,
)
result = agent.run("draft change", governance_action="propose")
```

`GovernedAgent` enforces MACI by default. If `maci_role` or
`governance_action` is missing, execution is denied before the wrapped callable
runs. Use `enforce_maci=False` only for an explicit advisory-mode evaluation
where no side effect is allowed.

Actions are classified by risk level: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
Higher risk levels trigger stricter validation and escalation paths.
