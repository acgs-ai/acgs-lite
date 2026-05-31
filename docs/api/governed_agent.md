# GovernedAgent

`GovernedAgent` wraps any callable agent with constitutional governance. Every input and output passes through the validation pipeline before execution.

## Class Reference

::: acgs_lite.governed.GovernedAgent
    options:
      members:
        - __init__
        - run
        - arun
      show_source: true

## Examples

### Basic usage

```python
from acgs_lite import Constitution, GovernedAgent, MACIRole

constitution = Constitution.from_template("general")
agent = GovernedAgent(
    my_llm_agent,
    constitution=constitution,
    maci_role=MACIRole.EXECUTOR,
)

result = agent.run("summarise this document", governance_action="execute")
```

MACI is enforced by default. A governed call without an explicit role and
per-call `governance_action` is denied before the wrapped agent executes.

### With a proposer role

```python
from acgs_lite import MACIRole

agent = GovernedAgent(
    my_agent,
    constitution=constitution,
    maci_role=MACIRole.PROPOSER,
)

result = agent.run("draft this policy change", governance_action="propose")
```

### Async usage

```python
result = await agent.arun("process this request", governance_action="propose")
```
