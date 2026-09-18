# GovernedAgent

`GovernedAgent` wraps any callable agent with constitutional input and output
checks. It does not automatically intercept tools or side effects performed
inside the wrapped callable. Put `GovernedCallable` or an equivalent verified
authorization check at each real side-effect boundary.

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
def my_llm_agent(prompt: str) -> str:
    return f"Processed: {prompt}"

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

def my_agent(prompt: str) -> str:
    return f"Draft: {prompt}"

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

### Retries and side effects

Output validation retries call the wrapped agent again. Set
`side_effectful=True` for a wrapper whose invocation may perform a side effect;
construction then rejects a nonzero `max_retries`. This avoids treating an
output-format retry as authorization to repeat an external operation. A system
that needs retries must instead use an independently verified idempotency and
recovery contract at the actual tool boundary.
