# GovernedAgent

`GovernedAgent` wraps any callable agent with constitutional input and output
checks. It does not automatically intercept tools or side effects performed
inside the wrapped callable. Put `GovernedCallable` or an equivalent verified
authorization check at each real side-effect boundary.

## Payload contract

`run()` and `arun()` enforce the same contract as `GovernedCallable`. The input
string, the caller's keyword arguments and the agent's output must be
JSON-native (exact `dict` with `str` keys, `list`, `tuple`, `str`, `int`,
`bool`, finite `float`, `None`, UTF-8 `bytes`). Each one is evaluated in full;
nothing is truncated. A value over 10,000 characters denies with
`GOVERNANCE-PAYLOAD-OVERSIZE` and a non-JSON value denies with
`GOVERNANCE-PAYLOAD-UNEVALUABLE`, both as `GovernancePayloadError`.

A blocking violation denies under `strict=False` as well as under the default
`strict=True`: the agent does not run, or its output is not returned.
Non-blocking (warning) violations pass in both modes and are audited.

An agent that returns a framework object (a message or response class) is
denied on output. Return or convert to a JSON-native value (for example
`message.content`, or `model.model_dump(mode="json")`). To skip output
enforcement deliberately, pass `validate_output=False`; that also turns off the
structured-output request injection. Keyword arguments are governed as passed:
pass handles such as callbacks or clients through a closure or the wrapped
agent's constructor, not as `run()` keyword arguments. The structured-output
request that `GovernedAgent` injects is generated from the constitution and is
not evaluated as caller content.

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

MACI is enforced by default. A governed call without an explicit role and a
`governance_action` is denied before the wrapped agent executes.

### Pinning the action label

The `governance_action` label decides which MACI check runs and which rules
with a `condition` on it apply. Pin it in the constructor when the operator,
not the caller, should decide it:

```python
agent = GovernedAgent(
    my_llm_agent,
    constitution=constitution,
    maci_role=MACIRole.EXECUTOR,
    governance_context={"governance_action": "execute"},
)

agent.run("summarise this document")                              # checked as "execute"
agent.run("summarise this document", governance_action="execute")  # equal: allowed
agent.run("summarise this document", governance_action="read")     # GovernanceError, agent not called
```

A pinned label is what MACI checks, what rule conditions see and what the CDP
record carries. A per-call label that differs from it raises `GovernanceError`
(`rule_id="MACI-ACTION"`) before the wrapped agent runs. If the label is not
pinned, the per-call `governance_action` is asserted by the caller of `run()`,
so it must never be derived from model output, tool arguments or request data.

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
