# Tool-Call Governance

`acgs_lite.tool_calls` evaluates one tool call against a constitution and returns
one of three verdicts. It is the shared core for framework adapters: the adapter
maps the verdict to its framework's own way of refusing or pausing a tool call.

The module is imported from its own path. It is not re-exported from the
top-level `acgs_lite` package.

```python
from acgs_lite import Constitution
from acgs_lite.tool_calls import ToolCallGovernor, Verdict

governor = ToolCallGovernor(Constitution.default(), agent_id="support-agent")
decision = governor.evaluate("send_email", {"to": "a@example.com", "body": "Hi"})

if decision.verdict is Verdict.DENY:
    raise PermissionError(decision.reason)
if decision.verdict is Verdict.REVIEW:
    ...  # ask a human before running the tool
```

## Verdicts

| Verdict | When |
|---------|------|
| `ALLOW` | No blocking rule matched. Matched warn-only rules are listed in `warning_rule_ids`. |
| `REVIEW` | Every matched rule has the workflow action `require_human_review` or `escalate_to_senior`. |
| `DENY` | Any other matched rule, or governance could not be evaluated. |

A blocking rule is never downgraded to `REVIEW` because a review rule matched too.

## Failure behaviour

`ToolCallGovernor.evaluate` is fail-closed. If formatting or validation raises
an `Exception`, the verdict is `DENY` and `GovernanceDecision.error` holds the
exception type and message. Arguments nested deeper than `MAX_ARGUMENT_DEPTH`
levels are denied, not partially rendered.

Three cases still propagate out of `evaluate`. In each the caller gets an
exception, not an `ALLOW`:

- cancellation signals such as `KeyboardInterrupt` and `asyncio.CancelledError`;
- an exception whose own `__str__` raises while the `DENY` decision is built;
- a logging filter or handler on the `acgs_lite.tool_calls` logger that raises.

Treat an exception from `evaluate` as a denial.

A rule's workflow action decides the verdict, not its severity alone: a
`CRITICAL` rule with the workflow action `warn` gives `ALLOW` with the rule in
`warning_rule_ids`, because the engine reports it as a warning.

`GovernanceDecision.reason` names the matched rules. It never contains argument
values.

## What the rules see

`format_tool_call` renders the tool name and every argument leaf as one
`path: value` line, and repeats identifiers such as `skip_audit` or
`disableLogging` as plain words, so a keyword rule for `skip audit` matches
both. Pass `tool_call_formatter=` to `ToolCallGovernor` to replace it.

Whitespace in a value is collapsed to single spaces. A value that contains
hidden control characters (vertical tab, form feed, the `\x1c`-`\x1f`
separators, NEL and similar) is rendered twice: once with them treated as
spaces, and once with them dropped, which is how the engine reads them. A rule
that matches either reading applies, so such a character can neither split a
keyword nor join two words to avoid one.

## Limits

- **Conditional rules are not applied.** `evaluate` passes no context to the
  engine, so a rule with a `condition` (for example `{"env": "production"}`)
  is skipped, whatever the arguments contain. Do not rely on conditional rules
  for tool calls evaluated through this module.

## Reference

::: acgs_lite.tool_calls.ToolCallGovernor

::: acgs_lite.tool_calls.GovernanceDecision

::: acgs_lite.tool_calls.Verdict

::: acgs_lite.tool_calls.format_tool_call
