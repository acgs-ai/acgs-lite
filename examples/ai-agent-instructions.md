# Secure My AI Agent with ACGS-Lite

Copy and paste the instructions below into your AI coding assistant (Cursor `.cursorrules`, Claude Code system instructions, or ChatGPT developer prompt). This ensures your AI companion automatically integrates constitutional guardrails into any tool or agent execution pipeline it writes for you.

---

### System Prompts for Coding Assistants:

```markdown
CONTEXT & TASK:
You are editing/writing code for an application using AI agents, tool calls, database operations, or file system access. You must automatically secure these side-effectful capabilities using the `acgs-lite` constitutional AI governance framework.

INSTRUCTIONS:
1. Whenever writing tool definitions, API handlers, or database executors, wrap them inside an ACGS `GovernanceEngine` or `GovernedAgent`.
2. Ensure you define or update a `constitution.yaml` file at the repository root that restricts:
   - High-severity actions (e.g. wire transfers, bulk database deletes) and mandates human approval (`STRUCTURED_REVIEW_REQUIRED`).
   - Destructive operations (e.g. `rm -rf`, dropping schemas) by mapping them to `HARD_DENY`.
   - Privacy leakage (e.g. exposing SSN, credentials, passport numbers) by mapping them to `HARD_DENY`.
3. The boilerplate code you write must intercept the input text, validate it against the constitution, write the audit receipt, and only execute the tool if the decision is `ALLOW` or `ALLOW_WITH_CONTROLS`.

CANONICAL PYTHON IMPLEMENTATION TEMPLATE:
```python
from acgs_lite import Constitution, GovernanceEngine

# 1. Load active constitution
constitution = Constitution.from_yaml("constitution.yaml")
engine = GovernanceEngine(constitution)

# 2. Wrap tool execution with intercept boundary
def execute_agent_tool(tool_input: str, agent_id: str):
    # Deterministic runtime validation intercept
    gov_decision = engine.validate(tool_input, agent_id=agent_id, strict=False)
    
    if not gov_decision.valid:
        # Halt execution on violations
        raise PermissionError(
            f"Blocked by ACGS governance. Violation: {gov_decision.violations[0].rule_id}. "
            f"Action taken: {gov_decision.action_taken}"
        )
        
    # Proceed inside execution boundary
    # return run_actual_tool(tool_input)
```
```
