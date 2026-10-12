# Integrations: Wrapping the Agentic Ecosystem

Use an adapter at the layer where your application needs a check. The catalog
below describes modules in this source checkout, not a production certification.
See [Installation and distributions](installation.md) for published-package versus
source differences and the complete optional-dependency catalog.

> **Not sure which adapter to pick?** Start with the
> [Integration Decision Guide](integration-decision-guide.md) — a short FAQ on
> native provider adapters vs. framework wrappers, streaming vs. non-streaming,
> when you need the async API, and when to run the MCP server vs. embed the
> engine in-process.

| Platform | Install dependency selection | Adapter / entry point |
|---|---|---|
| Anthropic | `acgs-lite[anthropic]` | `GovernedAnthropic` |
| OpenAI | `acgs-lite[openai]` | `GovernedOpenAI` |
| MCP server | `acgs-lite[mcp]` | `create_mcp_server` |
| Agno | `acgs-lite[agno]` | `AgnoACGSGovernor` |
| LangChain | `acgs-lite[langchain]` | `GovernanceRunnable` |
| LiteLLM | `acgs-lite[litellm]` | `GovernedLiteLLM` |
| Google GenAI | `acgs-lite[google]` | `GovernedGenAI` |
| AutoGen | `acgs-lite[autogen]` | `GovernedModelClient` (Core / AgentChat APIs) |
| CrewAI | `acgs-lite[crewai]` | `GovernedCrew` |
| PydanticAI | Install `acgs-lite` and `pydantic-ai` separately | `GovernedPydanticAgent` / `GovernedModel` |
| AMD GAIA | `acgs-lite`; install the host framework separately | `build_gaia_components` / `AcgsLitePolicyEngine` |

`[all]` does not install PydanticAI. Adapter presence does not establish coverage
of every SDK method, tool action, or streaming output path. The snippets below
show integration wiring; they assume configured framework clients, a constitution,
and any provider credentials. Pin the package version for published examples or
use an editable source install for source-only behavior.

---

## Governance coverage

The common shape is input interception, a policy check, the wrapped call, and
an audit record. Exact coverage varies by adapter:

- OpenAI validates the last text user message before the call. Completed response
  content is checked with `strict=False`; violations are logged, not blocked.
- LangChain validates the wrapped runnable's input and checks its completed output
  non-blockingly. Its `stream()` path validates input and forwards chunks.
- AutoGen `create()` validates extracted input and checks completed output
  non-blockingly; `create_stream()` checks input before forwarding chunks.
- CrewAI `GovernedCrew.kickoff()` checks task descriptions before kickoff and
  the final crew result non-blockingly. It does not by itself check every tool call.

For enforcement of an external side effect, connect the check to that callable's
actual execution boundary. See [Runtime Legitimacy](api/legitimacy.md) and the
[integration decision guide](integration-decision-guide.md).

---

## Anthropic

```python
from acgs_lite.integrations.anthropic import GovernedAnthropic
from acgs_lite import Constitution

constitution = Constitution.from_yaml("rules.yaml")
client = GovernedAnthropic(constitution=constitution)

# This message is automatically governed!
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Analyze these logs."}]
)
```

## OpenAI

```python
from acgs_lite.integrations.openai import GovernedOpenAI
client = GovernedOpenAI(constitution=constitution)

# Safe completion
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Draft a deployment plan."}]
)
```

## LangChain (LCEL)

Wrap an existing LangChain runnable or assembled chain. The `[langchain]` extra
installs `langchain-core`; provider-specific packages are installed separately.

```python
from acgs_lite.integrations.langchain import GovernanceRunnable

chain = my_llm | output_parser
governed = GovernanceRunnable(chain, constitution=constitution)

# Checks chain input and records non-blocking completed-output violations.
result = governed.invoke("Task instructions...")
```

## AutoGen

For multi-agent systems, wrap the model client to screen inter-agent chatter for policy violations.

```python
from acgs_lite.integrations.autogen import GovernedModelClient
from autogen_agentchat.agents import AssistantAgent

# base_client is your configured AutoGen Core model client.
governed_client = GovernedModelClient(base_client, constitution=constitution)
agent = AssistantAgent("safe_agent", model_client=governed_client)
```

## CrewAI

Govern the entire "Crew" to check the collective output of multiple agents against your constitution's rules.

```python
from acgs_lite.integrations.crewai import GovernedCrew

crew = Crew(agents=[a1, a2], tasks=[t1])
governed_crew = GovernedCrew(crew, constitution=constitution)

# Checks task descriptions, then records non-blocking final-output violations
result = governed_crew.kickoff()
```

## MCP (Model Context Protocol)

The MCP integration allows you to expose ACGS-Lite as a tool-providing server for clients like Claude Desktop or Cursor.

```python
from acgs_lite.integrations.mcp_server import create_mcp_server, run_mcp_server

# Expose governance tools to any MCP-compliant client
run_mcp_server(constitution=constitution)
```

## Agno (Agent Runtime)

Agno provides an agent runtime with pre-hooks (input) and post-hooks (output) and a FastAPI
server (AgentOS). ACGS-Lite plugs in as a guardrail + output check.

```python
from agno.agent import Agent
from agno.models.openai import OpenAIChat

from acgs_lite import Constitution
from acgs_lite.integrations.agno import AgnoACGSGovernor

constitution = Constitution.from_yaml("rules.yaml")
governor = AgnoACGSGovernor(constitution=constitution, agent_id="agno-agent")

agent = Agent(
    name="Governed Agent",
    model=OpenAIChat(id="gpt-5.5"),
    pre_hooks=[governor],                 # blocks unconstitutional user input
    post_hooks=[governor.output_hook],    # warns by default, can be configured to block
)
```

---

## Custom integrations

If you are using a custom framework, you can use the `@fail_closed` decorator and the `GovernedCallable` wrapper to add governance to any function.

```python
from acgs_lite import GovernedCallable, Constitution

constitution = Constitution.from_yaml("rules.yaml")

@GovernedCallable(constitution=constitution)
def call_my_custom_model(prompt: str) -> str:
    return "Response"
```

---

## Next Steps
- Learn how to use [MACI Roles](maci.md) in multi-agent systems.
- Deep dive into the [Governance Engine](architecture.md).
- See the [CLI Reference](cli.md) for CI/CD integration.
