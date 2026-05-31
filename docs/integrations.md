# Integrations: Wrapping the Agentic Ecosystem

**Meta Description**: Learn how to integrate ACGS-Lite with major AI frameworks like OpenAI, Anthropic, LangChain, AutoGen, and CrewAI using 2026-ready governance patterns.

---

ACGS-Lite is designed to be framework-agnostic. It provides native adapters for the most popular AI ecosystems, ensuring you can add a governance layer to any agent in minutes.

> **Not sure which adapter to pick?** Start with the
> [Integration Decision Guide](integration-decision-guide.md) — a short FAQ on
> native provider adapters vs. framework wrappers, streaming vs. non-streaming,
> when you need the async API, and when to run the MCP server vs. embed the
> engine in-process.

| Platform | Install Extra | Governance Pattern | Status |
|---|---|---|---|
| **Anthropic** | `acgs-lite[anthropic]` | `GovernedAnthropic` | Production |
| **OpenAI** | `acgs-lite[openai]` | `GovernedOpenAI` | Production |
| **MCP Server** | `acgs-lite[mcp]` | `create_mcp_server` | 2026 Standard |
| **Agno** | `acgs-lite[agno]` | `AgnoACGSGovernor` | Maintained |
| **LangChain** | `acgs-lite[langchain]` | `GovernanceRunnable` | Maintained |
| **LiteLLM** | `acgs-lite[litellm]` | `GovernedLiteLLM` | Maintained |
| **Google GenAI** | `acgs-lite[google]` | `GovernedGenAI` | Production |
| **AutoGen** | `acgs-lite[autogen]` | `GovernedModelClient` | Experimental |
| **CrewAI** | `acgs-lite[crewai]` | `GovernedCrew` | Experimental |
| **PydanticAI** | `acgs-lite[all]` | `GovernedAgent` | **New (2026)** |

---

## 🛡️ The Governance Pattern

All integrations follow the **Intercept-Validate-Execute-Audit** pattern:
1.  **Intercept**: The wrapper catches the call before it reaches the model.
2.  **Validate Input**: The `GovernanceEngine` checks the prompt for violations (e.g., prompt injection).
3.  **Execute**: If valid, the call is passed to the underlying model.
4.  **Validate Output**: The engine checks the response (e.g., for PII leakage).
5.  **Audit**: Both input and output are logged to the tamper-evident audit trail.

---

## 🐙 Anthropic (Claude 3.5+)

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

## 🌌 OpenAI (GPT-4o / o1)

```python
from acgs_lite.integrations.openai import GovernedOpenAI
client = GovernedOpenAI(constitution=constitution)

# Safe completion
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Draft a deployment plan."}]
)
```

## 🦜 LangChain (LCEL)

The `GovernanceRunnable` fits perfectly into LangChain Expression Language (LCEL) chains.

```python
from acgs_lite.integrations.langchain import GovernanceRunnable

governed = GovernanceRunnable(constitution=constitution)
chain = governed | my_llm | output_parser

# The entire chain is now constitutionally bounded
result = chain.invoke("Task instructions...")
```

## 🤖 AutoGen

For multi-agent systems, wrap the model client to ensure agents don't collude or violate policies in their inter-agent chatter.

```python
from acgs_lite.integrations.autogen import GovernedModelClient
from autogen import ConversableAgent

governed_client = GovernedModelClient(base_client, constitution=constitution)
agent = ConversableAgent("SafeAgent", llm_config={"model_client_cls": governed_client})
```

## 🏰 CrewAI

Govern the entire "Crew" to ensure that the collective output of multiple agents meets regulatory standards.

```python
from acgs_lite.integrations.crewai import GovernedCrew

crew = Crew(agents=[a1, a2], tasks=[t1])
governed_crew = GovernedCrew(crew, constitution=constitution)

# Kickoff triggers governance on every task result
result = governed_crew.kickoff()
```

## 🏗️ MCP (Model Context Protocol)

The MCP integration allows you to expose ACGS-Lite as a tool-providing server for clients like Claude Desktop or Cursor.

```python
from acgs_lite.integrations.mcp_server import create_mcp_server, run_mcp_server

# Expose governance tools to any MCP-compliant client
run_mcp_server(constitution=constitution)
```

## 🧠 Agno (Agent Runtime)

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

## 🛠️ Custom Integrations

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
