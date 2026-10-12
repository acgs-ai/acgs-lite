# Integration Decision Guide: Which Adapter When?

Choose the adapter by the execution path you need to check. Install commands and
optional-dependency limits are in [Installation and distributions](installation.md).
This guide describes the current source; verify the corresponding released adapter
before depending on source-only behavior.

## What is this? When do you use it?

ACGS-Lite ships many integrations (see the full table in
[Integrations](integrations.md)). They attach at different layers and have different input, output, and streaming
coverage. This guide answers the recurring "which one do I pick?"
questions so you stop reading the whole catalog and start with the right adapter.

Use this page when you are about to add governance to a project and need to
decide *where* the governance boundary should sit: at the model client, at the
framework/orchestration layer, or as a separate shared service.

---

## When should I use a native provider adapter instead of a framework wrapper?

**Use a native provider adapter** (`GovernedOpenAI`, `GovernedAnthropic`,
`GovernedXAI`, `GovernedGenAI` for Google, `GovernedLiteLLM` for the LiteLLM
router) when your code talks **directly** to a model SDK and you want a drop-in
replacement for that client. These wrap the SDK surface you already call:

```python
from acgs_lite.integrations.openai import GovernedOpenAI

client = GovernedOpenAI(constitution=constitution)
response = client.chat.completions.create(
    model="gpt-5.5",
    messages=[{"role": "user", "content": "Draft a deployment plan."}],
)
```

The OpenAI wrapper checks the last text user message before the call and checks
completed output with `strict=False`. Output violations are logged rather than
blocked. This wrapper does not authorize later tool execution.

**Use a framework wrapper** when an orchestration framework — not your code —
owns the model calls, the tool loop, or the multi-agent conversation. The wrapper can check the inputs and outputs of the wrapped entry point. Do not
assume that this intercepts every internal tool call or inter-agent message:

| If your stack is built on… | Use |
|---|---|
| LangChain / LCEL chains | `GovernanceRunnable` (`acgs_lite.integrations.langchain`) |
| LlamaIndex query/chat engines | `GovernedQueryEngine`, `GovernedChatEngine` (`acgs_lite.integrations.llamaindex`) |
| CrewAI multi-agent crews | `GovernedCrew` / `GovernedCrewAgent` / `GovernedTask` (`acgs_lite.integrations.crewai`) |
| AutoGen Core / AgentChat model calls | `GovernedModelClient` (`acgs_lite.integrations.autogen`) |
| Haystack pipelines | `GovernedHaystackPipeline` / `GovernanceComponent` (`acgs_lite.integrations.haystack`) |
| DSPy modules | `GovernedDSPyModule` / `GovernedPredict` (`acgs_lite.integrations.dspy`) |
| PydanticAI agents | `GovernedPydanticAgent` / `GovernedModel` (`acgs_lite.integrations.pydantic_ai`) |
| Agno agents (AgentOS) | `AgnoACGSGovernor` (`acgs_lite.integrations.agno`) |
| smolagents code agents | `SmolagentsGovernor` / `GovernedPythonExecutor` (`acgs_lite.integrations.smolagents`) |

Choose the entry point that sees the data you need to validate. Use a provider
adapter for model-client input checks, or a framework wrapper for the wrapped
runnable or agent's inputs. For a custom side-effect boundary, consult
`GovernedCallable` and the source-only production profile in
[Runtime Legitimacy](api/legitimacy.md). Test the real tool dispatcher as well as
the wrapper; function-level checks alone do not prove enforcement on every route.

---

## When should I worry about streaming vs. non-streaming?

Do not assume streaming has completed-output enforcement. In the current source,
`GovernanceRunnable.stream`, `GovernedModelClient.create_stream`, and
`GovernedGenAI`'s `generate_content_stream` validate extracted input and then
forward the stream. They do not buffer and validate the full generated output.
OpenAI's response-content check likewise expects a materialized response.

For non-streaming responses, several adapters perform observational output checks
with `strict=False`. A policy violation may be recorded while the response is
still returned. Check the specific adapter before treating output checks as a gate.

If you need to withhold unsafe streamed output, buffer it in your application,
validate the assembled text, and refuse to release it when validation fails. Do
not display chunks first and describe a later check as prevention. This is an
application responsibility, not a promise that each adapter implements buffering.

Input coverage also varies: the OpenAI adapter checks the last text user message,
while other adapters extract different fields. Test your message shape, SDK method,
and stream path explicitly.

---

## When do I need the async API?

Reach for the async surface when your application runs inside an event loop
(FastAPI/Starlette request handlers, asyncio workers, or any framework whose
agent loop is already `async`). Calling a blocking adapter from inside a running
loop will stall it.

The async entry points mirror their sync siblings:

| Adapter | Async method(s) |
|---|---|
| `GovernedOpenAI` (via `client.chat.completions`) | `acreate(...)` (pass an `AsyncOpenAI` client) |
| `GovernanceRunnable` (LangChain) | `ainvoke(...)` |
| `GovernedQueryEngine` / `GovernedChatEngine` (LlamaIndex) | `aquery(...)` / `achat(...)` |
| `GovernedCrew` (CrewAI) | `akickoff(...)` |
| `GovernedModelClient` (AutoGen) | `create(...)` / `create_stream(...)` (async-only) |
| `GovernedHaystackPipeline` (Haystack) | `arun(...)` |
| `GovernedPydanticAgent` / `GovernedModel` (PydanticAI) | `run(...)` / `arequest(...)` |
| `AgnoACGSGovernor` (Agno) | `async_check(...)` |
| `GovernedGenAI` (Google GenAI) | `aio.models.generate_content(...)` |
| LiteLLM | `governed_acompletion(...)` / `client.acompletion(...)` |
| A2A | `A2AGovernedClient.send_task(...)` (async-only) |

**Rule of thumb:** in synchronous scripts, CLIs, and notebooks use the plain
methods. Inside an `async def` handler or an already-running event loop, use the
`a*`-prefixed method (or the natively-async adapters like AutoGen and A2A) so
the governance call doesn't block the loop.

---

## When should I run the MCP server vs. embed the engine in-process?

By default ACGS-Lite runs **in-process**: the adapter holds a
`GovernanceEngine`, validates locally, and writes to a local audit trail. This
is the right default — it is the lowest latency, has no extra service to operate,
and applies to many of the adapters above.

**Run the MCP server** (`create_mcp_server` / `run_mcp_server` from
`acgs_lite.integrations.mcp_server`) when governance needs to be **shared
infrastructure** rather than a library call:

- You want a shared policy-checking service used by several clients. The clients must
  actually invoke that service and enforce the result at their execution boundary.
- An **MCP client** (Claude Desktop, Cursor, or any MCP-compliant host) should
  call governance as a tool, where embedding a Python library is not an option.
- You want governance to live behind a **process boundary** so the policy/audit
  service can be deployed, versioned, and operated independently of the agents
  it governs.

```python
from acgs_lite.integrations.mcp_server import run_mcp_server

# Exposes governance tools over MCP (stdio) as a standalone process
run_mcp_server(constitution=constitution)
```

Use an in-process engine for a local check; use MCP to expose checks to compatible
clients. An MCP governance tool does not automatically intercept other tools or
make audit storage durable. Choose and test those application boundaries separately.
See the [MCP Governance Guide](mcp-guide.md) for setup details.

---

## Next Steps

- Browse the full adapter table and code samples in [Integrations](integrations.md).
- Set up shared governance with the [MCP Governance Guide](mcp-guide.md).
- Learn how to test governed agents in the [Testing Guide](testing-governance.md).
