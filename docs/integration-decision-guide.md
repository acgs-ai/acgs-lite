# Integration Decision Guide: Which Adapter When?

**Meta Description**: A short, practical FAQ for choosing the right ACGS-Lite
integration — native provider adapters vs. framework wrappers, streaming vs.
non-streaming, sync vs. async, and in-process governance vs. the shared MCP
server.

---

## What is this? When do you use it?

ACGS-Lite ships many integrations (see the full table in
[Integrations](integrations.md)). They all enforce the same
**Intercept-Validate-Execute-Audit** pattern, but they attach to your stack at
different layers. This guide answers the recurring "which one do I pick?"
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

The wrapper validates the last user message before the call and validates the
returned content after — nothing else in your code changes.

**Use a framework wrapper** when an orchestration framework — not your code —
owns the model calls, the tool loop, or the multi-agent conversation. Wrapping
the framework lets ACGS-Lite see prompts, tool outputs, and inter-agent chatter
that never pass through a raw provider client:

| If your stack is built on… | Use |
|---|---|
| LangChain / LCEL chains | `GovernanceRunnable` (`acgs_lite.integrations.langchain`) |
| LlamaIndex query/chat engines | `GovernedQueryEngine`, `GovernedChatEngine` (`acgs_lite.integrations.llamaindex`) |
| CrewAI multi-agent crews | `GovernedCrew` / `GovernedCrewAgent` / `GovernedTask` (`acgs_lite.integrations.crewai`) |
| AutoGen conversable agents | `GovernedModelClient` (`acgs_lite.integrations.autogen`) |
| Haystack pipelines | `GovernedHaystackPipeline` / `GovernanceComponent` (`acgs_lite.integrations.haystack`) |
| DSPy modules | `GovernedDSPyModule` / `GovernedPredict` (`acgs_lite.integrations.dspy`) |
| PydanticAI agents | `GovernedPydanticAgent` / `GovernedModel` (`acgs_lite.integrations.pydantic_ai`) |
| Agno agents (AgentOS) | `AgnoACGSGovernor` (`acgs_lite.integrations.agno`) |
| smolagents code agents | `SmolagentsGovernor` / `GovernedPythonExecutor` (`acgs_lite.integrations.smolagents`) |

**Rule of thumb:** govern at the lowest layer that still sees everything you
care about. If you call the provider SDK yourself, use the native adapter. If a
framework calls the model for you (especially with tool loops or multiple
agents), wrap the framework so governance covers the steps your code never
touches directly. For anything custom, use `GovernedCallable` /
`@fail_closed` (see [Integrations: Custom Integrations](integrations.md)).

---

## When should I worry about streaming vs. non-streaming?

The native provider adapters validate the **input** before the call and the
**complete response object** after it. That post-call output check assumes a
fully materialized response.

**For non-streaming calls there is nothing extra to do** — input is validated
pre-call, and the whole response is validated before it is returned to you.

**When you set `stream=True` on a native adapter**, the provider returns an
iterator of chunks rather than a single completed message. The input is still
validated before the request goes out, but the post-call output validation can
no longer inspect a single finished response. Pick one of these patterns:

- Keep using a native adapter for **input governance + audit**, and treat
  output as un-validated while streaming (acceptable when the input check is
  your primary control).
- Buffer the stream, reassemble the full text, and call
  `engine.validate(text, agent_id=..., strict=False)` yourself before showing
  the result to a user, if you need output governance on streamed content.
- Use a framework wrapper that models streaming explicitly when you need
  governance hooks around streamed output — for example
  `GovernanceRunnable.stream` (LangChain), `GovernedChatEngine.stream_chat`
  (LlamaIndex), `GovernedModelClient.create_stream` (AutoGen), or
  `GovernedGenAI`'s `generate_content_stream` (Google GenAI). These keep
  input validation in place around the stream.

**Rule of thumb:** if you stream, input is always governed; decide explicitly
how (or whether) you want to validate the streamed output, because a single
post-call check no longer applies.

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
and is what every adapter above does.

**Run the MCP server** (`create_mcp_server` / `run_mcp_server` from
`acgs_lite.integrations.mcp_server`) when governance needs to be **shared
infrastructure** rather than a library call:

- You want one **shared constitution and audit trail** enforced identically
  across several agents, processes, or languages — not a copy of the engine per
  process.
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

**Rule of thumb:** embed the engine in-process for a single app or service
(default). Stand up the MCP server when multiple agents/processes must share one
governance policy and audit trail, or when an MCP host needs governance as a
callable tool. See the [MCP Governance Guide](mcp-guide.md) for setup details.

---

## Next Steps

- Browse the full adapter table and code samples in [Integrations](integrations.md).
- Set up shared governance with the [MCP Governance Guide](mcp-guide.md).
- Learn how to test governed agents in the [Testing Guide](testing-governance.md).
