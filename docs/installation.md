# Installation and distributions

Choose the artifact first, then add only the dependencies required by your application.
ACGS-Lite's base package requires **Python 3.10+**, Pydantic 2+, PyYAML 6+, and Click 8+.
Optional SDKs may impose stricter Python and platform requirements.

## Install the published package

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install acgs-lite==3.0.1
python -m pip check
acgs --help
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell.
Use the [5-minute membrane](guides/five-minute-membrane.md) for a pip-only example.
The wheel does not include the repository's `examples/` directory.

!!! warning "Source-only hardening"
    The source candidate includes execution-grant, trusted-context, durable-audit,
    and recovery changes absent from the published **3.0.1** wheel. Installing
    `acgs-lite==3.0.1` does not install those changes. Source metadata still reports
    3.0.1; record the Git commit when reproducing source behavior.

## Work from the repository

```bash
git clone https://github.com/acgs-ai/acgs-lite.git
cd acgs-lite
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
git rev-parse HEAD
python examples/membrane_5min.py
```

Python 3.11 is a practical choice for the repository's CI-oriented development
setup. Use `make dev-setup` for the repository's broader development dependency
set; a minimal `[dev]` install is not every integration's test environment.
See [Contributing](contributing.md) for validation and optional-test setup.

## Optional dependencies

For a published artifact, append an extra before the version pin:

```bash
python -m pip install "acgs-lite[openai,crypto]==3.0.1"
```

For the current source checkout, use an editable install:

```bash
python -m pip install -e ".[server,postgres]"
```

The table below describes **this checkout's** `pyproject.toml`; consult the
installed release's metadata when reproducing a published environment. Minimum
versions are dependency declarations, not proof that every future SDK version is
compatible. Let the resolver check the selected extras together, then run
`python -m pip check` and your integration's tests.

| Extra | Purpose | Declared dependencies / constraints |
| --- | --- | --- |
| `a2a` | Google A2A protocol | `a2a-sdk>=0.2`<br>`httpx>=0.27` |
| `openai` | OpenAI client adapter | `openai>=1.0` |
| `anthropic` | Anthropic client adapter | `anthropic>=0.30` |
| `agno` | Agno hooks | `agno>=2.5` |
| `langchain` | LangChain runnable wrapper; provider packages are separate | `langchain-core>=0.2` |
| `litellm` | LiteLLM router | `litellm>=1.0` |
| `google` | Google GenAI SDK | `google-genai>=1.0` |
| `llamaindex` | LlamaIndex engines | `llama-index-core>=0.10` |
| `gove` | Gove bridge; dependency only installed on Python 3.11+ | `gove-zone>=0.1.0a1; python_version >= '3.11'` |
| `autogen` | AutoGen Core and AgentChat APIs | `autogen-core>=0.4`<br>`autogen-agentchat>=0.4` |
| `mcp` | MCP server; bounded SDK major version | `mcp>=2.2,<3`<br>`jsonschema>=4.20`<br>`structlog>=21.0` |
| `crewai` | CrewAI wrappers | `crewai>=0.30` |
| `smolagents` | smolagents execution integration | `smolagents>=1.9` |
| `swarms` | Swarms integration | `swarms>=7.0` |
| `autonoma` | Autonoma integration dependencies | `pyjwt>=2.0`<br>`structlog>=21.0`<br>`fastapi>=0.100` |
| `server` | FastAPI governance HTTP application | `fastapi>=0.100`<br>`uvicorn>=0.24` |
| `gitlab` | GitLab integration | `httpx>=0.27`<br>`starlette>=0.37` |
| `google-cloud` | Google Cloud logging | `google-cloud-logging>=3.0` |
| `mistral` | Mistral client adapter | `mistralai>=2.0` |
| `pdf` | PDF reporting | `fpdf2>=2.7` |
| `crypto` | Cryptographic receipt support | `cryptography>=42.0` |
| `otel` | OpenTelemetry tracing; bounded major versions | `opentelemetry-api>=1.0,<2.0`<br>`opentelemetry-sdk>=1.0,<2.0` |
| `postgres` | PostgreSQL audit backend and connection pool | `psycopg[binary]>=3.1`<br>`psycopg-pool>=3.2` |
| `z3` | Z3 constraint solving | `z3-solver>=4.12` |
| `all` | Convenience integration bundle; exclusions below | `acgs-lite[a2a,openai,anthropic,agno,langchain,litellm,google,llamaindex,autogen,mcp,crewai,smolagents,swarms,autonoma,gitlab,google-cloud,pdf,crypto,mistral,otel,z3]` |
| `docs` | Material documentation and API-reference build tools | `mkdocs-material>=9.5`<br>`mkdocstrings[python]>=0.25`<br>`mike>=2.0`<br>`mkdocs-git-revision-date-localized-plugin>=1.2` |
| `dev` | Build, test, lint, typing, packaging, docs, and crypto tools | `build>=1.2`<br>`pytest>=8.0`<br>`pytest-asyncio>=0.24`<br>`pytest-benchmark>=4.0`<br>`pytest-cov>=4.1`<br>`ruff>=0.8`<br>`mypy>=1.13`<br>`twine>=5.0`<br>`tomli>=2.0; python_version < '3.11'`<br>`acgs-lite[docs]`<br>`acgs-lite[crypto]` |

### What `all` includes

`all` selects the integration names listed in its table row. It does **not** select
`server`, `postgres`, `gove`, `docs`, or `dev`. It also does not install every
third-party framework for which an adapter module exists. For example,
PydanticAI needs a separate `pydantic-ai` installation; there is no `pydantic-ai`
extra in this manifest. See the [adapter catalog](integrations.md).

`gove` has an explicit Python 3.11+ dependency marker: requesting that extra on
Python 3.10 does not install `gove-zone`. Other SDKs may further restrict Python
versions. An extras name is a dependency selection, not an activation or
production-readiness guarantee.

## Distribution surfaces

| Surface | What it contains | How to interpret it |
| --- | --- | --- |
| Python wheel and source distribution | `acgs-lite` package and declared package data | `make build` creates local artifacts; the qualified-candidate publish workflow controls PyPI publication. |
| Optional Rust companion | `acgs-lite-rust` wheels and source distribution built from `rust/pyo3` | `wheels.yml` uploads CI artifacts for Linux, macOS, and Windows. Artifact creation does not establish a PyPI release; the Python implementation remains available. |
| Docker / Cloud Run | The root Dockerfile runs `acgs_lite.integrations.cloud_run_server:app` | This is the Constitutional Sentinel service, distinct from the general `create_governance_app` FastAPI factory. A Dockerfile is not evidence of a deployed service. |
| Documentation build | MkDocs renders `docs/` using `mkdocs.yml` into `site/docs` | Build locally with the docs extra; a successful build does not publish pages. |
| Public website | The Cloudflare-hosted `acgs.ai` website is a separate delivery surface | At the 2026-10-12 audit, `/docs` redirected to `/resources`. New Markdown pages in this checkout are not automatically new live website routes. |

The root `package.json` defines `npm run build` to install docs dependencies and
run the strict MkDocs build, `npm run preview` as `wrangler dev`, and
`npm run deploy` as `wrangler versions upload`. Despite its name, the deploy script
uploads a Worker version; it does not activate that version for live traffic.
Treat upload, activation, and verification of the served route as separate steps.

Release sources: [candidate qualification workflow](https://github.com/acgs-ai/acgs-lite/blob/main/.github/workflows/release-candidate.yml),
[PyPI publication workflow](https://github.com/acgs-ai/acgs-lite/blob/main/.github/workflows/publish.yml),
[Rust artifact workflow](https://github.com/acgs-ai/acgs-lite/blob/main/.github/workflows/wheels.yml),
and [Dockerfile](https://github.com/acgs-ai/acgs-lite/blob/main/Dockerfile).

## Build and check locally

```bash
python -m pip install -e ".[dev]"
python -m mkdocs build --strict
python scripts/check_links.py
make publish-dry-run
```

`make publish-dry-run` builds local wheel/sdist artifacts and checks package
metadata without uploading. It replaces local `dist/` and `build/` output, so
preserve any release evidence there first. Direct `make publish` is disabled;
local validation does not authorize or perform a release.

For environment problems, record `python --version`, `python -m pip show acgs-lite`,
the selected extras, and the failing command. See the [community FAQ](community/faq.md).
