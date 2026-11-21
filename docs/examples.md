# Examples

`pip install acgs-lite` does **not** ship the `examples/` directory. Clone the repository to run these scripts locally:

```bash
git clone https://github.com/acgs-ai/acgs-lite.git
cd acgs-lite
pip install -e ".[dev]"
make test-examples
```

## Offline-runnable examples (smoke-tested by `make test-examples`)

All 29 scripts below run offline with no API keys or network services (`agent_quickstart/run.py` and `control_plane_demo.py` use `acgs-lite[crypto]`, which is included in `[dev]`).

| Example | What it shows |
| --- | --- |
| [`examples/adaptive_policy_generation.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/adaptive_policy_generation.py) | Infer domain/risk pre-context, generate a constitution YAML, and round-trip load it |
| [`examples/agent_quickstart/run.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/agent_quickstart/run.py) | Self-verifying quickstart covering `GovernedCallable` Ed25519 grants, MACI, and `AuditLog` |
| [`examples/audit_trail/main.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/audit_trail/main.py) | Build, query, JSON-export, and verify hash-chained audit entries |
| [`examples/basic_governance/main.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/basic_governance/main.py) | Govern a Python callable using inline, YAML, and default constitutions |
| [`examples/compliance_eu_ai_act/main.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/compliance_eu_ai_act/main.py) | Infer EU AI Act risk tiers and run single- and multi-framework gap assessments |
| [`examples/compliance_reports/run.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/compliance_reports/run.py) | Generate Markdown, text, and JSON compliance reports across 20 regulatory frameworks |
| [`examples/control_plane_demo.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/control_plane_demo.py) | Run the governed self-improvement loop and verify adversarial attack denial |
| [`examples/demo_cli_sidecars.sh`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/demo_cli_sidecars.sh) | Exercise `acgs_lite.cli` bootstrap, linting, testing, lifecycle, refusal, observe, and OTLP bundle export |
| [`examples/dspy_governance/run.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/dspy_governance/run.py) | Wrap a DSPy module (or offline stub predictor) with `GovernedDSPyModule` and audit logging |
| [`examples/eu_ai_act_quickstart.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/eu_ai_act_quickstart.py) | End-to-end EU AI Act Articles 12, 13, and 14 workflow with risk classification and checklist |
| [`examples/eu_ai_act_runtime/art12_record_keeping.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/eu_ai_act_runtime/art12_record_keeping.py) | EU AI Act Article 12 automatic record-keeping with signed `AttestationRegistry` tamper detection |
| [`examples/eu_ai_act_runtime/art14_human_oversight.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/eu_ai_act_runtime/art14_human_oversight.py) | EU AI Act Article 14 fail-closed `HumanOversightGateway` gating a high-risk payment side effect |
| [`examples/eu_ai_act_runtime/art15_robustness.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/eu_ai_act_runtime/art15_robustness.py) | EU AI Act Article 15 prompt-injection interception, `IncidentManager` triage, and audit logging |
| [`examples/gaia_amd/main.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/gaia_amd/main.py) | Build AMD GAIA governance seam components (`ALLOW` / `REVIEW` / `BLOCK`) without GAIA installed |
| [`examples/gitlab_anthropic_demo.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/gitlab_anthropic_demo.py) | Two-layer Anthropic output + GitLab MR diff governance walkthrough (`--simulate` runs offline) |
| [`examples/governed_execution_membrane.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/governed_execution_membrane.py) | Receipt-gated side-effect membrane showing `ALLOW`, `TRANSFORM` (SSN redaction), `DENY`, and missing-receipt refusal |
| [`examples/hackathon_starter_chatbot.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/hackathon_starter_chatbot.py) | Governed chatbot blocking PII, prompt injection, and harmful inputs with output validation |
| [`examples/hackathon_starter_content_mod.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/hackathon_starter_content_mod.py) | Content moderation rules via `GovernanceEngine` CLI demo (with optional FastAPI routes) |
| [`examples/hackathon_starter_maci.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/hackathon_starter_maci.py) | Multi-agent Proposer, Validator, and Executor deployment pipeline using `GovernedAgent` |
| [`examples/lifecycle_quickstart.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/lifecycle_quickstart.py) | Draft, review, evaluate, approve, stage, activate, and bind a constitution bundle in memory |
| [`examples/maci_separation/main.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/maci_separation/main.py) | MACI role-based operation gates and `check_no_self_validation` Golden Rule enforcement |
| [`examples/membrane_5min.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/membrane_5min.py) | Minimal single-file receipt-gated membrane proof documented in the 5-minute membrane guide |
| [`examples/mock_stub_testing/main.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/mock_stub_testing/main.py) | `typing.Protocol` + `InMemory*` vs filesystem stub swapping for credential-free tests |
| [`examples/phoenix_acgs_governed_agent/mock_llm.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/phoenix_acgs_governed_agent/mock_llm.py) | Deterministic stub LLM helper imported by `phoenix_acgs_governed_agent/run.py --mock` |
| [`examples/quickstart.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/quickstart.py) | Core API tour covering `Constitution`, `GovernedAgent`, `MACIEnforcer`, `AuditLog`, and `GovernedCallable` |
| [`examples/quickstart_content_mod.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/quickstart_content_mod.py) | Non-strict `GovernedAgent` blocking hate speech, misinformation, and harassment while auditing warnings |
| [`examples/quickstart_healthcare.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/quickstart_healthcare.py) | Healthcare safety rules enforcing PHI detection, diagnostic uncertainty, and medication guardrails |
| [`examples/quickstart_hiring.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/quickstart_hiring.py) | Fair hiring `GovernedAgent` blocking protected-class bias, cultural-fit proxies, and salary-history filters |
| [`examples/release_proof.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/release_proof.py) | Emit a deterministic JSON proof artifact from the governed execution membrane |

## Examples requiring optional extras, toolchains, or external services

Each file below carries a `# requires: ...` comment near the top of the source file.

| Example | Requires | What it shows |
| --- | --- | --- |
| [`examples/gitlab_mr_governance.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/gitlab_mr_governance.py) | `acgs-lite[gitlab]`, `GITLAB_TOKEN`, `GITLAB_PROJECT_ID`, `--mr-iid`, network | Validate live GitLab merge request diffs, commit messages, and MACI approver separation |
| [`examples/gitlab_webhook_server.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/gitlab_webhook_server.py) | `acgs-lite[gitlab]`, `starlette`, `uvicorn`, `GITLAB_TOKEN`, `GITLAB_PROJECT_ID`, server | Standalone Starlette/uvicorn webhook server validating GitLab MR events |
| [`examples/lean_runtime/lean-wrapper.sh`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/lean_runtime/lean-wrapper.sh) | Lean 4 / `lake` toolchain, `ACGS_LEAN_WORKDIR`, `<lean-file>` arg | Wrapper script invoking `lake env lean` for `ACGS_LEAN_CMD` |
| [`examples/mcp_agent_client.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/mcp_agent_client.py) | `acgs-lite[mcp]` | Connect an MCP stdio client to `acgs_lite.integrations.mcp_server` and call `validate_action` |
| [`examples/phoenix_acgs_governed_agent/governance_span.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/phoenix_acgs_governed_agent/governance_span.py) | `acgs-lite[otel]` (`opentelemetry-api`) | Context manager emitting `acgs.governed_execution` spans with outcome and receipt attributes |
| [`examples/phoenix_acgs_governed_agent/run.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/phoenix_acgs_governed_agent/run.py) | `acgs-lite[otel]` (`opentelemetry-sdk`); optional `arize-phoenix`, `OPENAI_API_KEY` | Run allow, deny, review, and fail-closed scenarios with console or Phoenix OTLP span export |
| [`examples/phoenix_acgs_governed_agent/test_phoenix_integration.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/phoenix_acgs_governed_agent/test_phoenix_integration.py) | `pytest`, `acgs-lite[otel]` (`opentelemetry-sdk`) | Integration test suite asserting span names, statuses, and governance attributes via `InMemorySpanExporter` |
