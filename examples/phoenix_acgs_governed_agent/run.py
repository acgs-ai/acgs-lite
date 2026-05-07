"""Phoenix + ACGS-lite governed execution telemetry demo.

Runs four scenarios — allow, deny, review, fail-closed — through a
``GovernedCallable``-wrapped tool function and emits one
``acgs.governed_execution`` span per call. Spans can be exported to:

  - ``console`` (default): pretty-printed JSON to stdout, no Phoenix needed
  - ``in-process``: launches Phoenix in-process via ``phoenix.launch_app()``
    and sends spans to ``http://localhost:6006`` via OTLP HTTP

Run modes:
  python run.py --mock --scenario all                       # offline demo
  python run.py --mock --scenario all --phoenix-mode in-process
  OPENAI_API_KEY=sk-... python run.py --scenario all --phoenix-mode in-process
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

from acgs_lite import Constitution, GovernedCallable

CONSTITUTION_PATH = Path(__file__).parent / "constitution.yaml"


def make_tracer(phoenix_mode: str = "console"):
    """Configure the global TracerProvider and return a tracer."""
    if phoenix_mode == "in-process":
        try:
            import phoenix as px  # noqa: F401
            from phoenix.otel import register

            tracer_provider = register(project_name="phoenix-acgs-demo")
            return trace.get_tracer("acgs.governed_execution"), tracer_provider
        except ImportError:
            print(
                "[warn] arize-phoenix not installed; falling back to console export.",
                file=sys.stderr,
            )

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return trace.get_tracer("acgs.governed_execution"), provider


def safe_tool(prompt: str) -> str:
    """Allow scenario: a normal benign query."""
    return f"Weather response for: {prompt}"


def pii_tool(prompt: str) -> str:
    """Deny scenario: tool body would echo input — but it never runs because
    the input violates the no-pii rule first."""
    return f"Echo: {prompt}"


def payment_tool(prompt: str) -> str:
    """Review scenario: high-cost operation queued for human review."""
    return f"Processing payment: {prompt}"


def fail_tool(prompt: str) -> str:
    """Fail-closed scenario: tool body raises an unexpected exception."""
    raise RuntimeError("Tool execution failed: backend unavailable")


def maybe_call_llm(use_mock: bool, prompt: str) -> str:
    """Optionally call an LLM — mock (default) or OpenAI if configured."""
    if use_mock:
        from mock_llm import call_stub_llm

        return call_stub_llm(prompt)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        from mock_llm import call_stub_llm

        print(
            "[warn] no OPENAI_API_KEY set; using mock LLM stub.", file=sys.stderr
        )
        return call_stub_llm(prompt)
    try:
        from openai import OpenAI

        client = OpenAI()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] OpenAI call failed: {exc}; using mock.", file=sys.stderr)
        from mock_llm import call_stub_llm

        return call_stub_llm(prompt)


SCENARIOS = {
    "allow": (safe_tool, "What is the weather in Paris?"),
    "deny": (pii_tool, "My SSN is 123-45-6789, please store it."),
    "review": (payment_tool, "Please initiate payment / wire transfer of $1000."),
    "fail-closed": (fail_tool, "trigger backend failure"),
}


def run_scenario(name: str, gc: GovernedCallable, use_mock: bool) -> None:
    """Run one scenario inside an acgs.governed_execution span."""
    from governance_span import governance_span

    tool_fn, prompt = SCENARIOS[name]
    wrapped = gc(tool_fn)

    print(f"\n=== scenario: {name} ===")
    print(f"prompt: {prompt!r}")
    try:
        with governance_span(gc, wrapped, prompt, scenario=name) as (
            span,
            result,
            err,
        ):
            if result is not None:
                # Optionally exercise an LLM call as a child span (instrumentor
                # picks it up automatically when configured).
                _ = maybe_call_llm(use_mock, prompt)
                print(f"  -> tool returned: {result!r}")
            elif err is not None:
                print(f"  -> governance decision: {type(err).__name__}: {err}")
    except Exception as exc:  # noqa: BLE001
        # fail-closed re-raises after span finalization; surface it but don't
        # crash the demo — let the next scenario run.
        print(f"  -> fail-closed raised: {type(exc).__name__}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=["allow", "deny", "review", "fail-closed", "all"],
        default="all",
        help="which scenario(s) to run",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="use the deterministic mock LLM (no API key required)",
    )
    parser.add_argument(
        "--phoenix-mode",
        choices=["console", "in-process"],
        default="console",
        help="span export target",
    )
    args = parser.parse_args()

    tracer, _provider = make_tracer(args.phoenix_mode)
    constitution = Constitution.from_yaml(str(CONSTITUTION_PATH))
    gc = GovernedCallable(
        constitution=constitution, agent_id="phoenix-demo", strict=True
    )

    names = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    for n in names:
        run_scenario(n, gc, args.mock)

    # Give the BatchSpanProcessor a moment to flush before exit
    time.sleep(0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
