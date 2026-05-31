"""Test configuration for acgs-lite.

Ensure pytest resolves the local ``src/`` tree before any installed package
copy so verification always exercises the workspace code under test.
"""

from __future__ import annotations

import importlib.util
import runpy
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
SRC_PATH = str(SRC_DIR)

if SRC_PATH in sys.path:
    sys.path.remove(SRC_PATH)
sys.path.insert(0, SRC_PATH)

# Reuse the repository-wide pytest compatibility setup when running inside the
# monorepo. In standalone mode (no monorepo root conftest), skip gracefully.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_REPO_CONFTEST = _REPO_ROOT / "conftest.py"
if _REPO_CONFTEST.is_file():
    runpy.run_path(str(_REPO_CONFTEST), run_name="acgs_repo_conftest")

# Skip test files whose top-level imports require extras not installed in slim
# environments (e.g. python-fallback CI job installs only [dev,mcp]).
_HERE = Path(__file__).parent

collect_ignore: list[str] = []

if importlib.util.find_spec("fastapi") is None:
    collect_ignore += [
        str(_HERE / "test_server.py"),
        str(_HERE / "test_server_rules_crud.py"),
        str(_HERE / "test_lifecycle_router.py"),
        str(_HERE / "test_autonoma.py"),
        str(_HERE / "test_cdp_record.py"),
        str(_HERE / "test_claude_code_integration.py"),
        str(_HERE / "test_federation_transport.py"),
        str(_HERE / "test_openshell_governance_integration.py"),
        str(_HERE / "test_openshell_governance_http.py"),
        str(_HERE / "test_telegram_webhook.py"),
        str(_HERE / "integrations" / "test_litserve.py"),
    ]

if importlib.util.find_spec("anthropic") is None:
    collect_ignore += [
        str(_HERE / "test_anthropic_integration.py"),
        str(_HERE / "test_integrations.py"),
    ]

if importlib.util.find_spec("openai") is None:
    # The xAI adapter is built on the OpenAI-compatible client; without the SDK
    # its construction/completion tests raise ImportError at collection/run time.
    collect_ignore += [
        str(_HERE / "test_xai_integration.py"),
    ]

if importlib.util.find_spec("opentelemetry") is None:
    collect_ignore += [
        str(_HERE / "test_otel_integration.py"),
    ]
