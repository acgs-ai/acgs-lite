# acgs-lite package Makefile
# Run from packages/acgs-lite/ or from repo root via:
#   make -C packages/acgs-lite <target>
#
# All tests run without API keys — InMemory* stubs handle external deps.

PYTHON     ?= python3
PYTEST      = $(PYTHON) -m pytest
RUFF        = $(PYTHON) -m ruff
MYPY        = $(PYTHON) -m mypy
BUILD       = $(PYTHON) -m build
TWINE       = $(PYTHON) -m twine
PACKAGE_DIR := .
SRC_DIR     = $(PACKAGE_DIR)/src/acgs_lite
TEST_DIR    = $(PACKAGE_DIR)/tests

# Detect repo root (two levels up from this Makefile)
REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null || echo ../..)

.PHONY: help dev-setup install install-dev test test-quick test-cov test-examples \
        test-governance \
        lint format typecheck check build publish-dry-run publish \
        examples visualize clean

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  acgs-lite development targets"
	@echo ""
	@echo "  Setup:"
	@echo "    make dev-setup     One-shot: create .venv + install all dev deps"
	@echo "    make install       Install package in editable mode"
	@echo "    make install-dev   Install package + dev deps (pytest, ruff, mypy)"
	@echo ""
	@echo "  Testing (no API keys required — InMemory* stubs used):"
	@echo "    make test          Full test suite"
	@echo "    make test-quick    Skip slow/benchmark tests (-m 'not slow')"
	@echo "    make test-cov      Test + coverage report (HTML in htmlcov/)"
	@echo "    make test-governance  Governance-regression safety gate"
	@echo "    make test-examples Run all examples/ as smoke tests"
	@echo ""
	@echo "  Quality:"
	@echo "    make lint          Ruff linter"
	@echo "    make format        Ruff auto-fix + format"
	@echo "    make typecheck     MyPy type check (strict)"
	@echo "    make check         lint + typecheck + test"
	@echo ""
	@echo "  Release:"
	@echo "    make build         Build wheel + sdist into dist/"
	@echo "    make publish-dry-run  Dry-run upload to PyPI (no publish)"
	@echo "    make publish       Upload dist/* to PyPI (needs TWINE_PASSWORD)"
	@echo ""
	@echo "  Utilities:"
	@echo "    make examples      Run all examples interactively"
	@echo "    make visualize     Open visualizer help (see scripts/visualizer.py)"
	@echo "    make clean         Remove caches, dist, build artifacts"
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────
# Python 3.11 is the CI-pinned version. Use it when available; fall back to 3.12.
# crewai/autogen extras require <=3.13 — they are intentionally excluded here.
# For the full locked environment use: uv sync --all-extras && uv run make test
PYTHON3_11 := $(shell which python3.11 2>/dev/null || which python3.12 2>/dev/null || echo python3)

dev-setup:
	@echo "Creating .venv with $(PYTHON3_11) and installing dev deps..."
	$(PYTHON3_11) -m venv .venv
	.venv/bin/pip install --upgrade pip -q
	.venv/bin/pip install -e ".[dev,openai,anthropic,langchain,mcp,mistral,google,llamaindex,litellm,otel]" -q
	.venv/bin/pip install fastapi httpx -q   # root conftest deps (standalone mode)
	@echo ""
	@echo "  Virtual environment : .venv/"
	@echo "  Activate (Unix/macOS): source .venv/bin/activate"
	@echo "  Activate (Windows)  : .venv\\Scripts\\activate"
	@echo ""
	@if [ ! -f .env.test ]; then cp .env.example .env.test 2>/dev/null || true; fi
	@echo "  API keys: see .env.example (all placeholders, no real keys needed)"
	@echo "  Note: crewai/autogen/a2a extras excluded (require Python <=3.13)"
	@echo "  Full locked env: uv sync --all-extras && uv run make test"
	@echo "  Ready.  Run: source .venv/bin/activate && make test"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"
	@echo ""
	@echo "Dev environment ready. No API keys required for tests."
	@echo "Placeholder keys: OPENAI_API_KEY=test-key ANTHROPIC_API_KEY=test-key"
	@echo "See .env.example for the full set."

# ── Testing ───────────────────────────────────────────────────────────────────
# ACGS tests use InMemory* stubs — zero external deps in CI.
# Set placeholder key so any import-time validation passes.
#
# Canonical path (CI / full suite): uv run make test      (4951+ tests)
# Standalone venv path: source .venv/bin/activate && make test
PYTEST_IGNORE_STANDALONE :=
TEST_ENV = OPENAI_API_KEY=test-key-for-unit-tests \
           ANTHROPIC_API_KEY=test-key-for-unit-tests

# --rootdir isolates pytest from the workspace root conftest.py when using a
# standalone .venv.  uv run pytest (workspace mode) loads the root conftest
# automatically via PYTHONPATH, so this flag is harmless there too.
PYTEST_ROOTDIR := --rootdir=$(PACKAGE_DIR)

test:
	$(TEST_ENV) $(PYTEST) $(TEST_DIR)/ \
	    $(PYTEST_ROOTDIR) $(PYTEST_IGNORE_STANDALONE) \
	    --import-mode=importlib \
	    -v

test-quick:
	$(TEST_ENV) $(PYTEST) $(TEST_DIR)/ \
	    $(PYTEST_ROOTDIR) $(PYTEST_IGNORE_STANDALONE) \
	    --import-mode=importlib \
	    -m "not slow and not benchmark" \
	    -x -v

test-cov:
	$(TEST_ENV) $(PYTEST) $(TEST_DIR)/ \
	    $(PYTEST_ROOTDIR) $(PYTEST_IGNORE_STANDALONE) \
	    --import-mode=importlib \
	    --cov=$(SRC_DIR) \
	    --cov-report=term-missing \
	    --cov-report=html:htmlcov
	@echo "Coverage report: htmlcov/index.html"

test-governance:
	$(TEST_ENV) $(PYTEST) \
	    $(TEST_DIR)/test_maci.py \
	    $(TEST_DIR)/test_core.py \
	    $(TEST_DIR)/test_legitimacy_contract.py \
	    $(TEST_DIR)/test_claude_code_integration.py \
	    $(TEST_DIR)/test_governance_regression_invariants.py \
	    $(TEST_DIR)/red_team \
	    $(PYTEST_ROOTDIR) \
	    --import-mode=importlib \
	    -q
	$(TEST_ENV) $(PYTHON) scripts/run_governance_regression.py --check

test-examples:
	@echo "Running examples as smoke tests..."
	$(TEST_ENV) $(PYTHON) examples/basic_governance/main.py
	$(TEST_ENV) $(PYTHON) examples/compliance_eu_ai_act/main.py
	$(TEST_ENV) $(PYTHON) examples/maci_separation/main.py
	$(TEST_ENV) $(PYTHON) examples/audit_trail/main.py
	$(TEST_ENV) $(PYTHON) examples/mock_stub_testing/main.py
	@echo "All examples passed."

# ── Quality ───────────────────────────────────────────────────────────────────
lint:
	$(RUFF) check $(SRC_DIR)/ $(TEST_DIR)/

format:
	$(RUFF) check --fix $(SRC_DIR)/ $(TEST_DIR)/
	$(RUFF) format $(SRC_DIR)/ $(TEST_DIR)/

typecheck:
	$(MYPY) $(SRC_DIR)/ --ignore-missing-imports

check: lint typecheck test

# ── Release ───────────────────────────────────────────────────────────────────
build: clean-dist
	$(BUILD) --wheel --sdist
	@echo "Artifacts in dist/:"
	@ls -lh dist/

publish-dry-run: build
	$(TWINE) check dist/*
	@echo "Dry-run OK. Run 'make publish' to upload."

publish: build
	$(TWINE) upload dist/* \
	    --username __token__ \
	    --non-interactive
	@echo "Published. https://pypi.org/project/acgs-lite/"

# ── Utilities ─────────────────────────────────────────────────────────────────
examples:
	$(PYTHON) examples/basic_governance/main.py
	$(PYTHON) examples/compliance_eu_ai_act/main.py
	$(PYTHON) examples/maci_separation/main.py
	$(PYTHON) examples/audit_trail/main.py
	$(PYTHON) examples/mock_stub_testing/main.py

visualize:
	$(PYTHON) scripts/visualizer.py --help

clean-dist:
	rm -rf dist/ build/

clean: clean-dist
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "Clean."
