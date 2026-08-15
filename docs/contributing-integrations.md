# Contributing a New Integration

**This is the easiest meaningful code contribution to ACGS.** Adding a new platform integration typically takes 1–3 hours and follows a well-worn pattern.

ACGS currently wraps **Anthropic, OpenAI, LangChain, LiteLLM, Google GenAI, LlamaIndex, AutoGen, CrewAI, A2A, MCP, GitLab CI, DSPy, Haystack, and AMD GAIA's PolicyEngine Protocol**.

---

## Before You Start

1. Open a [New Integration issue](https://github.com/acgs-ai/acgs-lite/issues/new?template=new_integration.yml) to claim the platform — avoids duplicate work
2. Read `src/acgs_lite/integrations/anthropic.py` — it's the reference implementation with inline comments
3. Need live help? Ask in [Discussions](https://github.com/acgs-ai/acgs-lite/discussions) — the **Q&A** category is watched by maintainers

---

## The Pattern

Every integration follows the same five-step pattern:

```
1. Optional import guard       → don't break if the package isn't installed
2. GovernanceEngine setup      → create engine with the user's constitution
3. Input validation            → validate before calling the platform API
4. Platform call               → the real API call, unchanged
5. Output validation + audit   → validate the response, record to AuditLog
```

---

## Step-by-Step

### 1. Create your file

```bash
touch src/acgs_lite/integrations/my_platform.py
```

### 2. Copy the skeleton

```python
"""ACGS integration for MyPlatform.

Usage::

    from acgs_lite.integrations.my_platform import GovernedMyPlatform

    client = GovernedMyPlatform(api_key="...", constitution=constitution)
    result = client.generate("my prompt")

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine

logger = logging.getLogger(__name__)

# ── Optional import guard ────────────────────────────────────────────────────
try:
    from my_platform import MyPlatformClient  # the real SDK

    MY_PLATFORM_AVAILABLE = True
except ImportError:
    MY_PLATFORM_AVAILABLE = False
    MyPlatformClient = object  # type: ignore[assignment,misc]

CONSTITUTIONAL_HASH = "608508a9bd224290"


class GovernedMyPlatform:
    """MyPlatform client wrapped with ACGS constitutional governance."""

    def __init__(
        self,
        api_key: str,
        constitution: Constitution | None = None,
        audit_mode: str = "full",
        **kwargs: Any,
    ) -> None:
        if not MY_PLATFORM_AVAILABLE:
            raise ImportError(
                "my-platform is not installed. Run: pip install my-platform"
            )
        self._client = MyPlatformClient(api_key=api_key, **kwargs)
        self._constitution = constitution or Constitution.from_template("general")
        self._engine = GovernanceEngine(
            self._constitution, constitutional_hash=CONSTITUTIONAL_HASH
        )
        self._audit = AuditLog(mode=audit_mode)

    def generate(self, prompt: str, **kwargs: Any) -> str:
        """Generate with constitutional governance applied to input and output."""
        # 1. Validate input
        input_result = self._engine.validate(prompt, agent_id="user")
        if not input_result.is_valid:
            self._audit.record_violation(prompt, input_result)
            raise ValueError(f"Input blocked by constitution: {input_result.violations}")

        # 2. Call the platform
        response = self._client.generate(prompt, **kwargs)

        # 3. Validate output
        output_text = response.text  # adapt to your SDK's response shape
        output_result = self._engine.validate(output_text, agent_id="assistant")
        self._audit.record(prompt, output_text, output_result)

        if not output_result.is_valid:
            raise ValueError(f"Output blocked by constitution: {output_result.violations}")

        return output_text

    @property
    def audit_log(self) -> AuditLog:
        return self._audit
```

### 3. Register in `__init__.py`

```python
# src/acgs_lite/integrations/__init__.py
# Add to the conditional imports block:
try:
    from acgs_lite.integrations.my_platform import GovernedMyPlatform
    __all__ += ["GovernedMyPlatform"]
except ImportError:
    pass
```

### 4. Write tests

```python
# tests/integrations/test_my_platform.py
import pytest
from unittest.mock import MagicMock, patch
from acgs_lite import Constitution
from acgs_lite.integrations.my_platform import GovernedMyPlatform

@pytest.fixture
def governed_client():
    with patch("acgs_lite.integrations.my_platform.MY_PLATFORM_AVAILABLE", True), \
         patch("acgs_lite.integrations.my_platform.MyPlatformClient") as mock_sdk:
        mock_sdk.return_value.generate.return_value.text = "safe response"
        constitution = Constitution.from_template("general")
        return GovernedMyPlatform(api_key="test-key", constitution=constitution)

def test_valid_request_passes(governed_client):
    result = governed_client.generate("tell me about AI governance")
    assert result == "safe response"

def test_blocked_input_raises(governed_client):
    with pytest.raises(ValueError, match="Input blocked"):
        governed_client.generate("drop table users")  # triggers constitution rule

def test_audit_log_populated(governed_client):
    governed_client.generate("safe prompt")
    assert len(governed_client.audit_log.records) == 1

def test_unavailable_raises_import_error():
    with patch("acgs_lite.integrations.my_platform.MY_PLATFORM_AVAILABLE", False):
        with pytest.raises(ImportError, match="my-platform"):
            GovernedMyPlatform(api_key="test")
```

### 5. Add to `pyproject.toml` optional extras

```toml
[project.optional-dependencies]
my-platform = ["my-platform>=1.0.0"]
all = [
    ...,
    "my-platform>=1.0.0",  # add here too
]
```

### 6. Document it

Add a row to the integrations table in `docs/integrations.md`:

```markdown
| MyPlatform | `GovernedMyPlatform` | `pip install "acgs-lite[my-platform]"` | ✅ |
```

---

## Checklist Before Opening a PR

- [ ] Optional import guard in place (no hard dependency)
- [ ] `MY_PLATFORM_AVAILABLE` guard in `__init__`
- [ ] `CONSTITUTIONAL_HASH = "608508a9bd224290"` present
- [ ] Tests cover: valid pass, block on violation, unavailable SDK, audit log
- [ ] `make test-quick` passes
- [ ] Row added to `docs/integrations.md`
- [ ] Optional extra added to `pyproject.toml`

---

## Getting Help

- Open a draft PR early — we give feedback before the code is complete
- Ask in [Discussions](https://github.com/acgs-ai/acgs-lite/discussions) under **Q&A**
- Look at `anthropic.py` for streaming support, `langchain.py` for chain wrapping
