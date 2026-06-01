# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Governed agent discovery: capability registry + task-to-agent selection.

Two coordinated pieces:

* :class:`~acgs_lite.agents.registry.AgentRegistry` -- discovery. A process-local
  registry of :class:`~acgs_lite.agents.capability.AgentCapabilityProfile` records,
  seeded from a bundled manifest or loaded from a JSON index such as the repo's
  ``agent-index.json`` (repo root).
* :class:`~acgs_lite.agents.selector.GovernedAgentSelector` -- decision. Picks the
  most suitable agent for a task as a fail-closed, receipted, MACI-respecting
  constitutional decision.

This subpackage imports only stdlib plus acgs-lite's legitimacy and MACI surfaces
at module load time; the optional Ed25519 signer stays lazy behind the ``crypto``
extra. It does not touch the governance hot-path ``engine/matcher.py``.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from acgs_lite.agents.capability import AgentCapabilityProfile
from acgs_lite.agents.errors import NoEligibleAgentError, SelectionDeniedError
from acgs_lite.agents.registry import (
    AgentRegistry,
    get_agent_manifest_path,
    get_agent_registry,
    load_agent_manifest,
    reset_agent_registry,
)
from acgs_lite.agents.selector import AgentSelection, GovernedAgentSelector

__all__ = [
    "AgentCapabilityProfile",
    "AgentRegistry",
    "AgentSelection",
    "GovernedAgentSelector",
    "NoEligibleAgentError",
    "SelectionDeniedError",
    "get_agent_manifest_path",
    "get_agent_registry",
    "load_agent_manifest",
    "reset_agent_registry",
]
