"""AMD GAIA seam demo — no GAIA install required.

Shows the four objects GaiaGovernanceAdapter composes, including a
fail-closed BLOCK when a mutating tool is proposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from acgs_lite import Constitution, Rule, Severity, ViolationAction
from acgs_lite.integrations.gaia import build_gaia_components


@dataclass
class ActionRequest:
    action_id: str
    actor_id: str
    tool_name: str
    action_type: str
    args: dict[str, Any]
    risk_tags: list[str] = field(default_factory=list)
    workflow_id: str | None = "demo-wf"
    source: str = "gaia"


def main() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="GAIA-MAIL-1",
                text="Outbound mail must be reviewed",
                keywords=["send_email", "mailto"],
                severity=Severity.HIGH,
                workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
            ),
            Rule(
                id="GAIA-SHELL-1",
                text="Destructive shell commands are blocked",
                keywords=["rm -rf", "wipe-disk"],
                severity=Severity.CRITICAL,
                workflow_action=ViolationAction.BLOCK,
            ),
        ]
    )
    engine, checkpoints, receipts, binding = build_gaia_components(constitution)

    search = engine.evaluate_action(
        ActionRequest("a1", "alice", "search", "tool_call", {"q": "weather tomorrow"})
    )
    mail = engine.evaluate_action(
        ActionRequest("a2", "alice", "send_email", "tool_call", {"to": "ops@example.com"})
    )
    shell = engine.evaluate_action(
        ActionRequest("a3", "alice", "shell", "tool_call", {"cmd": "rm -rf /tmp/demo"})
    )

    print("search:", search.decision, search.reason)
    print("mail:  ", mail.decision, mail.reason)
    print("shell: ", shell.decision, shell.reason)
    print("constitution:", binding.current_version().constitution_hash[:12])
    print("receipts stored:", len(receipts._records))
    print("open checkpoints:", len(checkpoints._records))

    if search.decision != "ALLOW" or mail.decision != "REVIEW" or shell.decision != "BLOCK":
        raise SystemExit("unexpected GAIA seam decisions")


if __name__ == "__main__":
    main()
