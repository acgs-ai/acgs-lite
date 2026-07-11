import pytest

pytest.importorskip("gove_zone")

from gove_zone.decision import Decision

from acgs_lite.gove.verdicts import decision_state_to_gove


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("ALLOW", Decision.ALLOW),
        ("ALLOW_WITH_CONTROLS", Decision.ALLOW),
        ("TRANSFORM_REQUIRED", Decision.TRANSFORM),
        ("STRUCTURED_REVIEW_REQUIRED", Decision.ESCALATE),
        ("REPLAN_REQUIRED", Decision.DENY),
        ("DENY_OPERATION_WITH_ALTERNATIVE", Decision.DENY),
        ("DENY_GOAL", Decision.DENY),
        ("HARD_DENY", Decision.DENY),
    ],
)
def test_all_eight_states_map(state, expected):
    assert decision_state_to_gove(state) is expected


def test_unknown_state_raises():
    with pytest.raises(ValueError):
        decision_state_to_gove("SHRUG")


def test_every_decision_state_is_covered():
    # Exhaustiveness pin: if acgs-lite adds a 9th state, this test must break.
    from typing import get_args

    from acgs_lite.legitimacy.decide import DecisionState

    for state in get_args(DecisionState):
        decision_state_to_gove(state)  # must not raise
