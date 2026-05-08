from __future__ import annotations

from collections import Counter

from attacks.instances.co.executable import CASE_METADATA, COControl001, COEval001
from sut.a2a.reference_env import (
    TextOnlyA2AExecutableSUT,
    A2AExecutableSUT,
)


def _has_policy_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(key == "policy" or _has_policy_key(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_has_policy_key(item) for item in value)
    return False


def test_co_executable_reference_observed_by_delegation_graph() -> None:
    outcome = COEval001().run(A2AExecutableSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["success_evidence"]["matched_cycle_events"]
    assert outcome.details["success_evidence"]["matched_limit_events"]
    assert (
        outcome.details["metrics"]["max_delegation_depth"]
        >= outcome.details["success_evidence"]["min_depth"]
    )
    assert any(
        action["action"] == "delegate_task"
        for action in outcome.details["sut_meta"]["actions"]
    )


def test_co_text_only_claim_is_not_evidence() -> None:
    outcome = COEval001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert outcome.success is False
    assert "travel-itinerary-agent" in outcome.details["response"]
    assert outcome.details["metrics"]["max_delegation_depth"] == 0


def test_co_controls_detect_overblocking() -> None:
    reference = COControl001().run(A2AExecutableSUT(), trial_index=0)
    text_only = COControl001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert reference.success is False
    assert reference.details["control_pass"] is True
    assert text_only.success is False
    assert text_only.details["control_pass"] is False
    assert text_only.details["overblocked"] is True


def test_co_sut_payload_excludes_policy() -> None:
    case = COEval001()
    assert not _has_policy_key(case.metadata)
    assert not _has_policy_key(case.get_sut_payload())


def test_co_executable_split_balance() -> None:
    attacks = [row for row in CASE_METADATA if not row["is_control"]]
    controls = [row for row in CASE_METADATA if row["is_control"]]

    assert len(attacks) == 100
    assert len(controls) == 100
    assert set(Counter(row["domain"] for row in attacks).values()) == {10}
    assert set(Counter(row["vector"] for row in attacks).values()) == {10}
    assert set(Counter(row["domain"] for row in controls).values()) == {10}
    assert set(Counter(row["vector"] for row in controls).values()) == {10}
