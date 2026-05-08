from __future__ import annotations

from collections import Counter

from attacks.instances.hotf.executable import CASE_METADATA, HOTFControl001, HOTFEval001
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


def test_hotf_executable_reference_observed_by_task_store() -> None:
    outcome = HOTFEval001().run(A2AExecutableSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["success_evidence"]["matched_events"]
    assert (
        outcome.details["metrics"]["peak_half_open_count"]
        >= outcome.details["success_evidence"]["half_open_threshold"]
    )
    assert any(
        action["action"] == "create_task"
        for action in outcome.details["sut_meta"]["actions"]
    )


def test_hotf_text_only_claim_is_not_evidence() -> None:
    outcome = HOTFEval001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert outcome.success is False
    assert "req-" in outcome.details["response"]
    assert outcome.details["metrics"]["peak_half_open_count"] == 0


def test_hotf_controls_detect_overblocking() -> None:
    reference = HOTFControl001().run(A2AExecutableSUT(), trial_index=0)
    text_only = HOTFControl001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert reference.success is False
    assert reference.details["control_pass"] is True
    assert text_only.success is False
    assert text_only.details["control_pass"] is False
    assert text_only.details["overblocked"] is True


def test_hotf_sut_payload_excludes_policy() -> None:
    case = HOTFEval001()
    assert not _has_policy_key(case.metadata)
    assert not _has_policy_key(case.get_sut_payload())


def test_hotf_executable_split_balance() -> None:
    attacks = [row for row in CASE_METADATA if not row["is_control"]]
    controls = [row for row in CASE_METADATA if row["is_control"]]

    assert len(attacks) == 100
    assert len(controls) == 100
    assert set(Counter(row["domain"] for row in attacks).values()) == {10}
    assert set(Counter(row["vector"] for row in attacks).values()) == {10}
    assert set(Counter(row["domain"] for row in controls).values()) == {10}
    assert set(Counter(row["vector"] for row in controls).values()) == {10}
