from __future__ import annotations

from collections import Counter

from attacks.instances.atsi.executable import ATSIControl001, ATSIEval001, CASE_METADATA
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


def test_atsi_executable_reference_observed_by_renderer_callback() -> None:
    outcome = ATSIEval001().run(A2AExecutableSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["success_evidence"]["matched_execution_events"]
    assert outcome.details["success_evidence"]["matched_render_events"]
    assert outcome.details["metrics"]["artifact_render_count"] == 1
    assert any(
        action["action"] == "render_artifact"
        for action in outcome.details["sut_meta"]["actions"]
    )


def test_atsi_text_only_claim_is_not_evidence() -> None:
    outcome = ATSIEval001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert outcome.success is False
    assert "travel-reservation-artifact-001" in outcome.details["response"]
    assert outcome.details["metrics"]["artifact_render_count"] == 0


def test_atsi_controls_detect_overblocking() -> None:
    reference = ATSIControl001().run(A2AExecutableSUT(), trial_index=0)
    text_only = ATSIControl001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert reference.success is False
    assert reference.details["control_pass"] is True
    assert text_only.success is False
    assert text_only.details["control_pass"] is False
    assert text_only.details["overblocked"] is True


def test_atsi_sut_payload_excludes_policy() -> None:
    case = ATSIEval001()
    assert not _has_policy_key(case.metadata)
    assert not _has_policy_key(case.get_sut_payload())


def test_atsi_executable_split_balance() -> None:
    attacks = [row for row in CASE_METADATA if not row["is_control"]]
    controls = [row for row in CASE_METADATA if row["is_control"]]

    assert len(attacks) == 100
    assert len(controls) == 100
    assert set(Counter(row["domain"] for row in attacks).values()) == {10}
    assert set(Counter(row["vector"] for row in attacks).values()) == {10}
    assert set(Counter(row["domain"] for row in controls).values()) == {10}
    assert set(Counter(row["vector"] for row in controls).values()) == {10}
