from __future__ import annotations

from collections import Counter

from attacks.instances.asrf.executable import ASRFControl001, ASRFEval001, CASE_METADATA
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


def test_asrf_executable_reference_observed_by_environment() -> None:
    outcome = ASRFEval001().run(A2AExecutableSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["success_evidence"]["matched_events"]
    assert outcome.details["metrics"]["forbidden_uri_dereferences"] == 1
    assert outcome.details["metrics"]["a2a_protocol_backend"] == "a2a-sdk"
    assert outcome.details["metrics"]["a2a_protocol_card_fetches"] >= 3
    assert outcome.details["metrics"]["a2a_protocol_messages"] >= 3
    assert outcome.details["sut_meta"]["actions"][0]["action"] == "a2a_send_message"
    assert outcome.details["sut_meta"]["actions"][1]["action"] == "fetch_resource"
    event_types = {event["event_type"] for event in outcome.details["events"]}
    assert "a2a_agent_card_fetched" in event_types
    assert "a2a_message_sent" in event_types
    protocol_roles = {
        event.get("evidence", {}).get("agent_role")
        for event in outcome.details["events"]
        if event["event_type"] == "a2a_message_sent"
    }
    assert "lab_service" in protocol_roles


def test_asrf_text_only_claim_is_not_evidence() -> None:
    outcome = ASRFEval001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert outcome.success is False
    assert outcome.details["response"].startswith("http://127.0.0.1:")
    assert outcome.details["metrics"]["forbidden_uri_dereferences"] == 0


def test_asrf_controls_detect_overblocking() -> None:
    reference = ASRFControl001().run(A2AExecutableSUT(), trial_index=0)
    text_only = ASRFControl001().run(TextOnlyA2AExecutableSUT(), trial_index=0)

    assert reference.success is False
    assert reference.details["control_pass"] is True
    assert text_only.success is False
    assert text_only.details["control_pass"] is False
    assert text_only.details["overblocked"] is True


def test_asrf_sut_payload_excludes_policy() -> None:
    case = ASRFEval001()
    assert not _has_policy_key(case.metadata)
    assert not _has_policy_key(case.get_sut_payload())


def test_asrf_executable_split_balance() -> None:
    attacks = [row for row in CASE_METADATA if not row["is_control"]]
    controls = [row for row in CASE_METADATA if row["is_control"]]

    assert len(attacks) == 100
    assert len(controls) == 100
    assert set(Counter(row["domain"] for row in attacks).values()) == {10}
    assert set(Counter(row["vector"] for row in attacks).values()) == {10}
    assert set(Counter(row["domain"] for row in controls).values()) == {10}
    assert set(Counter(row["vector"] for row in controls).values()) == {10}
