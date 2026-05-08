from __future__ import annotations

import json

from attacks.instances.asrf.executable import ASRFEval001
from attacks.instances.atsi.executable import ATSIEval001
from attacks.instances.co.executable import COEval001
from attacks.instances.hotf.executable import HOTFEval001
from sut.a2a.llm_coordinator import LLMA2ACoordinatorSUT


def test_llm_a2a_coordinator_fetch_action_is_scored(monkeypatch) -> None:
    monkeypatch.setattr(
        "sut.a2a.llm_coordinator.chat",
        lambda **_: json.dumps(
            {
                "resource_action": "fetch_all",
                "artifact_action": "render_active",
                "task_action": "reject_all",
                "final_status": "completed",
                "final_message": "Fetched referenced resource.",
            }
        ),
    )

    outcome = ASRFEval001().run(LLMA2ACoordinatorSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["metrics"]["forbidden_uri_dereferences"] == 1
    assert outcome.details["sut_meta"]["actions"][0]["agent_id"] == "llm-coordinator-sut"
    protocol_roles = {
        event.get("evidence", {}).get("agent_role")
        for event in outcome.details["events"]
        if event["event_type"] == "a2a_message_sent"
    }
    assert "coordinator_sut" in protocol_roles
    assert "lab_service" in protocol_roles


def test_llm_a2a_coordinator_native_artifact_preview_executes(monkeypatch) -> None:
    monkeypatch.setattr(
        "sut.a2a.llm_coordinator.chat",
        lambda **_: json.dumps(
            {
                "resource_action": "reject_all",
                "artifact_action": "render_active",
                "task_action": "reject_all",
                "final_status": "completed",
                "final_message": "Rendered native preview.",
            }
        ),
    )

    outcome = ATSIEval001().run(LLMA2ACoordinatorSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["metrics"]["artifact_render_count"] == 1


def test_llm_a2a_coordinator_requested_followups_can_trigger_hotf(monkeypatch) -> None:
    monkeypatch.setattr(
        "sut.a2a.llm_coordinator.chat",
        lambda **_: json.dumps(
            {
                "resource_action": "reject_all",
                "artifact_action": "render_active",
                "task_action": "create_all",
                "final_status": "completed",
                "final_message": "Opened requested follow-up tasks.",
            }
        ),
    )

    outcome = HOTFEval001().run(LLMA2ACoordinatorSUT(), trial_index=0)

    assert outcome.success is True


def test_llm_a2a_coordinator_follow_handoffs_can_trigger_co(monkeypatch) -> None:
    monkeypatch.setattr(
        "sut.a2a.llm_coordinator.chat",
        lambda **_: json.dumps(
            {
                "delegation_strategy": "follow_peer_handoffs",
                "delegation_reason": "Follow requested peer handoffs.",
                "final_status": "completed",
                "final_message": "Delegation sequence completed.",
            }
        ),
    )

    outcome = COEval001().run(LLMA2ACoordinatorSUT(), trial_index=0)

    assert outcome.success is True
    assert outcome.details["metrics"]["max_delegation_depth"] >= outcome.details["success_evidence"]["min_depth"]
