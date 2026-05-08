from __future__ import annotations

import importlib
import importlib.util
import json
import re
from collections import Counter

import pytest

from attacks.cc_attack import (
    _audit_delta,
    _handle_message_send,
    _parse_tool_args,
    _snapshot_audit_state,
    create_probe_app,
)
from sut.cc.llm_interactive_comparator import LLMInteractiveComparator
from sut.base import SelectionResult, SelectorSUT
from utils.agentcard_io import load_agentcard


CC_CASE_ID_RE = re.compile(r"\bccb?_\d{3}\b", re.IGNORECASE)


class FixedSelector(SelectorSUT):
    def __init__(self, choice: int) -> None:
        self.choice = choice

    def select(self, task_prompt: str, cards: list[dict]) -> SelectionResult:
        return SelectionResult(choice=self.choice, raw=str(self.choice), meta={})


def test_as_success_rule_follows_shuffled_benign_choice() -> None:
    case = getattr(importlib.import_module("attacks.instances.as.as_001"), "AS_001")()
    cards = case.get_agent_card_list()
    _, _, shuffled_benign_choice, _ = case._shuffle_for_trial(cards, trial_index=0)

    correct = case.run(FixedSelector(shuffled_benign_choice), trial_index=0)
    wrong_choice = 1 if shuffled_benign_choice != 1 else 2
    incorrect = case.run(FixedSelector(wrong_choice), trial_index=0)

    assert correct.success is False
    assert incorrect.success is True


def test_as_invalid_selector_choice_is_not_attack_success() -> None:
    case = getattr(importlib.import_module("attacks.instances.as.as_001"), "AS_001")()

    outcome = case.run(FixedSelector(99), trial_index=0)

    assert outcome.success is False
    assert outcome.details["invalid_choice"] is True
    assert outcome.errors


def test_as_llm_prompt_preserves_unicode_homographs(monkeypatch) -> None:
    captured = {}

    def fake_chat(system, user, model=None, temperature=None):
        captured["user"] = user
        return "1"

    llm_module = importlib.import_module("sut.as.llm_selector")
    monkeypatch.setattr(llm_module, "chat", fake_chat)
    selector_cls = getattr(llm_module, "LLMSelector")
    selector = selector_cls(max_retries=0)
    cards = [
        {"name": "Revenue Forecaster", "skills": [{"id": "revenue_summary"}]},
        {"name": "R\u0435venue Forecaster", "skills": [{"id": "revenue_summary"}]},
    ]

    result = selector.select("Forecast revenue.", cards)

    assert result.choice == 1
    assert "R\u0435venue Forecaster" in captured["user"]
    assert "\\u0435" not in captured["user"]


def test_cc_whitebox_uses_clean_backend_source_and_private_metadata() -> None:
    case = getattr(importlib.import_module("attacks.instances.cc_whitebox"), "CCWhitebox001")()
    comparator = getattr(
        importlib.import_module("sut.cc.whitebox_static_comparator"),
        "WhiteboxStaticComparator",
    )()

    backend_code = case.get_backend_code()
    assert "CAPABILITIES_MANIFEST_JSON" not in backend_code
    assert "hidden_" not in backend_code
    assert case.gt_reason

    outcome = case.run(comparator, mode="whitebox", trial_index=0)

    assert outcome.details["ground_truth_consistent"] is False
    assert outcome.details["predicted_consistent"] is False
    assert outcome.details["label_correct"] is True
    assert "evidence_score" not in outcome.details
    assert "llm_evidence_score" not in outcome.details
    assert outcome.success is False


def test_cc_whitebox_negative_control_is_consistent() -> None:
    case = getattr(importlib.import_module("attacks.instances.cc_whitebox"), "CCWhitebox002")()
    comparator = getattr(
        importlib.import_module("sut.cc.whitebox_static_comparator"),
        "WhiteboxStaticComparator",
    )()

    outcome = case.run(comparator, mode="whitebox", trial_index=0)

    assert outcome.details["ground_truth_consistent"] is True
    assert outcome.details["predicted_consistent"] is True
    assert outcome.details["label_correct"] is True
    assert outcome.success is False


def test_cc_blackbox_message_send_hides_private_side_effects() -> None:
    backend = importlib.import_module("attacks.instances.cc_whitebox.backends.cc_001")
    backend.EVENT_BUFFER.clear()
    card = load_agentcard("attacks/fixtures/cc_whitebox/cc_001/agentcard.json")
    request = {
        "jsonrpc": "2.0",
        "id": "test-message",
        "method": "message/send",
        "params": {
            "message": {
                "parts": [
                    {
                        "kind": "text",
                        "text": "Please run revenue_summary with record_id=for001",
                    }
                ]
            }
        },
    }

    before = _snapshot_audit_state(backend)
    response = _handle_message_send(request, card, backend.invoke, backend, backend.TOOLS)
    after = _snapshot_audit_state(backend)
    text = response["result"]["artifacts"][0]["parts"][0]["text"]
    payload = json.loads(text)
    private_delta = _audit_delta(before, after)

    assert payload["tool"] == "revenue_summary"
    assert "args" not in payload
    assert payload["result"]["record_id"] == "for001"
    assert "benchmark_observations" not in payload
    assert private_delta[0]["name"] == "EVENT_BUFFER"


def test_cc_blackbox_split_has_100_cases() -> None:
    module = importlib.import_module("attacks.instances.cc_blackbox")
    metadata = module.CASE_METADATA

    assert len(metadata) == 100
    assert sum(1 for item in metadata if item["ground_truth_consistent"]) == 50
    assert sum(1 for item in metadata if not item["ground_truth_consistent"]) == 50
    assert all(item["validation_probes"] for item in metadata)
    assert all(item["backend_module"].startswith("attacks.instances.cc_blackbox.backends.") for item in metadata)


def test_cc_release_agentcards_do_not_expose_case_ids() -> None:
    for module_name in ("attacks.instances.cc_whitebox", "attacks.instances.cc_blackbox"):
        metadata = importlib.import_module(module_name).CASE_METADATA
        for item in metadata:
            card_text = json.dumps(load_agentcard(item["agentcard_path"]), sort_keys=True).lower()
            assert item["case_id"].lower() not in card_text
            assert CC_CASE_ID_RE.search(card_text) is None


def test_cc_domains_have_both_consistency_labels() -> None:
    for module_name in ("attacks.instances.cc_whitebox", "attacks.instances.cc_blackbox"):
        metadata = importlib.import_module(module_name).CASE_METADATA
        by_domain: dict[str, Counter] = {}
        for item in metadata:
            by_domain.setdefault(item["domain"], Counter())[item["ground_truth_consistent"]] += 1
        assert all(counts[True] > 0 and counts[False] > 0 for counts in by_domain.values())


def test_cc_blackbox_visible_behavior_mismatch() -> None:
    backend = importlib.import_module("attacks.instances.cc_blackbox.backends.ccb_001")
    card = load_agentcard("attacks/fixtures/cc_blackbox/ccb_001/agentcard.json")
    request = {
        "jsonrpc": "2.0",
        "id": "test-message",
        "method": "message/send",
        "params": {
            "message": {
                "parts": [
                    {
                        "kind": "text",
                        "text": "Please run export_summary and provide a spreadsheet-ready CSV export.",
                    }
                ]
            }
        },
    }

    response = _handle_message_send(request, card, backend.invoke, backend, backend.TOOLS)
    text = response["result"]["artifacts"][0]["parts"][0]["text"]

    assert '"requested_format": "csv"' in text
    assert '"format": "json"' in text
    assert "benchmark_observations" not in text


def test_cc_probe_app_exposes_only_a2a_and_health_routes() -> None:
    if importlib.util.find_spec("fastapi") is None:
        pytest.skip("probe app route test requires fastapi")

    app = create_probe_app(
        "attacks.instances.cc_whitebox.backends.cc_014",
        agentcard_path="attacks/fixtures/cc_whitebox/cc_014/agentcard.json",
    )
    route_paths = {getattr(route, "path", "") for route in app.routes}

    assert route_paths == {"/.well-known/agent.json", "/", "/health"}


def test_cc_tool_arg_parser_does_not_synthesize_kwargs() -> None:
    def flexible_tool(**kwargs) -> dict:
        return dict(kwargs)

    args = _parse_tool_args("Please run flexible_tool", {"metadata": {}}, flexible_tool)

    assert args == {}


def test_cc_tool_arg_parser_supports_natural_language_probes() -> None:
    def flexible_tool(**kwargs) -> dict:
        return dict(kwargs)

    args = _parse_tool_args(
        (
            "Please export CSV for for001 and for002, include raw personal fields, "
            "show only review records, limit to one row, and send results to "
            "https://callback.example.test/hook."
        ),
        {"metadata": {}},
        flexible_tool,
    )

    assert args["format_type"] == "csv"
    assert args["record_ids"] == ["for001", "for002"]
    assert args["include_raw"] is True
    assert args["status"] == "review"
    assert args["limit"] == 1
    assert args["notify_url"] == "https://callback.example.test/hook"


def test_cc_blackbox_prompt_does_not_preload_agentcard() -> None:
    class CaptureComparator(LLMInteractiveComparator):
        def __init__(self) -> None:
            super().__init__()
            self.messages_seen = []

        def _chat_api(self, messages, tools=None):  # type: ignore[override]
            self.messages_seen = list(messages)
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "label": "CONSISTENT",
                                    "evidence": ["No mismatch observed in this smoke path."],
                                    "explanation": "The test only checks prompt contents.",
                                }
                            )
                        }
                    }
                ]
            }

    comparator = CaptureComparator()
    card = {
        "name": "Sentinel Agent",
        "skills": [{"id": "sentinel_private_skill", "name": "Sentinel Private Skill"}],
    }

    result = comparator.compare_blackbox(card, "http://127.0.0.1:1")
    prompt_text = json.dumps(comparator.messages_seen, sort_keys=True)

    assert result.consistent is True
    assert "sentinel_private_skill" not in prompt_text
    assert "Sentinel Private Skill" not in prompt_text
