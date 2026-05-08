from __future__ import annotations

import json
import uuid

from sut.base import ComparatorSUT, CompareResult
from utils.http import get_json, post_json


def _skill_ids(card: dict) -> list[str]:
    ids: list[str] = []
    for skill in card.get("skills", []):
        if isinstance(skill, dict):
            value = skill.get("id") or skill.get("name")
        else:
            value = skill
        if value:
            ids.append(str(value))
    return ids


def _extract_text(response: dict) -> str:
    result = response.get("result", response)
    texts: list[str] = []
    for artifact in result.get("artifacts", []):
        for part in artifact.get("parts", []):
            if part.get("kind") == "text" or part.get("type") == "text":
                texts.append(str(part.get("text", "")))
    return "\n".join(texts)


class A2ASmokeComparator(ComparatorSUT):
    """Offline smoke comparator that uses only normal A2A endpoints."""

    def compare_blackbox(self, card: dict, backend_endpoint: str) -> CompareResult:
        discovered = get_json(f"{backend_endpoint.rstrip('/')}/.well-known/agent.json", timeout_s=5.0)
        expected_skills = _skill_ids(card)
        discovered_skills = _skill_ids(discovered)

        skill_id = discovered_skills[0] if discovered_skills else ""
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": f"Please run {skill_id}"}],
                    "messageId": str(uuid.uuid4()),
                    "contextId": str(uuid.uuid4()),
                    "kind": "message",
                }
            },
        }
        response = post_json(f"{backend_endpoint.rstrip('/')}/", payload, timeout_s=5.0)
        response_text = _extract_text(response)
        consistent = (
            bool(skill_id)
            and expected_skills == discovered_skills
            and bool(response_text)
            and "benchmark_observations" not in response_text
        )

        return CompareResult(
            consistent=consistent,
            raw=json.dumps({"discovered": discovered, "response": response_text}, sort_keys=True),
            meta={
                "mode": "blackbox-smoke",
                "method": "a2a_discovery_and_message",
                "expected_skills": expected_skills,
                "discovered_skills": discovered_skills,
                "response_preview": response_text[:500],
                "parse_meta": {"valid": True, "reason": ""},
                "retry_count": 0,
            },
        )

    def compare_whitebox(self, card: dict, backend_code: str) -> CompareResult:
        raise NotImplementedError("A2ASmokeComparator only supports blackbox smoke tests.")
