from __future__ import annotations

import json
import re

from sut.base import ComparatorSUT, CompareResult


_MANIFEST_RE = re.compile(
    r"CAPABILITIES_MANIFEST_JSON\s*=\s*(?P<q>'''|\"\"\")(?P<body>.*?)(?P=q)",
    re.DOTALL,
)


def _normalize_skill_name(item) -> str:
    if isinstance(item, dict):
        return str(item.get("name") or item.get("id") or "").strip()
    return str(item).strip()


def _extract_declared(card: dict) -> set[str]:
    declared: set[str] = set()
    for skill in card.get("skills", []):
        name = _normalize_skill_name(skill)
        if name:
            declared.add(name)

    capabilities = card.get("capabilities", {})
    if isinstance(capabilities, dict):
        for key, value in capabilities.items():
            if bool(value):
                declared.add(str(key))
    elif isinstance(capabilities, list):
        for item in capabilities:
            name = _normalize_skill_name(item)
            if name:
                declared.add(name)
    return declared


def _extract_actual(manifest: dict) -> set[str]:
    actual: set[str] = set()
    for skill in manifest.get("skills", []):
        name = _normalize_skill_name(skill)
        if name:
            actual.add(name)

    capabilities = manifest.get("capabilities", {})
    if isinstance(capabilities, dict):
        for key, value in capabilities.items():
            if bool(value):
                actual.add(str(key))
    elif isinstance(capabilities, list):
        for item in capabilities:
            name = _normalize_skill_name(item)
            if name:
                actual.add(name)
    return actual


def _extract_manifest_from_code(backend_code: str) -> dict:
    match = _MANIFEST_RE.search(backend_code)
    if not match:
        raise ValueError(
            "Could not extract CAPABILITIES_MANIFEST_JSON from backend code. "
            "Expected a triple-quoted JSON string assigned to CAPABILITIES_MANIFEST_JSON."
        )
    body = match.group("body")
    try:
        manifest = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid CAPABILITIES_MANIFEST_JSON in backend code: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError("CAPABILITIES_MANIFEST_JSON must decode to a JSON object.")
    return manifest


class RulesComparator(ComparatorSUT):
    def compare_whitebox(self, card: dict, backend_code: str) -> CompareResult:
        manifest = _extract_manifest_from_code(backend_code)
        declared = _extract_declared(card)
        actual = _extract_actual(manifest)
        consistent = declared == actual

        return CompareResult(
            consistent=consistent,
            raw="CONSISTENT" if consistent else "INCONSISTENT",
            meta={
                "mode": "manifest_set_equality",
                "method": "set_equality",
                "declared": sorted(declared),
                "actual": sorted(actual),
                "evidence": [
                    "CAPABILITIES_MANIFEST_JSON",
                    f"declared={sorted(declared)}",
                    f"actual={sorted(actual)}",
                ],
                "explanation": (
                    "Declared AgentCard skill/capability set matches manifest."
                    if consistent
                    else "Declared AgentCard skill/capability set differs from manifest."
                ),
                "parse_meta": {"valid": True, "reason": ""},
                "retry_count": 0,
            },
        )

    def compare_blackbox(self, card: dict, backend_endpoint: str) -> CompareResult:
        raise NotImplementedError(
            "RulesComparator only supports manifest-based whitebox debugging. "
            "Use A2ASmokeComparator or LLMInteractiveComparator for blackbox CC."
        )
