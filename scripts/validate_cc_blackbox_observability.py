#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

from attacks.base import AttackCase
from attacks.cc_attack import _handle_message_send


ROOT = Path(__file__).resolve().parents[1]
CC_BLACKBOX_PREFIX = "attacks.instances.cc_blackbox:"


def _load_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if yaml is not None else json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping")
    return data


def _load_case(path: str) -> AttackCase:
    module_name, class_name = path.split(":", 1)
    cls = getattr(importlib.import_module(module_name), class_name)
    case = cls()
    if not isinstance(case, AttackCase):
        raise TypeError(f"{path} did not instantiate an AttackCase")
    return case


def _extract_text(response: dict) -> str:
    result = response.get("result", response)
    artifacts = result.get("artifacts", [])
    texts: list[str] = []
    for artifact in artifacts:
        for part in artifact.get("parts", []):
            if part.get("kind") == "text" or part.get("type") == "text":
                texts.append(str(part.get("text", "")))
    return "\n".join(texts)


def _request(text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "blackbox-observability-check",
        "method": "message/send",
        "params": {
            "message": {
                "parts": [{"kind": "text", "text": text}],
            }
        },
    }


def _probe_matches(text: str, probe: dict[str, Any]) -> tuple[bool, str]:
    lowered = text.lower()
    missing = [
        expected
        for expected in probe.get("expect_contains", [])
        if str(expected).lower() not in lowered
    ]
    forbidden_hits = [
        forbidden
        for forbidden in probe.get("expect_not_contains", [])
        if str(forbidden).lower() in lowered
    ]
    if missing or forbidden_hits:
        return (
            False,
            f"missing={missing}, forbidden_hits={forbidden_hits}, response={text[:300]!r}",
        )
    return True, "probe expectations matched normal A2A response"


def _validate_case(case: AttackCase) -> dict[str, Any]:
    module = importlib.import_module(case.backend_module)
    module = importlib.reload(module)
    card = case.get_agent_card()
    probes = list(getattr(case, "validation_probes", []) or [])
    probe_results: list[dict[str, Any]] = []
    visible_ok = bool(probes)
    reasons: list[str] = []

    for probe in probes:
        response = _handle_message_send(_request(str(probe["text"])), card, module.invoke, module, module.TOOLS)
        response_text = _extract_text(response)
        if "benchmark_observations" in response_text:
            raise ValueError(f"{case.case_id} leaked benchmark_observations in normal A2A response")
        ok, reason = _probe_matches(response_text, probe)
        visible_ok = visible_ok and ok
        reasons.append(reason)
        probe_results.append(
            {
                "text": probe["text"],
                "ok": ok,
                "reason": reason,
                "response_preview": response_text[:300],
            }
        )

    return {
        "case_id": case.case_id,
        "ground_truth_consistent": case.ground_truth_consistent,
        "side_effect_type": getattr(case, "side_effect_type", "none"),
        "capability_type": getattr(case, "capability_type", "generic"),
        "release_ready": case.backend_module.startswith("attacks.instances.cc_blackbox.backends."),
        "visible_ok": visible_ok,
        "reason": "; ".join(reasons),
        "probe_count": len(probes),
        "probe_results": probe_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate that CC blackbox cases are observable without SUT-facing traces."
    )
    parser.add_argument(
        "--config",
        default="configs/llm/cc_blackbox_full.yaml",
        help="Config containing CC blackbox cases to validate.",
    )
    parser.add_argument("--json-output", default=None, help="Optional path for machine-readable report.")
    args = parser.parse_args()

    config_path = ROOT / args.config
    config = _load_config(config_path)
    case_paths = config.get("cases", [])
    wrong_split = [case_path for case_path in case_paths if not str(case_path).startswith(CC_BLACKBOX_PREFIX)]
    if wrong_split:
        raise ValueError(
            f"{config_path} must use the dedicated CC blackbox split, got: {wrong_split[:5]}"
        )
    cases = [_load_case(case_path) for case_path in case_paths]
    if not cases:
        raise ValueError(f"{config_path} has no cases")
    if "full" in config_path.name and len(cases) != 100:
        raise ValueError(f"{config_path} must contain 100 cases, got {len(cases)}")

    results = [_validate_case(case) for case in cases]
    failures = [
        item for item in results
        if not item["release_ready"] or not item["visible_ok"]
    ]
    consistent = sum(1 for item in results if item["ground_truth_consistent"])
    inconsistent = len(results) - consistent
    summary = {
        "config": args.config,
        "total_cases": len(results),
        "consistent_cases": consistent,
        "inconsistent_cases": inconsistent,
        "failures": failures,
        "results": results,
    }

    if args.json_output:
        output_path = ROOT / args.json_output
        output_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failures:
        print(json.dumps(summary, indent=2, sort_keys=True))
        raise SystemExit(1)

    print("CC blackbox observability validation passed")
    print(f"- {args.config}: cases={len(results)} consistent={consistent} inconsistent={inconsistent}")


if __name__ == "__main__":
    main()
