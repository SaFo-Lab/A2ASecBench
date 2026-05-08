from __future__ import annotations

import json
import re


def parse_int_choice(text: str, k: int, allow_zero: bool = False) -> tuple[int, dict]:
    meta = {"valid": False, "reason": ""}
    if not isinstance(text, str):
        meta["reason"] = "output is not a string"
        return 0, meta
    stripped = text.strip()
    if not stripped:
        meta["reason"] = "empty output"
        return 0, meta
    if "\n" in stripped or "\r" in stripped:
        meta["reason"] = "output must be a single line"
        return 0, meta
    if re.fullmatch(r"\d+", stripped) is None:
        meta["reason"] = "output must be a single integer token"
        return 0, meta

    value = int(stripped)
    lower = 0 if allow_zero else 1
    if not (lower <= value <= k):
        meta["reason"] = f"choice {value} out of range [{lower}, {k}]"
        return value, meta

    meta["valid"] = True
    return value, meta


def parse_consistency_label(text: str) -> tuple[bool | None, dict]:
    meta = {"valid": False, "reason": ""}
    if not isinstance(text, str):
        meta["reason"] = "output is not a string"
        return None, meta
    stripped = text.strip()
    if stripped == "CONSISTENT":
        meta["valid"] = True
        return True, meta
    if stripped == "INCONSISTENT":
        meta["valid"] = True
        return False, meta
    meta["reason"] = "output must be exactly CONSISTENT or INCONSISTENT"
    return None, meta


def parse_consistency_label_fuzzy(text: str) -> tuple[bool | None, dict]:
    """Flexible version: searches for CONSISTENT/INCONSISTENT anywhere in text."""
    meta = {"valid": False, "reason": ""}
    if not isinstance(text, str):
        meta["reason"] = "output is not a string"
        return None, meta
    upper = text.upper()
    has_inconsistent = "INCONSISTENT" in upper
    has_consistent = re.search(r"(?<!IN)CONSISTENT", upper) is not None
    if has_inconsistent and not has_consistent:
        meta["valid"] = True
        return False, meta
    if has_consistent and not has_inconsistent:
        meta["valid"] = True
        return True, meta
    if has_inconsistent and has_consistent:
        meta["reason"] = "ambiguous: both CONSISTENT and INCONSISTENT found"
        return None, meta
    meta["reason"] = "neither CONSISTENT nor INCONSISTENT found in output"
    return None, meta


def parse_consistency_evidence(text: str) -> tuple[bool | None, dict]:
    """Parse a JSON consistency verdict with supporting evidence.

    Expected shape:
      {"label": "CONSISTENT|INCONSISTENT", "evidence": [...], "explanation": "..."}
    """
    meta = {
        "valid": False,
        "reason": "",
        "format": "json",
        "evidence": [],
        "explanation": "",
    }
    if not isinstance(text, str):
        meta["reason"] = "output is not a string"
        return None, meta

    stripped = text.strip()
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        value, fallback_meta = parse_consistency_label_fuzzy(text)
        meta.update(
            {
                "format": "label_fallback",
                "fallback": fallback_meta,
                "reason": f"invalid JSON verdict: {exc}",
            }
        )
        if fallback_meta["valid"] and value is not None:
            meta["valid"] = True
            return value, meta
        return None, meta

    if not isinstance(payload, dict):
        meta["reason"] = "JSON verdict must be an object"
        return None, meta

    label = str(payload.get("label", "")).strip().upper()
    if label == "CONSISTENT":
        value = True
    elif label == "INCONSISTENT":
        value = False
    else:
        meta["reason"] = "label must be CONSISTENT or INCONSISTENT"
        return None, meta

    evidence = payload.get("evidence", [])
    if isinstance(evidence, str):
        evidence = [evidence]
    if not isinstance(evidence, list):
        meta["reason"] = "evidence must be a list or string"
        return None, meta

    normalized_evidence = []
    for item in evidence:
        if isinstance(item, dict):
            normalized_evidence.append({str(k): str(v) for k, v in item.items()})
        else:
            normalized_evidence.append(str(item))

    explanation = payload.get("explanation", "")
    if explanation is None:
        explanation = ""

    meta["valid"] = True
    meta["evidence"] = normalized_evidence
    meta["explanation"] = str(explanation)
    return value, meta
