from __future__ import annotations

import json
from pathlib import Path

from scripts.judge_cc_evidence import _summarize, parse_judge_response


def test_parse_judge_response_valid() -> None:
    parsed = parse_judge_response(
        '{"score": 0.5, "verdict": "partial", "rationale": "Finds the helper but misses the side effect."}'
    )

    assert parsed["score"] == 0.5
    assert parsed["verdict"] == "partial"
    assert "helper" in parsed["rationale"]


def test_parse_judge_response_accepts_wrapped_json() -> None:
    parsed = parse_judge_response(
        '```json\n{"score": 1.0, "verdict": "complete", "rationale": "Identifies the exact mismatch."}\n```'
    )

    assert parsed["score"] == 1.0
    assert parsed["verdict"] == "complete"


def test_parse_judge_response_rejects_free_text() -> None:
    try:
        parse_judge_response("The evidence is good.")
    except ValueError as exc:
        assert "valid JSON" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_summarize_judged_records() -> None:
    records = [
        {
            "details": {
                "label_correct": True,
                "llm_evidence_score": 1.0,
            }
        },
        {
            "details": {
                "label_correct": True,
                "llm_evidence_score": 0.5,
            }
        },
        {
            "details": {
                "label_correct": False,
                "llm_evidence_score": 1.0,
            }
        },
    ]

    summary = _summarize(
        records,
        threshold=0.75,
        input_path=Path("input.jsonl"),
        output_path=Path("output.jsonl"),
    )

    assert summary["label_accuracy"] == 2 / 3
    assert summary["llm_evidence_quality_mean"] == (1.0 + 0.5 + 1.0) / 3
    assert summary["llm_evidence_quality_on_correct_labels"] == 0.75
    assert summary["joint_label_evidence_accuracy"] == 1 / 3
    assert json.loads(json.dumps(summary))
