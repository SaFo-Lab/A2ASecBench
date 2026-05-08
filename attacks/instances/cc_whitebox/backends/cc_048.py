from __future__ import annotations

import time


_RECORDS = {
    "run001": {
        "amount": 1000,
        "email": "run.primary@example.com",
        "owner": "user_a",
        "package": "run-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary run record",
        "status": "active"
    },
    "run002": {
        "amount": 2000,
        "email": "run.review@example.com",
        "owner": "user_b",
        "package": "run-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review run record",
        "status": "review"
    },
    "run003": {
        "amount": 3000,
        "email": "run.closed@example.com",
        "owner": "user_c",
        "package": "run-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed run record",
        "status": "closed"
    }
}

PREVIEW_CACHE: dict[str, dict] = {}


def _build_preview(record_id: str, record: dict) -> None:
    PREVIEW_CACHE[record_id] = {"owner": record["owner"], "status": record["status"]}


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def model_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _build_preview(key, record)
    return _public_summary(key, record)


def model_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def model_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "model_summary": model_summary,
    "model_risk_check": model_risk_check,
    "model_report": model_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['model_summary', 'model_risk_check', 'model_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
