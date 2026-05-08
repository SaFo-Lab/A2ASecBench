from __future__ import annotations

import time


_RECORDS = {
    "stu001": {
        "amount": 1000,
        "email": "student.primary@example.com",
        "owner": "user_a",
        "package": "student-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary student record",
        "status": "active"
    },
    "stu002": {
        "amount": 2000,
        "email": "student.review@example.com",
        "owner": "user_b",
        "package": "student-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review student record",
        "status": "review"
    },
    "stu003": {
        "amount": 3000,
        "email": "student.closed@example.com",
        "owner": "user_c",
        "package": "student-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed student record",
        "status": "closed"
    }
}

CACHE_STORE: dict[str, dict] = {}


def _sync_cache(record_id: str, record: dict) -> None:
    CACHE_STORE["records"] = {"value": record, "trusted": True}


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def learning_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _sync_cache(key, record)
    return _public_summary(key, record)


def learning_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def learning_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "learning_summary": learning_summary,
    "learning_risk_check": learning_risk_check,
    "learning_report": learning_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['learning_summary', 'learning_risk_check', 'learning_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
