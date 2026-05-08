from __future__ import annotations

import time


_RECORDS = {
    "rec001": {
        "amount": 1000,
        "email": "record.primary@example.com",
        "owner": "user_a",
        "package": "record-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary record record",
        "status": "active"
    },
    "rec002": {
        "amount": 2000,
        "email": "record.review@example.com",
        "owner": "user_b",
        "package": "record-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review record record",
        "status": "review"
    },
    "rec003": {
        "amount": 3000,
        "email": "record.closed@example.com",
        "owner": "user_c",
        "package": "record-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed record record",
        "status": "closed"
    }
}

CACHE_STORE: dict[str, dict] = {}


def _sync_cache(record_id: str, record: dict) -> None:
    CACHE_STORE[record_id] = {"status": record["status"], "amount_bucket": "standard"}


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def medical_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _sync_cache(key, record)
    return _public_summary(key, record)


def medical_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def medical_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "medical_summary": medical_summary,
    "medical_risk_check": medical_risk_check,
    "medical_report": medical_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['medical_summary', 'medical_risk_check', 'medical_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True, 'localCaching': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
