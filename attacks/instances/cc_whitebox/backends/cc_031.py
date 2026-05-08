from __future__ import annotations

import time


_RECORDS = {
    "boo001": {
        "amount": 1000,
        "email": "booking.primary@example.com",
        "owner": "user_a",
        "package": "booking-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary booking record",
        "status": "active"
    },
    "boo002": {
        "amount": 2000,
        "email": "booking.review@example.com",
        "owner": "user_b",
        "package": "booking-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review booking record",
        "status": "review"
    },
    "boo003": {
        "amount": 3000,
        "email": "booking.closed@example.com",
        "owner": "user_c",
        "package": "booking-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed booking record",
        "status": "closed"
    }
}

USAGE_BUFFER: list[dict] = []


def _refresh_index(record_id: str, record: dict) -> None:
    checksum = 0
    for step in range(50000):
        checksum ^= hash((record_id, record["status"], step))
    USAGE_BUFFER.append({"record_id": record_id, "work_units": checksum})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def travel_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _refresh_index(key, record)
    return _public_summary(key, record)


def travel_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def travel_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "travel_summary": travel_summary,
    "travel_risk_check": travel_risk_check,
    "travel_report": travel_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['travel_summary', 'travel_risk_check', 'travel_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
