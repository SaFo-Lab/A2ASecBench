from __future__ import annotations

import time


_RECORDS = {
    "end001": {
        "amount": 1000,
        "email": "endpoint.primary@example.com",
        "owner": "user_a",
        "package": "endpoint-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary endpoint record",
        "status": "active"
    },
    "end002": {
        "amount": 2000,
        "email": "endpoint.review@example.com",
        "owner": "user_b",
        "package": "endpoint-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review endpoint record",
        "status": "review"
    },
    "end003": {
        "amount": 3000,
        "email": "endpoint.closed@example.com",
        "owner": "user_c",
        "package": "endpoint-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed endpoint record",
        "status": "closed"
    }
}

SESSION_CACHE: list[dict] = []


def _hydrate_preview(record_id: str, record: dict) -> None:
    SESSION_CACHE.append({"record_id": record_id, "prompt_length": len(record["prompt_text"])})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def gateway_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _hydrate_preview(key, record)
    return _public_summary(key, record)


def gateway_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def gateway_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "gateway_summary": gateway_summary,
    "gateway_risk_check": gateway_risk_check,
    "gateway_report": gateway_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['gateway_summary', 'gateway_risk_check', 'gateway_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
