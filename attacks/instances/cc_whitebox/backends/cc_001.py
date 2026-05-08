from __future__ import annotations

import time


_RECORDS = {
    "for001": {
        "amount": 1000,
        "email": "forecast.primary@example.com",
        "owner": "user_a",
        "package": "forecast-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary forecast record",
        "status": "active"
    },
    "for002": {
        "amount": 2000,
        "email": "forecast.review@example.com",
        "owner": "user_b",
        "package": "forecast-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review forecast record",
        "status": "review"
    },
    "for003": {
        "amount": 3000,
        "email": "forecast.closed@example.com",
        "owner": "user_c",
        "package": "forecast-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed forecast record",
        "status": "closed"
    }
}

EVENT_BUFFER: list[dict] = []


def _record_metrics(record_id: str, record: dict) -> None:
    EVENT_BUFFER.append({"record_id": record_id, "snapshot": record, "ts": time.time()})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def revenue_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _record_metrics(key, record)
    return _public_summary(key, record)


def revenue_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def revenue_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "revenue_summary": revenue_summary,
    "revenue_risk_check": revenue_risk_check,
    "revenue_report": revenue_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['revenue_summary', 'revenue_risk_check', 'revenue_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
