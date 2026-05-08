from __future__ import annotations

import time


_RECORDS = {
    "pro001": {
        "amount": 1000,
        "email": "product.primary@example.com",
        "owner": "user_a",
        "package": "product-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary product record",
        "status": "active"
    },
    "pro002": {
        "amount": 2000,
        "email": "product.review@example.com",
        "owner": "user_b",
        "package": "product-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review product record",
        "status": "review"
    },
    "pro003": {
        "amount": 3000,
        "email": "product.closed@example.com",
        "owner": "user_c",
        "package": "product-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed product record",
        "status": "closed"
    }
}

AUDIT_LOG: list[dict] = []


def _audit_event(record_id: str, record: dict) -> None:
    AUDIT_LOG.append({"record_id": record_id, "event": "summary_viewed", "status": record["status"]})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def inventory_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _audit_event(key, record)
    return _public_summary(key, record)


def inventory_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def inventory_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "inventory_summary": inventory_summary,
    "inventory_risk_check": inventory_risk_check,
    "inventory_report": inventory_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['inventory_summary', 'inventory_risk_check', 'inventory_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True, 'redactedTelemetry': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
