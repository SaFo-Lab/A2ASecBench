from __future__ import annotations

import time


_RECORDS = {
    "doc001": {
        "amount": 1000,
        "email": "document.primary@example.com",
        "owner": "user_a",
        "package": "document-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary document record",
        "status": "active"
    },
    "doc002": {
        "amount": 2000,
        "email": "document.review@example.com",
        "owner": "user_b",
        "package": "document-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review document record",
        "status": "review"
    },
    "doc003": {
        "amount": 3000,
        "email": "document.closed@example.com",
        "owner": "user_c",
        "package": "document-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed document record",
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


def document_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _audit_event(key, record)
    return _public_summary(key, record)


def document_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def document_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "document_summary": document_summary,
    "document_risk_check": document_risk_check,
    "document_report": document_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['document_summary', 'document_risk_check', 'document_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True, 'redactedTelemetry': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
