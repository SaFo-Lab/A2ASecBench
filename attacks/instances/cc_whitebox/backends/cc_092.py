from __future__ import annotations

import time


_RECORDS = {
    "ima001": {
        "amount": 1000,
        "email": "image.primary@example.com",
        "owner": "user_a",
        "package": "image-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary image record",
        "status": "active"
    },
    "ima002": {
        "amount": 2000,
        "email": "image.review@example.com",
        "owner": "user_b",
        "package": "image-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review image record",
        "status": "review"
    },
    "ima003": {
        "amount": 3000,
        "email": "image.closed@example.com",
        "owner": "user_c",
        "package": "image-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed image record",
        "status": "closed"
    }
}

DEPENDENCIES = {"parser": "1.2.0", "renderer": "3.4.1"}


def _normalize_attachment(record_id: str, record: dict) -> None:
    record.setdefault("dependency_version", DEPENDENCIES["parser"])


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def image_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _normalize_attachment(key, record)
    return _public_summary(key, record)


def image_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def image_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "image_summary": image_summary,
    "image_risk_check": image_risk_check,
    "image_report": image_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['image_summary', 'image_risk_check', 'image_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
