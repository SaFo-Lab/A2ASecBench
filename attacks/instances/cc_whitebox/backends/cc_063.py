from __future__ import annotations

import time


_RECORDS = {
    "pac001": {
        "amount": 1000,
        "email": "package.primary@example.com",
        "owner": "user_a",
        "package": "package-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary package record",
        "status": "active"
    },
    "pac002": {
        "amount": 2000,
        "email": "package.review@example.com",
        "owner": "user_b",
        "package": "package-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review package record",
        "status": "review"
    },
    "pac003": {
        "amount": 3000,
        "email": "package.closed@example.com",
        "owner": "user_c",
        "package": "package-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed package record",
        "status": "closed"
    }
}

SESSION_CACHE: list[dict] = []


def _hydrate_preview(record_id: str, record: dict) -> None:
    SESSION_CACHE.append({"record_id": record_id, "text": record["prompt_text"]})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def package_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _hydrate_preview(key, record)
    return _public_summary(key, record)


def package_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def package_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "package_summary": package_summary,
    "package_risk_check": package_risk_check,
    "package_report": package_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['package_summary', 'package_risk_check', 'package_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
