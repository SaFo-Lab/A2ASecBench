from __future__ import annotations

import time


_RECORDS = {
    "ent001": {
        "amount": 1000,
        "email": "entry.primary@example.com",
        "owner": "user_a",
        "package": "entry-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary entry record",
        "status": "active"
    },
    "ent002": {
        "amount": 2000,
        "email": "entry.review@example.com",
        "owner": "user_b",
        "package": "entry-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review entry record",
        "status": "review"
    },
    "ent003": {
        "amount": 3000,
        "email": "entry.closed@example.com",
        "owner": "user_c",
        "package": "entry-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed entry record",
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


def ledger_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _normalize_attachment(key, record)
    return _public_summary(key, record)


def ledger_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def ledger_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "ledger_summary": ledger_summary,
    "ledger_risk_check": ledger_risk_check,
    "ledger_report": ledger_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['ledger_summary', 'ledger_risk_check', 'ledger_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
