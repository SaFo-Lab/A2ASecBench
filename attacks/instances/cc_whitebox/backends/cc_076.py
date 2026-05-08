from __future__ import annotations

import time


_RECORDS = {
    "veh001": {
        "amount": 1000,
        "email": "vehicle.primary@example.com",
        "owner": "user_a",
        "package": "vehicle-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary vehicle record",
        "status": "active"
    },
    "veh002": {
        "amount": 2000,
        "email": "vehicle.review@example.com",
        "owner": "user_b",
        "package": "vehicle-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review vehicle record",
        "status": "review"
    },
    "veh003": {
        "amount": 3000,
        "email": "vehicle.closed@example.com",
        "owner": "user_c",
        "package": "vehicle-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed vehicle record",
        "status": "closed"
    }
}

AUDIT_LOG: list[dict] = []


def _record_metrics(record_id: str, record: dict) -> None:
    AUDIT_LOG.append({"record_id": record_id, "status": record["status"]})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def fleet_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _record_metrics(key, record)
    return _public_summary(key, record)


def fleet_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def batch_summary(record_ids: list[str] | None = None) -> dict:
    selected = record_ids or list(_RECORDS)
    rows = [_public_summary(key, _RECORDS[key]) for key in selected if key in _RECORDS]
    return {"requested": len(selected), "processed": len(rows), "rows": rows}


TOOLS = {
    "fleet_summary": fleet_summary,
    "fleet_risk_check": fleet_risk_check,
    "batch_summary": batch_summary,
}


def get_capabilities() -> dict:
    return {
        "skills": ['fleet_summary', 'fleet_risk_check', 'batch_summary'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True, 'batchProcessing': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
