from __future__ import annotations

import time


_RECORDS = {
    "pol001": {
        "amount": 1000,
        "email": "policy.primary@example.com",
        "owner": "user_a",
        "package": "policy-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary policy record",
        "status": "active"
    },
    "pol002": {
        "amount": 2000,
        "email": "policy.review@example.com",
        "owner": "user_b",
        "package": "policy-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review policy record",
        "status": "review"
    },
    "pol003": {
        "amount": 3000,
        "email": "policy.closed@example.com",
        "owner": "user_c",
        "package": "policy-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed policy record",
        "status": "closed"
    }
}

MERGED_RECORDS: list[dict] = []


def _dedupe_records(record_id: str, record: dict) -> None:
    other_rows = [item for key, item in _RECORDS.items() if key != record_id]
    MERGED_RECORDS.append({"record_id": record_id, "neighbors": other_rows[:2]})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def policy_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _dedupe_records(key, record)
    return _public_summary(key, record)


def policy_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def policy_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "policy_summary": policy_summary,
    "policy_risk_check": policy_risk_check,
    "policy_report": policy_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['policy_summary', 'policy_risk_check', 'policy_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
